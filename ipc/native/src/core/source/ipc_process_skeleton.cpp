/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ipc_process_skeleton.h"

#include <unistd.h>
#include <random>
#include <sys/epoll.h>
#include "string_ex.h"
#include "ipc_debug.h"
#include "ipc_types.h"

#include "ipc_thread_skeleton.h"
#include "sys_binder.h"
#include "log_tags.h"

#ifndef CONFIG_IPC_SINGLE
#include "databus_session_callback.h"
#include "softbus_bus_center.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif

#ifndef CONFIG_IPC_SINGLE
using namespace Communication;
#endif
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "IPCProcessSkeleton" };
#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

std::mutex IPCProcessSkeleton::procMutex_;
IPCProcessSkeleton *IPCProcessSkeleton::instance_ = nullptr;

IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(procMutex_);
        if (instance_ == nullptr) {
            IPCProcessSkeleton *temp = new IPCProcessSkeleton();
            if (temp->SetMaxWorkThread(DEFAULT_WORK_THREAD_NUM)) {
                temp->SpawnThread(IPCWorkThread::SPAWN_ACTIVE);
            }
            instance_ = temp;
        }
    }

    return instance_;
}

IPCProcessSkeleton::IPCProcessSkeleton()
{
#ifndef CONFIG_IPC_SINGLE
    std::random_device randDevice;
    std::default_random_engine baseRand { randDevice() };
    std::uniform_int_distribution<> range(1, DBINDER_HANDLE_BASE * DBINDER_HANDLE_RANG);
    uint32_t temp = range(baseRand);
    randNum_ = static_cast<uint64_t>(temp);
#endif
}

IPCProcessSkeleton::~IPCProcessSkeleton()
{
    std::lock_guard<std::mutex> lockGuard(procMutex_);
    delete threadPool_;
    threadPool_ = nullptr;

    objects_.clear();
    isContainStub_.clear();
    rawData_.clear();
#ifndef CONFIG_IPC_SINGLE
    listenThreadReady_.reset();
    threadLockInfo_.clear();
    seqNumberToThread_.clear();
    stubObjects_.clear();
    proxyToSession_.clear();
    dbinderSessionObjects_.clear();
    noticeStub_.clear();
    transTimes_.clear();

    std::shared_ptr<ISessionService> manager = ISessionService::GetInstance();
    if (manager != nullptr) {
        (void)manager->RemoveSessionServer(DBINDER_SERVER_PKG_NAME, sessionName_);
    }
#endif
}

sptr<IRemoteObject> IPCProcessSkeleton::GetRegistryObject()
{
    if (registryObject_ == nullptr) {
        registryObject_ = FindOrNewObject(REGISTRY_HANDLE);
    }

    return registryObject_;
}

std::u16string IPCProcessSkeleton::MakeHandleDescriptor(int handle)
{
    std::string descriptor = "IPCObjectProxy" + std::to_string(handle);
    return to_utf16(descriptor);
}

IRemoteObject *IPCProcessSkeleton::FindOrNewObject(int handle)
{
    IRemoteObject *remoteObject = nullptr;
    std::u16string descriptor = MakeHandleDescriptor(handle);
    {
        std::unique_lock<std::shared_mutex> lockGuard(mutex_);

        remoteObject = QueryObjectInner(descriptor);
        if (remoteObject == nullptr) {
            if (handle == REGISTRY_HANDLE) {
                IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
                if (invoker == nullptr) {
                    DBINDER_LOGE("fail to get invoker");
                    return nullptr;
                }
                if (!invoker->PingService(REGISTRY_HANDLE)) {
                    DBINDER_LOGE("Registry is not exist");
                    return nullptr;
                }
            }

            remoteObject = new IPCObjectProxy(handle, descriptor);
            remoteObject->AttemptAcquire(this);

            if (!AttachObjectInner(remoteObject)) {
                DBINDER_LOGE("attach object fail");
                delete remoteObject;
                return nullptr;
            }
            return remoteObject;
        }
    }

    IPCObjectProxy *remoteProxy = reinterpret_cast<IPCObjectProxy *>(remoteObject);
    remoteProxy->WaitForInit();
    return remoteObject;
}

bool IPCProcessSkeleton::SetMaxWorkThread(int maxThreadNum)
{
    if (maxThreadNum <= 0) {
        DBINDER_LOGE("Set Invalid thread Number %d", maxThreadNum);
        return false;
    }

    if (threadPool_ == nullptr) {
        threadPool_ = new IPCWorkThreadPool(maxThreadNum);
    }

    threadPool_->UpdateMaxThreadNum(maxThreadNum);
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker != nullptr) {
        return invoker->SetMaxWorkThread(maxThreadNum);
    }

    return false;
}

bool IPCProcessSkeleton::SetRegistryObject(sptr<IRemoteObject> &object)
{
    if (object == nullptr) {
        DBINDER_LOGE("object is null");
        return false;
    }

    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker == nullptr) {
        DBINDER_LOGE("fail to get invoker");
        return false;
    }

    bool ret = invoker->SetRegistryObject(object);
    if (ret) {
        registryObject_ = object;
    }

    return ret;
}

bool IPCProcessSkeleton::SpawnThread(int policy, int proto)
{
    if (threadPool_ != nullptr) {
        return threadPool_->SpawnThread(policy, proto);
    }

    /* can NOT reach here */
    return false;
}

bool IPCProcessSkeleton::OnThreadTerminated(const std::string &threadName)
{
    if (threadPool_ != nullptr) {
        return threadPool_->RemoveThread(threadName);
    }

    return true;
}

bool IPCProcessSkeleton::IsContainsObject(IRemoteObject *object)
{
    /* don't care mutex result even object is deleted */
    auto it = isContainStub_.find(object);
    if (it != isContainStub_.end()) {
        return it->second;
    }

    return false;
}

bool IPCProcessSkeleton::DetachObject(IRemoteObject *object)
{
    std::unique_lock<std::shared_mutex> lockGuard(mutex_);
    // If it fails, clear it in the destructor.
    (void)isContainStub_.erase(object);

    std::u16string descriptor = object->GetObjectDescriptor();
    if (descriptor.empty()) {
        return false;
    }

    return (objects_.erase(descriptor) > 0);
}

bool IPCProcessSkeleton::AttachObject(IRemoteObject *object)
{
    std::unique_lock<std::shared_mutex> lockGuard(mutex_);
    return AttachObjectInner(object);
}

bool IPCProcessSkeleton::AttachObjectInner(IRemoteObject *object)
{
    // If it fails, it means it was added before.
    (void)isContainStub_.insert(std::pair<IRemoteObject *, bool>(object, true));
    std::u16string descriptor = object->GetObjectDescriptor();
    if (descriptor.empty()) {
        return false;
    }

    auto result = objects_.insert(std::pair<std::u16string, wptr<IRemoteObject>>(descriptor, object));
    return result.second;
}

IRemoteObject *IPCProcessSkeleton::QueryObject(const std::u16string &descriptor)
{
    if (descriptor.empty()) {
        return nullptr;
    }

    std::shared_lock<std::shared_mutex> lockGuard(mutex_);
    return QueryObjectInner(descriptor);
}

IRemoteObject *IPCProcessSkeleton::QueryObjectInner(const std::u16string &descriptor)
{
    auto it = objects_.find(descriptor);
    if (it != objects_.end()) {
        if (it->second == nullptr) {
            return nullptr;
        }
        it->second->AttemptAcquire(this);
        return it->second.GetRefPtr();
    }

    return nullptr;
}

#ifndef CONFIG_IPC_SINGLE
sptr<IRemoteObject> IPCProcessSkeleton::GetSAMgrObject()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker == nullptr) {
        return nullptr;
    }
    return invoker->GetSAMgrObject();
}

/*
 * databus return int64_t channel id, but high 32bit only use 1bit channel type, we convert to int
 * convert to 24bit channelID and 7bit channel type
 * |---1bit---|------7bit----| ------------------------24bit------|
 * | reserved | channel type |    true channel id                 |
 * don't care signed bit when convert,for we reserved high 1bit
 */
uint32_t IPCProcessSkeleton::ConvertChannelID2Int(int64_t databusChannelId)
{
    if (databusChannelId < 0) {
        return 0;
    }
    uint32_t channelType = static_cast<uint32_t>((databusChannelId >> 8) & 0X00000000FF000000ULL);
    uint32_t channelID = static_cast<uint32_t>(databusChannelId & 0X0000000000FFFFFFULL);
    return (channelType | channelID);
}

std::string IPCProcessSkeleton::GetLocalDeviceID()
{
    std::lock_guard<std::mutex> lockGuard(databusProcMutex_);

    std::string pkgName = "dbinderService";
    NodeBasicInfo nodeBasicInfo;
    if (GetLocalNodeDeviceInfo(pkgName.c_str(), &nodeBasicInfo) != 0) {
        DBINDER_LOGE("Get local node device info failed");
        return "";
    }
    std::string networkId(nodeBasicInfo.networkId);
    return networkId;
}

uint32_t IPCProcessSkeleton::GetDBinderIdleHandle(uint64_t stubIndex)
{
    std::unique_lock<std::shared_mutex> lockGuard(handleToIndexMutex_);

    if (dBinderHandle_ < DBINDER_HANDLE_BASE || dBinderHandle_ > DBINDER_HANDLE_BASE + DBINDER_HANDLE_BASE) {
        dBinderHandle_ = DBINDER_HANDLE_BASE;
    }
    uint32_t tempHandle = dBinderHandle_;
    uint32_t count = DBINDER_HANDLE_BASE;
    bool insertResult = false;
    do {
        count--;
        tempHandle++;
        if (tempHandle > DBINDER_HANDLE_BASE + DBINDER_HANDLE_BASE) {
            tempHandle = DBINDER_HANDLE_BASE;
        }
        insertResult = handleToStubIndex_.insert(std::pair<uint32_t, uint64_t>(tempHandle, stubIndex)).second;
    } while (insertResult == false && count > 0);

    if (count == 0 && insertResult == false) {
        return 0;
    }
    dBinderHandle_ = tempHandle;
    return dBinderHandle_;
}

bool IPCProcessSkeleton::DetachHandleToIndex(uint32_t handle)
{
    std::unique_lock<std::shared_mutex> lockGuard(handleToIndexMutex_);

    return (handleToStubIndex_.erase(handle) > 0);
}

bool IPCProcessSkeleton::AttachHandleToIndex(uint32_t handle, uint64_t stubIndex)
{
    std::unique_lock<std::shared_mutex> lockGuard(handleToIndexMutex_);
    auto result = handleToStubIndex_.insert(std::pair<uint32_t, uint64_t>(handle, stubIndex));
    return result.second;
}

uint64_t IPCProcessSkeleton::QueryHandleToIndex(uint32_t handle)
{
    std::shared_lock<std::shared_mutex> lockGuard(handleToIndexMutex_);

    auto it = handleToStubIndex_.find(handle);
    if (it != handleToStubIndex_.end()) {
        return it->second;
    }

    return 0;
}

uint64_t IPCProcessSkeleton::QueryHandleToIndex(std::list<uint32_t> &handleList, uint32_t &handle)
{
    std::shared_lock<std::shared_mutex> lockGuard(handleToIndexMutex_);
    for (auto it = handleList.begin(); it != handleList.end(); it++) {
        auto mapIndex = handleToStubIndex_.find(*it);
        if (mapIndex != handleToStubIndex_.end()) {
            handle = mapIndex->first;
            return mapIndex->second;
        }
    }
    return 0;
}


bool IPCProcessSkeleton::ProxyDetachDBinderSession(uint32_t handle)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);

    return (proxyToSession_.erase(handle) > 0);
}

bool IPCProcessSkeleton::ProxyAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    auto result = proxyToSession_.insert(std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handle, object));
    return result.second;
}

std::shared_ptr<DBinderSessionObject> IPCProcessSkeleton::ProxyQueryDBinderSession(uint32_t handle)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);

    auto it = proxyToSession_.find(handle);
    if (it != proxyToSession_.end()) {
        return it->second;
    }

    return nullptr;
}

bool IPCProcessSkeleton::QueryProxyBySessionHandle(uint32_t handle, std::vector<uint32_t> &proxyHandle)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);

    for (auto it = proxyToSession_.begin(); it != proxyToSession_.end(); it++) {
        std::shared_ptr<Session> session = it->second->GetBusSession();
        if (session == nullptr) {
            DBINDER_LOGE("session is null, handle = %{public}u", handle);
            return false;
        }
        uint32_t sessionHandle = IPCProcessSkeleton::ConvertChannelID2Int(session->GetChannelId());
        if (sessionHandle == handle) {
            proxyHandle.push_back(it->first);
        }
    }

    return true;
}

uint32_t IPCProcessSkeleton::QueryHandleByDatabusSession(const std::string &name, const std::string &deviceId,
    uint64_t index)
{
    std::list<uint32_t> handleList;
    bool found = false;
    {
        std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);

        for (auto it = proxyToSession_.begin(); it != proxyToSession_.end(); it++) {
            if ((it->second->GetDeviceId().compare(deviceId) == 0) &&
                (it->second->GetServiceName().compare(name) == 0)) {
                handleList.push_front(it->first);
                found = true; // found one at the least
            }
        }
    }
    uint32_t handleFound = 0;
    if (found == true && QueryHandleToIndex(handleList, handleFound) == index) {
        return handleFound;
    }

    return 0;
}

std::shared_ptr<DBinderSessionObject> IPCProcessSkeleton::QuerySessionByInfo(const std::string &name,
    const std::string &deviceId)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);

    for (auto it = proxyToSession_.begin(); it != proxyToSession_.end(); it++) {
        if ((it->second->GetDeviceId().compare(deviceId) == 0) && (it->second->GetServiceName().compare(name) == 0)) {
            return it->second;
        }
    }

    return nullptr;
}

bool IPCProcessSkeleton::StubDetachDBinderSession(uint32_t handle)
{
    std::unique_lock<std::shared_mutex> lockGuard(databusSessionMutex_);

    return (dbinderSessionObjects_.erase(handle) > 0);
}

bool IPCProcessSkeleton::StubAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object)
{
    std::unique_lock<std::shared_mutex> lockGuard(databusSessionMutex_);
    auto result =
        dbinderSessionObjects_.insert(std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handle, object));

    return result.second;
}

std::shared_ptr<DBinderSessionObject> IPCProcessSkeleton::StubQueryDBinderSession(uint32_t handle)
{
    std::shared_lock<std::shared_mutex> lockGuard(databusSessionMutex_);

    auto it = dbinderSessionObjects_.find(handle);
    if (it != dbinderSessionObjects_.end()) {
        return it->second;
    }

    return nullptr;
}

bool IPCProcessSkeleton::DetachThreadLockInfo(const std::thread::id &threadId)
{
    std::unique_lock<std::shared_mutex> lockGuard(threadLockMutex_);

    return (threadLockInfo_.erase(threadId) > 0);
}

bool IPCProcessSkeleton::AttachThreadLockInfo(std::shared_ptr<SocketThreadLockInfo> object,
    const std::thread::id &threadId)
{
    std::unique_lock<std::shared_mutex> lockGuard(threadLockMutex_);
    auto result =
        threadLockInfo_.insert(std::pair<std::thread::id, std::shared_ptr<SocketThreadLockInfo>>(threadId, object));
    return result.second;
}

std::shared_ptr<SocketThreadLockInfo> IPCProcessSkeleton::QueryThreadLockInfo(const std::thread::id &threadId)
{
    std::shared_lock<std::shared_mutex> lockGuard(threadLockMutex_);

    auto it = threadLockInfo_.find(threadId);
    if (it != threadLockInfo_.end()) {
        return it->second;
    }

    return nullptr;
}


bool IPCProcessSkeleton::AddDataThreadToIdle(const std::thread::id &threadId)
{
    std::lock_guard<std::mutex> lockGuard(idleDataMutex_);

    idleDataThreads_.push_front(threadId);
    return true;
}

bool IPCProcessSkeleton::DeleteDataThreadFromIdle(const std::thread::id &threadId)
{
    std::lock_guard<std::mutex> lockGuard(idleDataMutex_);
    for (auto it = idleDataThreads_.begin(); it != idleDataThreads_.end(); it++) {
        if ((*it) == threadId) {
            it = idleDataThreads_.erase(it);
            return true;
        }
    }

    /* not in idle state, also return true */
    return true;
}

std::thread::id IPCProcessSkeleton::GetIdleDataThread()
{
    std::lock_guard<std::mutex> lockGuard(idleDataMutex_);

    if (idleDataThreads_.size() == 0) {
        return std::thread::id();
    }

    std::thread::id threadId = idleDataThreads_.back();
    return threadId;
}

int IPCProcessSkeleton::GetSocketIdleThreadNum() const
{
    if (threadPool_ != nullptr) {
        return threadPool_->GetSocketIdleThreadNum();
    }

    return 0;
}
int IPCProcessSkeleton::GetSocketTotalThreadNum() const
{
    if (threadPool_ != nullptr) {
        return threadPool_->GetSocketTotalThreadNum();
    }

    return 0;
}

void IPCProcessSkeleton::AddDataInfoToThread(const std::thread::id &threadId,
    std::shared_ptr<ThreadProcessInfo> processInfo)
{
    std::lock_guard<std::mutex> lockGuard(dataQueueMutex_);

    (dataInfoQueue_[threadId]).push_back(processInfo);
}

std::shared_ptr<ThreadProcessInfo> IPCProcessSkeleton::PopDataInfoFromThread(const std::thread::id &threadId)
{
    std::lock_guard<std::mutex> lockGuard(dataQueueMutex_);

    if ((dataInfoQueue_[threadId]).size() == 0) {
        return 0;
    }

    std::shared_ptr<ThreadProcessInfo> processInfo = (dataInfoQueue_[threadId]).front();

    (dataInfoQueue_[threadId]).erase((dataInfoQueue_[threadId]).begin());
    return processInfo;
}

void IPCProcessSkeleton::WakeUpDataThread(const std::thread::id &threadID)
{
    if (threadID != std::thread::id()) {
        std::shared_ptr<SocketThreadLockInfo> threadLockInfo = QueryThreadLockInfo(threadID);
        if (threadLockInfo != nullptr) {
            /* Wake up this IO thread to process socket stream
             * Wake up the client processing thread
             */
            std::unique_lock<std::mutex> lock_unique(threadLockInfo->mutex);
            threadLockInfo->ready = true;
            threadLockInfo->condition.notify_one();
        }
    }
}

void IPCProcessSkeleton::AddDataThreadInWait(const std::thread::id &threadId)
{
    std::shared_ptr<SocketThreadLockInfo> threadLockInfo;

    threadLockInfo = QueryThreadLockInfo(threadId);
    if (threadLockInfo == nullptr) {
        threadLockInfo = std::make_shared<struct SocketThreadLockInfo>();
        if (!AttachThreadLockInfo(threadLockInfo, threadId)) {
            DBINDER_LOGE("thread has added lock info");
            return;
        }
    }

    AddDataThreadToIdle(threadId);
    std::unique_lock<std::mutex> lock_unique(threadLockInfo->mutex);
    threadLockInfo->condition.wait(lock_unique, [&threadLockInfo] { return threadLockInfo->ready; });
    threadLockInfo->ready = false;
    /* corresponding thread will be waked up */
    DeleteDataThreadFromIdle(threadId);
}

uint64_t IPCProcessSkeleton::GetSeqNumber()
{
    std::lock_guard<std::mutex> lockGuard(seqNumberMutex_);
    seqNumber_++; // can be overflow, and seqNumber do not use 0
    if (seqNumber_ == 0) {
        seqNumber_++;
    }
    return seqNumber_;
}

std::shared_ptr<ThreadMessageInfo> IPCProcessSkeleton::QueryThreadBySeqNumber(uint64_t seqNumber)
{
    std::lock_guard<std::mutex> lockGuard(findThreadMutex_);

    auto it = seqNumberToThread_.find(seqNumber);
    if (it != seqNumberToThread_.end()) {
        return it->second;
    }

    return nullptr;
}

void IPCProcessSkeleton::EraseThreadBySeqNumber(uint64_t seqNumber)
{
    std::lock_guard<std::mutex> lockGuard(findThreadMutex_);
    seqNumberToThread_.erase(seqNumber);
}


bool IPCProcessSkeleton::AddThreadBySeqNumber(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo)
{
    std::lock_guard<std::mutex> lockGuard(findThreadMutex_);

    auto result =
        seqNumberToThread_.insert(std::pair<uint64_t, std::shared_ptr<ThreadMessageInfo>>(seqNumber, messageInfo));

    return result.second;
}

void IPCProcessSkeleton::WakeUpThreadBySeqNumber(uint64_t seqNumber, uint32_t handle)
{
    std::shared_ptr<ThreadMessageInfo> messageInfo;

    messageInfo = QueryThreadBySeqNumber(seqNumber);
    if (messageInfo == nullptr) {
        DBINDER_LOGE("error! messageInfo is nullptr");
        return;
    }

    if (handle != messageInfo->socketId) {
        DBINDER_LOGE("error! handle is not equal messageInfo, handle = %{public}d, messageFd = %{public}u", handle,
            messageInfo->socketId);
        return;
    }

    if (messageInfo->threadId != std::thread::id()) {
        std::shared_ptr<SocketThreadLockInfo> threadLockInfo = QueryThreadLockInfo(messageInfo->threadId);
        if (threadLockInfo != nullptr) {
            /* wake up this IO thread to process socket stream
             * Wake up the client processing thread
             */
            std::unique_lock<std::mutex> lock_unique(threadLockInfo->mutex);
            threadLockInfo->ready = true;
            threadLockInfo->condition.notify_one();
        }
    }
}

bool IPCProcessSkeleton::AddSendThreadInWait(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo,
    int userWaitTime)
{
    std::shared_ptr<SocketThreadLockInfo> threadLockInfo;

    if (!AddThreadBySeqNumber(seqNumber, messageInfo)) {
        DBINDER_LOGE("add seqNumber = %" PRIu64 " failed", seqNumber);
        return false;
    }

    threadLockInfo = QueryThreadLockInfo(messageInfo->threadId);
    if (threadLockInfo == nullptr) {
        threadLockInfo = std::make_shared<struct SocketThreadLockInfo>();
        bool ret = AttachThreadLockInfo(threadLockInfo, messageInfo->threadId);
        if (!ret) {
            DBINDER_LOGE("AttachThreadLockInfo fail");
            return false;
        }
    }

    std::unique_lock<std::mutex> lock_unique(threadLockInfo->mutex);
    if (threadLockInfo->condition.wait_for(lock_unique, std::chrono::seconds(userWaitTime),
        [&threadLockInfo] { return threadLockInfo->ready; }) == false) {
        threadLockInfo->ready = false;
        DBINDER_LOGE("socket thread timeout, seqNumber = %{public}" PRIu64 ", ipc wait time = %{public}d", seqNumber,
            userWaitTime);
        return false;
    }
    threadLockInfo->ready = false;
    return true;
}

IRemoteObject *IPCProcessSkeleton::QueryStubByIndex(uint64_t stubIndex)
{
    std::shared_lock<std::shared_mutex> lockGuard(stubObjectsMutex_);

    auto it = stubObjects_.find(stubIndex);
    if (it != stubObjects_.end()) {
        return it->second;
    }

    return nullptr;
}

uint64_t IPCProcessSkeleton::AddStubByIndex(IRemoteObject *stubObject)
{
    std::unique_lock<std::shared_mutex> lockGuard(stubObjectsMutex_);

    /* if stub has its index, return it directly */
    for (auto it = stubObjects_.begin(); it != stubObjects_.end(); it++) {
        if (it->second == stubObject) {
            return it->first;
        }
    }
    uint64_t stubIndex = randNum_++;
    auto result = stubObjects_.insert(std::pair<uint64_t, IRemoteObject *>(stubIndex, stubObject));
    if (result.second) {
        return stubIndex;
    } else {
        return 0;
    }
}

uint64_t IPCProcessSkeleton::EraseStubIndex(IRemoteObject *stubObject)
{
    std::unique_lock<std::shared_mutex> lockGuard(stubObjectsMutex_);

    for (auto it = stubObjects_.begin(); it != stubObjects_.end(); it++) {
        if (it->second == stubObject) {
            uint64_t stubIndex = it->first;
            stubObjects_.erase(it);
            return stubIndex;
        }
    }
    return 0;
}

bool IPCProcessSkeleton::DetachAppInfoToStubIndex(uint32_t pid, uint32_t uid, const std::string &deviceId,
    uint64_t stubIndex)
{
    std::string appInfo = deviceId + std::to_string(pid) + std::to_string(uid);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        bool result = it->second.erase(stubIndex) > 0;
        if (it->second.size() == 0) {
            appInfoToStubIndex_.erase(it);
        }
        return result;
    }

    return false;
}

void IPCProcessSkeleton::DetachAppInfoToStubIndex(uint64_t stubIndex)
{
    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    for (auto it = appInfoToStubIndex_.begin(); it != appInfoToStubIndex_.end();) {
        (void)it->second.erase(stubIndex);
        if (it->second.size() == 0) {
            it = appInfoToStubIndex_.erase(it);
        } else {
            it++;
        }
    }
}

bool IPCProcessSkeleton::AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, const std::string &deviceId,
    uint64_t stubIndex)
{
    std::string appInfo = deviceId + std::to_string(pid) + std::to_string(uid);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        auto result = it->second.insert(std::pair<uint64_t, bool>(stubIndex, true));
        return result.second;
    }

    std::map<uint64_t, bool> mapItem { { stubIndex, true } };
    auto result = appInfoToStubIndex_.insert(std::pair<std::string, std::map<uint64_t, bool>>(appInfo, mapItem));
    return result.second;
}

bool IPCProcessSkeleton::QueryAppInfoToStubIndex(uint32_t pid, uint32_t uid, const std::string &deviceId,
    uint64_t stubIndex)
{
    std::string appInfo = deviceId + std::to_string(pid) + std::to_string(uid);

    std::shared_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        auto it2 = it->second.find(stubIndex);
        if (it2 != it->second.end()) {
            return true;
        }
    }

    return false;
}

std::shared_ptr<SocketThreadLockInfo> IPCProcessSkeleton::GetListenThreadLockInfo()
{
    return listenThreadReady_;
}

bool IPCProcessSkeleton::AttachCallbackStub(IPCObjectProxy *ipcProxy, sptr<IPCObjectStub> callbackStub)
{
    std::unique_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    auto result = noticeStub_.insert(std::pair<IPCObjectProxy *, sptr<IPCObjectStub>>(ipcProxy, callbackStub));
    return result.second;
}

bool IPCProcessSkeleton::DetachCallbackStub(IPCObjectStub *callbackStub)
{
    std::unique_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    for (auto it = noticeStub_.begin(); it != noticeStub_.end(); it++) {
        if (it->second.GetRefPtr() == callbackStub) {
            noticeStub_.erase(it);
            return true;
        }
    }
    return false;
}

bool IPCProcessSkeleton::DetachCallbackStubByProxy(IPCObjectProxy *ipcProxy)
{
    std::unique_lock<std::shared_mutex> lockGuard(callbackStubMutex_);

    return (noticeStub_.erase(ipcProxy) > 0);
}

sptr<IPCObjectStub> IPCProcessSkeleton::QueryCallbackStub(IPCObjectProxy *ipcProxy)
{
    std::shared_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    auto it = noticeStub_.find(ipcProxy);
    if (it != noticeStub_.end()) {
        return it->second;
    }

    return nullptr;
}

IPCObjectProxy *IPCProcessSkeleton::QueryCallbackProxy(IPCObjectStub *callbackStub)
{
    std::shared_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    for (auto it = noticeStub_.begin(); it != noticeStub_.end(); it++) {
        if (it->second.GetRefPtr() == callbackStub) {
            return it->first;
        }
    }

    return nullptr;
}

std::string IPCProcessSkeleton::GetDatabusName()
{
    std::lock_guard<std::mutex> lockGuard(sessionNameMutex_);

    return sessionName_;
}

bool IPCProcessSkeleton::CreateSoftbusServer(const std::string &name)
{
    std::lock_guard<std::mutex> lockGuard(sessionNameMutex_);

    if (!sessionName_.empty()) {
        return true;
    }

    if (name.empty()) {
        DBINDER_LOGE("get wrong session name = %s", name.c_str());
        return false;
    }

    std::shared_ptr<ISessionService> manager = ISessionService::GetInstance();
    if (manager == nullptr) {
        DBINDER_LOGE("fail to get softbus manager");
        return false;
    }

    std::shared_ptr<DatabusSessionCallback> callback = std::make_shared<DatabusSessionCallback>();
    if (callback == nullptr) {
        DBINDER_LOGE("fail to create softbus callbacks");
        return false;
    }

    int ret = manager->CreateSessionServer(DBINDER_SERVER_PKG_NAME, name, callback);
    if (ret != 0) {
        DBINDER_LOGE("fail to create softbus server");
        return false;
    }

    sessionName_ = name;
    SpawnThread(IPCWorkThread::PROCESS_ACTIVE, IRemoteObject::IF_PROT_DATABUS);

    return true;
}

bool IPCProcessSkeleton::AttachRawData(uint32_t fd, std::shared_ptr<InvokerRawData> rawData)
{
    std::unique_lock<std::shared_mutex> lockGuard(rawDataMutex_);
    /* always discard the old one if exists */
    rawData_.erase(fd);
    auto result = rawData_.insert(std::pair<uint32_t, std::shared_ptr<InvokerRawData>>(fd, rawData));
    return result.second;
}

bool IPCProcessSkeleton::DetachRawData(uint32_t fd)
{
    std::unique_lock<std::shared_mutex> lockGuard(rawDataMutex_);
    return (rawData_.erase(fd) > 0);
}

std::shared_ptr<InvokerRawData> IPCProcessSkeleton::QueryRawData(uint32_t fd)
{
    std::shared_lock<std::shared_mutex> lockGuard(rawDataMutex_);
    auto it = rawData_.find(fd);
    if (it != rawData_.end()) {
        return it->second;
    }
    return nullptr;
}

bool IPCProcessSkeleton::AttachStubRecvRefInfo(IRemoteObject *stub, int pid, const std::string &deviceId)
{
    auto check = [&stub, &pid, &deviceId](const std::shared_ptr<StubRefCountObject> &stubRef) {
        return stubRef->GetRemotePid() == pid && stubRef->GetDeviceId().compare(deviceId) == 0 &&
            stubRef->GetStubObject() == stub;
    };

    std::unique_lock<std::shared_mutex> lockGuard(stubRecvRefMutex_);
    auto it = std::find_if(stubRecvRefs_.begin(), stubRecvRefs_.end(), check);
    if (it != stubRecvRefs_.end()) {
        DBINDER_LOGE("fail to attach stub recv ref info, already in");
        return false;
    }

    std::shared_ptr<StubRefCountObject> refCount = std::make_shared<StubRefCountObject>(stub, pid, deviceId);
    stubRecvRefs_.push_front(refCount);
    return true;
}

void IPCProcessSkeleton::DetachStubRecvRefInfo(int pid, const std::string &deviceId)
{
    auto check = [&pid, &deviceId](const std::shared_ptr<StubRefCountObject> &stubRef) {
        return stubRef->GetRemotePid() == pid && stubRef->GetDeviceId().compare(deviceId) == 0;
    };

    std::unique_lock<std::shared_mutex> lockGuard(stubRecvRefMutex_);
    stubRecvRefs_.remove_if(check);
}

bool IPCProcessSkeleton::DetachStubRecvRefInfo(const IRemoteObject *stub, int pid, const std::string &deviceId)
{
    std::unique_lock<std::shared_mutex> lockGuard(stubRecvRefMutex_);
    for (auto it = stubRecvRefs_.begin(); it != stubRecvRefs_.end(); it++) {
        std::shared_ptr<StubRefCountObject> object = (*it);
        if ((object->GetRemotePid() == pid) && (object->GetDeviceId().compare(deviceId) == 0) &&
            (object->GetStubObject() == stub)) {
            stubRecvRefs_.erase(it);
            return true;
        }
    }
    return false;
}

void IPCProcessSkeleton::DetachStubRecvRefInfo(const IRemoteObject *stub)
{
    auto check = [&stub](const std::shared_ptr<StubRefCountObject> &stubRef) {
        return stubRef->GetStubObject() == stub;
    };

    std::unique_lock<std::shared_mutex> lockGuard(stubRecvRefMutex_);
    stubRecvRefs_.remove_if(check);
}

std::list<IRemoteObject *> IPCProcessSkeleton::QueryStubRecvRefInfo(int pid, const std::string &deviceId)
{
    std::shared_lock<std::shared_mutex> lockGuard(stubRecvRefMutex_);
    std::list<IRemoteObject *> stubList;
    for (auto it = stubRecvRefs_.begin(); it != stubRecvRefs_.end(); it++) {
        std::shared_ptr<StubRefCountObject> object = (*it);
        if ((object->GetRemotePid() == pid) && (object->GetDeviceId().compare(deviceId) == 0)) {
            stubList.push_back(object->GetStubObject());
        }
    }

    return stubList;
}

void IPCProcessSkeleton::DetachStubRefInfo(int pid, const std::string &deviceId)
{
    std::list<IRemoteObject *> stubList = QueryStubRecvRefInfo(pid, deviceId);
    if (!stubList.empty()) {
        for (auto it = stubList.begin(); it != stubList.end(); it++) {
            (*it)->DecStrongRef(this);
        }
    }
    DetachStubRecvRefInfo(pid, deviceId);
    DetachStubSendRefInfo(pid, deviceId);
}

void IPCProcessSkeleton::DetachStubRefInfo(IRemoteObject *stub, int pid, const std::string &deviceId)
{
    if (DetachStubRecvRefInfo(stub, pid, deviceId) == true) {
        stub->DecStrongRef(this);
    }
    DetachStubSendRefInfo(stub, pid, deviceId);
}

bool IPCProcessSkeleton::IncStubRefTimes(IRemoteObject *stub)
{
    std::lock_guard<std::mutex> lockGuard(transTimesMutex_);

    auto it = transTimes_.find(stub);
    if (it != transTimes_.end()) {
        it->second++;
        return true;
    }

    auto result = transTimes_.insert(std::pair<IRemoteObject *, uint32_t>(stub, TRANS_TIME_INIT_VALUE));
    return result.second;
}

bool IPCProcessSkeleton::DecStubRefTimes(IRemoteObject *stub)
{
    std::lock_guard<std::mutex> lockGuard(transTimesMutex_);

    auto it = transTimes_.find(stub);
    if (it != transTimes_.end()) {
        if (it->second > 0) {
            it->second--;
            return true;
        }
    }
    return false;
}

bool IPCProcessSkeleton::DetachStubRefTimes(IRemoteObject *stub)
{
    std::lock_guard<std::mutex> lockGuard(transTimesMutex_);
    return (transTimes_.erase(stub) > 0);
}

bool IPCProcessSkeleton::AttachStubSendRefInfo(IRemoteObject *stub, int pid, const std::string &deviceId)
{
    auto check = [&stub, &pid, &deviceId](const std::shared_ptr<StubRefCountObject> &stubRef) {
        return stubRef->GetRemotePid() == pid && stubRef->GetDeviceId().compare(deviceId) == 0 &&
            stubRef->GetStubObject() == stub;
    };

    std::lock_guard<std::mutex> lockGuard(stubSendRefMutex_);
    auto it = std::find_if(stubSendRefs_.begin(), stubSendRefs_.end(), check);
    if (it != stubSendRefs_.end()) {
        DBINDER_LOGE("fail to attach stub sender ref info, already in");
        return false;
    }
    std::shared_ptr<StubRefCountObject> refCount = std::make_shared<StubRefCountObject>(stub, pid, deviceId);
    stubSendRefs_.push_front(refCount);

    return true;
}

void IPCProcessSkeleton::DetachStubSendRefInfo(IRemoteObject *stub)
{
    auto check = [&stub](const std::shared_ptr<StubRefCountObject> &stubRef) {
        return stubRef->GetStubObject() == stub;
    };

    std::lock_guard<std::mutex> lockGuard(stubSendRefMutex_);
    stubSendRefs_.remove_if(check);
}

void IPCProcessSkeleton::DetachStubSendRefInfo(int pid, const std::string &deviceId)
{
    auto check = [&pid, &deviceId](const std::shared_ptr<StubRefCountObject> &stubRef) {
        return stubRef->GetRemotePid() == pid && stubRef->GetDeviceId().compare(deviceId) == 0;
    };

    std::lock_guard<std::mutex> lockGuard(stubSendRefMutex_);
    stubSendRefs_.remove_if(check);
}

void IPCProcessSkeleton::DetachStubSendRefInfo(IRemoteObject *stub, int pid, const std::string &deviceId)
{
    auto check = [&pid, &deviceId, &stub](const std::shared_ptr<StubRefCountObject> &stubRef) {
        return stubRef->GetRemotePid() == pid && stubRef->GetDeviceId().compare(deviceId) == 0 &&
            stubRef->GetStubObject() == stub;
    };

    std::lock_guard<std::mutex> lockGuard(stubSendRefMutex_);
    stubSendRefs_.remove_if(check);
}

bool IPCProcessSkeleton::IsSameRemoteObject(IRemoteObject *stub, int pid, int uid, const std::string &deviceId,
    const std::shared_ptr<CommAuthInfo> &auth)
{
    if ((auth->GetStubObject() == stub) && (auth->GetRemotePid() == pid) && (auth->GetRemoteUid() == uid) &&
        (auth->GetRemoteDeviceId().compare(deviceId) == 0)) {
        return true;
    } else {
        return false;
    }
}

bool IPCProcessSkeleton::IsSameRemoteObject(int pid, int uid, const std::string &deviceId,
    const std::shared_ptr<CommAuthInfo> &auth)
{
    if ((auth->GetRemotePid() == pid) && (auth->GetRemoteUid() == uid) &&
        (auth->GetRemoteDeviceId().compare(deviceId) == 0)) {
        return true;
    } else {
        return false;
    }
}

bool IPCProcessSkeleton::AttachCommAuthInfo(IRemoteObject *stub, int pid, int uid, const std::string &deviceId)
{
    auto check = [&stub, &pid, &uid, &deviceId, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(stub, pid, uid, deviceId, auth);
    };

    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    auto it = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (it != commAuth_.end()) {
        DBINDER_LOGI("AttachCommAuthInfo already");
        return true;
    }

    std::shared_ptr<CommAuthInfo> authObject = std::make_shared<CommAuthInfo>(stub, pid, uid, deviceId);
    commAuth_.push_front(authObject);
    return true;
}

void IPCProcessSkeleton::DetachCommAuthInfo(IRemoteObject *stub, int pid, int uid, const std::string &deviceId)
{
    auto check = [&stub, &pid, &uid, &deviceId, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(stub, pid, uid, deviceId, auth);
    };

    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    commAuth_.remove_if(check);
}

bool IPCProcessSkeleton::QueryIsAuth(int pid, int uid, const std::string &deviceId)
{
    auto check = [&pid, &uid, &deviceId, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(pid, uid, deviceId, auth);
    };

    std::shared_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    auto it = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (it != commAuth_.end()) {
        return true;
    }
    DBINDER_LOGE("Query Comm Auth Fail");
    return false;
}

void IPCProcessSkeleton::DetachCommAuthInfoByStub(IRemoteObject *stub)
{
    auto check = [&stub](const std::shared_ptr<CommAuthInfo> &auth) { return auth->GetStubObject() == stub; };
    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    commAuth_.remove_if(check);
}
#endif
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS

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

#include <securec.h>
#include <unistd.h>
#include <random>
#include <sys/epoll.h>
#include "string_ex.h"
#include "ipc_debug.h"
#include "ipc_types.h"

#include "ipc_thread_skeleton.h"
#include "process_skeleton.h"
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

std::mutex IPCProcessSkeleton::procMutex_;
IPCProcessSkeleton *IPCProcessSkeleton::instance_ = nullptr;

IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(procMutex_);
        if (instance_ == nullptr) {
            IPCProcessSkeleton *temp = new (std::nothrow) IPCProcessSkeleton();
            if (temp == nullptr) {
                ZLOGE(LOG_LABEL, "create IPCProcessSkeleton object failed");
                return nullptr;
            }
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
    int temp = range(baseRand);
    randNum_ = static_cast<uint64_t>(temp);
#endif
}

std::string IPCProcessSkeleton::ConvertToSecureString(const std::string &deviceId)
{
    if (strlen(deviceId.c_str()) <= ENCRYPT_LENGTH) {
        return "****";
    }
    return deviceId.substr(0, ENCRYPT_LENGTH) + "****" + deviceId.substr(strlen(deviceId.c_str()) - ENCRYPT_LENGTH);
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
    threadLockInfo_.clear();
    seqNumberToThread_.clear();
    stubObjects_.clear();
    proxyToSession_.clear();
    dbinderSessionObjects_.clear();
    noticeStub_.clear();

    std::shared_ptr<ISessionService> manager = ISessionService::GetInstance();
    if (manager != nullptr) {
        std::string pkgName = std::string(DBINDER_SERVER_PKG_NAME) + "_" + std::to_string(getpid());
        (void)manager->RemoveSessionServer(pkgName, sessionName_);
    }
#endif
}

sptr<IRemoteObject> IPCProcessSkeleton::GetRegistryObject()
{
    auto current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "get process skeleton failed");
        return nullptr;
    }
    sptr<IRemoteObject> object = current->GetRegistryObject();
    if (object == nullptr) {
        object = FindOrNewObject(REGISTRY_HANDLE);
        if (object != nullptr) {
            current->SetRegistryObject(object);
        }
    }
    return object;
}

std::u16string IPCProcessSkeleton::MakeHandleDescriptor(int handle)
{
    std::string descriptor = "IPCObjectProxy" + std::to_string(handle);
    return Str8ToStr16(descriptor);
}

sptr<IRemoteObject> IPCProcessSkeleton::FindOrNewObject(int handle)
{
    sptr<IRemoteObject> result = nullptr;
    std::u16string descriptor = MakeHandleDescriptor(handle);
    if (descriptor.length() == 0) {
        ZLOGE(LOG_LABEL, "make handle descriptor failed");
        return nullptr;
    }
    {
        result = QueryObject(descriptor);
        if (result == nullptr) {
            // Either this is a new handle or attemptIncStrong failed(strong refcount has been decreased to zero),
            // we need to create a new proxy and initialize it. Meanwhile, the old proxy is destroying concurrently.
            if (handle == REGISTRY_HANDLE) {
                IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
                if (invoker == nullptr) {
                    ZLOGE(LOG_LABEL, "failed to get invoker");
                    return nullptr;
                }
                if (!invoker->PingService(REGISTRY_HANDLE)) {
                    ZLOGE(LOG_LABEL, "Registry is not exist");
                    return nullptr;
                }
            }
            // OnFirstStrongRef will be called.
            result = new (std::nothrow) IPCObjectProxy(handle, descriptor);
            AttachObject(result.GetRefPtr());
        }
    }

    sptr<IPCObjectProxy> proxy = reinterpret_cast<IPCObjectProxy *>(result.GetRefPtr());
    // When a new proxy is initializing, other thread will find an existed proxy and need to wait,
    // this makes sure proxy has been initialized when ReadRemoteObject return.
    proxy->WaitForInit();
#ifndef CONFIG_IPC_SINGLE
    if (proxy->GetProto() == IRemoteObject::IF_PROT_ERROR) {
        ZLOGE(LOG_LABEL, "init rpc proxy:%{public}d failed", handle);
        return nullptr;
    }
#endif
    return result;
}

bool IPCProcessSkeleton::SetMaxWorkThread(int maxThreadNum)
{
    if (maxThreadNum <= 0) {
        ZLOGE(LOG_LABEL, "Set Invalid thread Number %d", maxThreadNum);
        return false;
    }

    if (threadPool_ == nullptr) {
        threadPool_ = new (std::nothrow) IPCWorkThreadPool(maxThreadNum);
        if (threadPool_ == nullptr) {
            ZLOGE(LOG_LABEL, "create IPCWorkThreadPool object failed");
            return false;
        }
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
        ZLOGE(LOG_LABEL, "object is null");
        return false;
    }
    auto current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "get process skeleton failed");
        return false;
    }
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    if (invoker == nullptr) {
        ZLOGE(LOG_LABEL, "fail to get invoker");
        return false;
    }
    bool ret = invoker->SetRegistryObject(object);
    if (ret) {
        current->SetRegistryObject(object);
        current->SetSamgrFlag(true);
    }
    ZLOGI(LOG_LABEL, "%{public}s set registry result is %{public}d", __func__, ret);
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
    // check whether it is a valid IPCObjectStub object.
    std::shared_lock<std::shared_mutex> lockGuard(mutex_);
    auto it = isContainStub_.find(object);
    if (it != isContainStub_.end()) {
        return it->second;
    }

    return false;
}

bool IPCProcessSkeleton::DetachObject(IRemoteObject *object)
{
    std::unique_lock<std::shared_mutex> lockGuard(mutex_);
    (void)isContainStub_.erase(object);

    std::u16string descriptor = object->GetObjectDescriptor();
    if (descriptor.empty()) {
        return false;
    }
    // This handle may have already been replaced with a new IPCObjectProxy,
    // if someone failed the AttemptIncStrong.
    auto iterator = objects_.find(descriptor);
    if (iterator->second == object) {
        objects_.erase(iterator);
        return true;
    }
    return false;
}

bool IPCProcessSkeleton::AttachObject(IRemoteObject *object)
{
    std::unique_lock<std::shared_mutex> lockGuard(mutex_);
    (void)isContainStub_.insert(std::pair<IRemoteObject *, bool>(object, true));

    std::u16string descriptor = object->GetObjectDescriptor();
    if (descriptor.empty()) {
        return false;
    }
    // If attemptIncStrong failed, old proxy might still exist, replace it with the new proxy.
    wptr<IRemoteObject> wp = object;
    auto result = objects_.insert_or_assign(descriptor, wp);
    return result.second;
}

sptr<IRemoteObject> IPCProcessSkeleton::QueryObject(const std::u16string &descriptor)
{
    sptr<IRemoteObject> result = nullptr;
    if (descriptor.empty()) {
        return result;
    }

    std::shared_lock<std::shared_mutex> lockGuard(mutex_);
    IRemoteObject *remoteObject = nullptr;
    auto it = objects_.find(descriptor);
    if (it != objects_.end()) {
        // Life-time of IPCObjectProxy is extended to WEAK
        // now it's weak reference counted, so it's safe to get raw pointer
        remoteObject = it->second.GetRefPtr();
    }
    if (remoteObject == nullptr || !remoteObject->AttemptIncStrong(this)) {
        return result;
    }
    result = remoteObject;
    return result;
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
    uint64_t databusChannel = static_cast<uint64_t>(databusChannelId);
    uint32_t channelType = static_cast<uint32_t>((databusChannel >> 8) & 0X00000000FF000000ULL);
    uint32_t channelID = static_cast<uint32_t>(databusChannel & 0X0000000000FFFFFFULL);
    return (channelType | channelID);
}

std::string IPCProcessSkeleton::GetLocalDeviceID()
{
    std::lock_guard<std::mutex> lockGuard(databusProcMutex_);

    std::string pkgName = std::string(DBINDER_SERVER_PKG_NAME) + "_" + std::to_string(getpid());
    NodeBasicInfo nodeBasicInfo;
    if (GetLocalNodeDeviceInfo(pkgName.c_str(), &nodeBasicInfo) != 0) {
        ZLOGE(LOG_LABEL, "Get local node device info failed");
        return "";
    }
    std::string networkId(nodeBasicInfo.networkId);
    return networkId;
}

bool IPCProcessSkeleton::IsHandleMadeByUser(uint32_t handle)
{
    if (handle >= DBINDER_HANDLE_BASE && handle <= (DBINDER_HANDLE_BASE + DBINDER_HANDLE_BASE)) {
        ZLOGE(LOG_LABEL, "handle = %{public}u is make by user, not kernel", handle);
        return true;
    }
    return false;
}

uint32_t IPCProcessSkeleton::GetDBinderIdleHandle(std::shared_ptr<DBinderSessionObject> session)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    uint32_t tempHandle = dBinderHandle_;
    int count = DBINDER_HANDLE_BASE;
    bool insertResult = false;
    do {
        count--;
        tempHandle++;
        if (tempHandle > DBINDER_HANDLE_BASE + DBINDER_HANDLE_BASE) {
            tempHandle = DBINDER_HANDLE_BASE;
        }
        insertResult = proxyToSession_.insert(std::pair<uint32_t,
            std::shared_ptr<DBinderSessionObject>>(tempHandle, session)).second;
    } while (insertResult == false && count > 0);

    if (count == 0 && insertResult == false) {
        return 0;
    }
    dBinderHandle_ = tempHandle;
    return dBinderHandle_;
}

std::shared_ptr<DBinderSessionObject> IPCProcessSkeleton::ProxyDetachDBinderSession(uint32_t handle,
    IPCObjectProxy *proxy)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    std::shared_ptr<DBinderSessionObject> tmp = nullptr;
    auto it = proxyToSession_.find(handle);
    if (it != proxyToSession_.end() && it->second->GetProxy() == proxy) {
        tmp = it->second;
        proxyToSession_.erase(it);
    }
    ZLOGI(LOG_LABEL, "handle = %{public}u erase: %{public}d, not found: %{public}d", handle,
        tmp != nullptr, it == proxyToSession_.end());
    return tmp;
}

bool IPCProcessSkeleton::ProxyAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object)
{
    ZLOGI(LOG_LABEL, "attach handle = %{public}u to session: %{public}" PRIu64
        " service: %{public}s, stubIndex: %{public}" PRIu64 " tokenId: %{public}u",
        handle, object->GetBusSession()->GetChannelId(), object->GetServiceName().c_str(),
        object->GetStubIndex(), object->GetTokenId());
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

bool IPCProcessSkeleton::ProxyMoveDBinderSession(uint32_t handle, IPCObjectProxy *proxy)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    auto it = proxyToSession_.find(handle);
    if (it != proxyToSession_.end()) {
        ZLOGI(LOG_LABEL, "found session of handle = %{public}u old==null: %{public}d, old==new: %{public}d", handle,
            it->second->GetProxy() == nullptr, it->second->GetProxy() == proxy);
        // moves ownership to this new proxy, so old proxy should not detach this session and stubIndex
        // see QueryHandleByDatabusSession
        it->second->SetProxy(proxy);
        return true;
    }
    return false;
}

bool IPCProcessSkeleton::QueryProxyBySessionHandle(uint32_t handle, std::vector<uint32_t> &proxyHandle)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    for (auto it = proxyToSession_.begin(); it != proxyToSession_.end(); it++) {
        std::shared_ptr<Session> session = it->second->GetBusSession();
        if (session == nullptr) {
            continue;
        }
        uint32_t sessionHandle = IPCProcessSkeleton::ConvertChannelID2Int(session->GetChannelId());
        if (sessionHandle == handle) {
            proxyHandle.push_back(it->first);
        }
    }
    return true;
}

uint32_t IPCProcessSkeleton::QueryHandleByDatabusSession(const std::string &name, const std::string &deviceId,
    uint64_t stubIndex)
{
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);

    for (auto it = proxyToSession_.begin(); it != proxyToSession_.end(); it++) {
        if ((it->second->GetStubIndex() == stubIndex) && (it->second->GetDeviceId().compare(deviceId) == 0) &&
            (it->second->GetServiceName().compare(name) == 0)) {
            ZLOGI(LOG_LABEL, "found session of handle = %{public}u", it->first);
            // marks ownership not belong to the original proxy, In FindOrNewObject method,
            // we will find the original proxy and take ownership again if the original proxy is still existed.
            // Otherwise, if the original proxy is destroyed, it will not erase the session
            // because we marks here. Later we will setProxy again with the new proxy in UpdateProto method
            it->second->SetProxy(nullptr);
            return it->first;
        }
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

bool IPCProcessSkeleton::StubDetachDBinderSession(uint32_t handle, uint32_t &tokenId)
{
    std::unique_lock<std::shared_mutex> lockGuard(databusSessionMutex_);
    auto it = dbinderSessionObjects_.find(handle);
    if (it != dbinderSessionObjects_.end()) {
        tokenId = it->second->GetTokenId();
        ZLOGI(LOG_LABEL, "%{public}s: handle=%{public}u, stubIndex=%{public}" PRIu64 " tokenId=%{public}u",
            __func__, handle, it->second->GetStubIndex(), tokenId);
        dbinderSessionObjects_.erase(it);
        return true;
    }
    return false;
}

bool IPCProcessSkeleton::StubAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object)
{
    std::unique_lock<std::shared_mutex> lockGuard(databusSessionMutex_);
    auto result =
        dbinderSessionObjects_.insert(std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handle, object));
    ZLOGI(LOG_LABEL, "handle=%{public}u, stubIndex=%{public}" PRIu64 " tokenId=%{public}u result=%{public}u",
        handle, object->GetStubIndex(), object->GetTokenId(), result.second);
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
        return nullptr;
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
            ZLOGE(LOG_LABEL, "thread has added lock info");
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
        ZLOGE(LOG_LABEL, "error! messageInfo is nullptr");
        return;
    }

    if (handle != messageInfo->socketId) {
        ZLOGE(LOG_LABEL, "handle is not equal, handle = %{public}d, socketFd = %{public}u", handle,
            messageInfo->socketId);
        return;
    }

    std::unique_lock<std::mutex> lock_unique(messageInfo->mutex);
    messageInfo->ready = true;
    messageInfo->condition.notify_one();
}

bool IPCProcessSkeleton::AddSendThreadInWait(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo,
    int userWaitTime)
{
    if (!AddThreadBySeqNumber(seqNumber, messageInfo)) {
        ZLOGE(LOG_LABEL, "add seqNumber = %{public}" PRIu64 " failed", seqNumber);
        return false;
    }

    std::unique_lock<std::mutex> lock_unique(messageInfo->mutex);
    if (messageInfo->condition.wait_for(lock_unique, std::chrono::seconds(userWaitTime),
        [&messageInfo] { return messageInfo->ready; }) == false) {
        messageInfo->ready = false;
        ZLOGE(LOG_LABEL, "socket thread timeout, seqNumber = %{public}" PRIu64 ", waittime = %{public}d",
            seqNumber, userWaitTime);
        return false;
    }
    messageInfo->ready = false;
    return true;
}

IRemoteObject *IPCProcessSkeleton::QueryStubByIndex(uint64_t stubIndex)
{
    if (stubIndex == 0) {
        ZLOGE(LOG_LABEL, "stubIndex invalid");
        return nullptr;
    }
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

uint64_t IPCProcessSkeleton::QueryStubIndex(IRemoteObject *stubObject)
{
    std::unique_lock<std::shared_mutex> lockGuard(stubObjectsMutex_);

    for (auto it = stubObjects_.begin(); it != stubObjects_.end(); it++) {
        if (it->second == stubObject) {
            return it->first;
        }
    }
    return 0;
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

std::string IPCProcessSkeleton::UIntToString(uint32_t input)
{
    // 12: convert to fixed string length
    char str[12] = {0};
    if (sprintf_s(str, sizeof(str) / sizeof(str[0]), "%011u", input) <= EOK) {
        ZLOGE(LOG_LABEL, "sprintf_s fail");
    }
    return str;
}

bool IPCProcessSkeleton::DetachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, uint64_t stubIndex, uint32_t listenFd)
{
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);
    bool result = false;
    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        std::map<uint64_t, uint32_t> indexs = it->second;
        auto it2 = indexs.find(stubIndex);
        if (it2 != indexs.end() && it2->second == listenFd) {
            indexs.erase(it2);
            result = true;
        }
        if (indexs.empty()) {
            appInfoToStubIndex_.erase(it);
        }
    }
    ZLOGI(LOG_LABEL, "pid %{public}u uid %{public}u tokenId %{public}u deviceId %{public}s stubIndex %{public}" PRIu64
        " listenFd %{public}u result %{public}d", pid, uid, tokenId, ConvertToSecureString(deviceId).c_str(),
        stubIndex, listenFd, result);
    return result;
}

std::list<uint64_t> IPCProcessSkeleton::DetachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, uint32_t listenFd)
{
    std::list<uint64_t> indexs;
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);
    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        std::map<uint64_t, uint32_t> stubIndexs = it->second;
        for (auto it2 = stubIndexs.begin(); it2 != stubIndexs.end();) {
            if (it2->second == listenFd) {
                indexs.push_back(it2->first);
                it2 = stubIndexs.erase(it2);
            } else {
                it2++;
            }
        }
        if (stubIndexs.empty()) {
            appInfoToStubIndex_.erase(it);
        }
    }
    ZLOGI(LOG_LABEL, "pid %{public}u uid %{public}u tokenId %{public}u deviceId %{public}s listenFd %{public}u",
        pid, uid, tokenId, ConvertToSecureString(deviceId).c_str(), listenFd);
    return indexs;
}

void IPCProcessSkeleton::DetachAppInfoToStubIndex(uint64_t stubIndex)
{
    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    for (auto it = appInfoToStubIndex_.begin(); it != appInfoToStubIndex_.end();) {
        if (it->second.erase(stubIndex) > 0) {
            ZLOGI(LOG_LABEL, "appInfo %{public}s stubIndex %{public}" PRIu64,
                ConvertToSecureString(it->first).c_str(), stubIndex);
        }
        if (it->second.size() == 0) {
            it = appInfoToStubIndex_.erase(it);
        } else {
            it++;
        }
    }
}

bool IPCProcessSkeleton::AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, uint64_t stubIndex, uint32_t listenFd)
{
    ZLOGI(LOG_LABEL, "pid %{public}u uid %{public}u tokenId %{public}u deviceId %{public}s stubIndex %{public}" PRIu64
        " listenFd %{public}u", pid, uid, tokenId, ConvertToSecureString(deviceId).c_str(), stubIndex, listenFd);
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        auto result = it->second.insert_or_assign(stubIndex, listenFd);
        return result.second;
    }

    std::map<uint64_t, uint32_t> mapItem { { stubIndex, listenFd } };
    auto result = appInfoToStubIndex_.insert(std::pair<std::string, std::map<uint64_t, uint32_t>>(appInfo, mapItem));
    return result.second;
}

bool IPCProcessSkeleton::AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, uint32_t listenFd)
{
    ZLOGI(LOG_LABEL, "pid %{public}u uid %{public}u tokenId %{public}u deviceId %{public}s listenFd %{public}u",
        pid, uid, tokenId, ConvertToSecureString(deviceId).c_str(), listenFd);
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        std::map<uint64_t, uint32_t> indexs = it->second;
        // OnSessionOpen update listenFd
        for (auto it2 = indexs.begin(); it2 != indexs.end(); it2++) {
            it2->second = listenFd;
        }
    }
    return true;
}

bool IPCProcessSkeleton::QueryAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, uint64_t stubIndex, uint32_t listenFd)
{
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::shared_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        auto it2 = it->second.find(stubIndex);
        // listenFd may be marked as 0
        if (it2 != it->second.end() && (it2->second == 0 || it2->second == listenFd)) {
            ZLOGI(LOG_LABEL, "appInfo %{public}s stubIndex %{public}" PRIu64,
                ConvertToSecureString(appInfo).c_str(), stubIndex);
            return true;
        }
    }

    return false;
}

bool IPCProcessSkeleton::AttachCallbackStub(IPCObjectProxy *ipcProxy, sptr<IPCObjectStub> callbackStub)
{
    std::unique_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    auto result = noticeStub_.insert(std::pair<IPCObjectProxy *, sptr<IPCObjectStub>>(ipcProxy, callbackStub));
    return result.second;
}

sptr<IPCObjectStub> IPCProcessSkeleton::DetachCallbackStub(IPCObjectProxy *ipcProxy)
{
    sptr<IPCObjectStub> ret = nullptr;
    std::unique_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    auto it = noticeStub_.find(ipcProxy);
    if (it != noticeStub_.end()) {
        ret = it->second;
        noticeStub_.erase(it);
    }
    return ret;
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

sptr<IPCObjectProxy> IPCProcessSkeleton::QueryCallbackProxy(IPCObjectStub *callbackStub)
{
    sptr<IPCObjectProxy> ret = nullptr;
    std::shared_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    for (auto it = noticeStub_.begin(); it != noticeStub_.end(); it++) {
        if (it->second.GetRefPtr() == callbackStub) {
            ret = it->first;
        }
    }

    return ret;
}

std::string IPCProcessSkeleton::GetDatabusName()
{
    std::lock_guard<std::mutex> lockGuard(sessionNameMutex_);

    return sessionName_;
}

bool IPCProcessSkeleton::CreateSoftbusServer(const std::string &name)
{
    std::lock_guard<std::mutex> lockGuard(sessionNameMutex_);

    if (name.empty()) {
        ZLOGE(LOG_LABEL, "get wrong session name = %s", name.c_str());
        return false;
    }

    std::shared_ptr<ISessionService> manager = ISessionService::GetInstance();
    if (manager == nullptr) {
        ZLOGE(LOG_LABEL, "fail to get softbus manager");
        return false;
    }

    std::shared_ptr<DatabusSessionCallback> callback = std::make_shared<DatabusSessionCallback>();
    if (callback == nullptr) {
        ZLOGE(LOG_LABEL, "fail to create softbus callbacks");
        return false;
    }
    std::string pkgName = std::string(DBINDER_SERVER_PKG_NAME) + "_" + std::to_string(getpid());
    int ret = manager->CreateSessionServer(pkgName, name, callback);
    if (ret != 0) {
        ZLOGE(LOG_LABEL, "fail to create softbus server, maybe created already");
    }

    if (name != sessionName_) {
        SpawnThread(IPCWorkThread::PROCESS_ACTIVE, IRemoteObject::IF_PROT_DATABUS);
    }
    sessionName_ = name;
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

bool IPCProcessSkeleton::IsSameRemoteObject(IRemoteObject *stub, int pid, int uid, uint32_t tokenId,
    const std::string &deviceId, const std::shared_ptr<CommAuthInfo> &auth)
{
    if ((auth->GetStubObject() == stub) && (auth->GetRemotePid() == pid) && (auth->GetRemoteUid() == uid) &&
        (auth->GetRemoteTokenId() == tokenId) && (auth->GetRemoteDeviceId().compare(deviceId) == 0)) {
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

bool IPCProcessSkeleton::AttachCommAuthInfo(IRemoteObject *stub, int pid, int uid, uint32_t tokenId,
    const std::string &deviceId)
{
    auto check = [&stub, &pid, &uid, &tokenId, &deviceId, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(stub, pid, uid, tokenId, deviceId, auth);
    };
    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    auto it = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (it != commAuth_.end()) {
        return false;
    }

    std::shared_ptr<CommAuthInfo> authObject = std::make_shared<CommAuthInfo>(stub, pid, uid, tokenId, deviceId);
    commAuth_.push_front(authObject);
    return true;
}

bool IPCProcessSkeleton::DetachCommAuthInfo(IRemoteObject *stub, int pid, int uid, uint32_t tokenId,
    const std::string &deviceId)
{
    auto check = [&stub, &pid, &uid, &tokenId, &deviceId, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(stub, pid, uid, tokenId, deviceId, auth);
    };
    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    auto it = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (it != commAuth_.end()) {
        commAuth_.erase(it);
        return true;
    }
    return false;
}

bool IPCProcessSkeleton::QueryCommAuthInfo(int pid, int uid, uint32_t &tokenId, const std::string &deviceId)
{
    auto check = [&pid, &uid, &deviceId, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(pid, uid, deviceId, auth);
    };

    std::shared_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    auto it = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (it != commAuth_.end()) {
        if ((*it) == nullptr) {
            tokenId = 0;
            return false;
        }
        tokenId = (*it)->GetRemoteTokenId();
        return true;
    }
    ZLOGI(LOG_LABEL, "%{public}s: NOT exist, deviceId %{public}s pid %{public}u uid %{public}u",
        __func__, ConvertToSecureString(deviceId).c_str(), pid, uid);
    tokenId = 0;
    return false;
}

void IPCProcessSkeleton::DetachCommAuthInfoByStub(IRemoteObject *stub)
{
    auto check = [&stub](const std::shared_ptr<CommAuthInfo> &auth) { return auth->GetStubObject() == stub; };
    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    commAuth_.remove_if(check);
}

bool IPCProcessSkeleton::AttachDBinderCallbackStub(sptr<IRemoteObject> proxy, sptr<DBinderCallbackStub> stub)
{
    std::unique_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
    auto result = dbinderSentCallback.insert(std::pair<sptr<IRemoteObject>, wptr<DBinderCallbackStub>>(proxy, stub));
    return result.second;
}

bool IPCProcessSkeleton::DetachDBinderCallbackStubByProxy(sptr<IRemoteObject> proxy)
{
    std::unique_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);

    return (dbinderSentCallback.erase(proxy) > 0);
}

void IPCProcessSkeleton::DetachDBinderCallbackStub(DBinderCallbackStub *stub)
{
    std::unique_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
    for (auto it = dbinderSentCallback.begin(); it != dbinderSentCallback.end(); it++) {
        if (it->second == stub) {
            dbinderSentCallback.erase(it);
            break;
        }
    }
}

sptr<DBinderCallbackStub> IPCProcessSkeleton::QueryDBinderCallbackStub(sptr<IRemoteObject> proxy)
{
    std::shared_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
    auto it = dbinderSentCallback.find(proxy);
    if (it != dbinderSentCallback.end()) {
        wptr<DBinderCallbackStub> cache = it->second;
        return cache.promote();
    }
    return nullptr;
}

sptr<IRemoteObject> IPCProcessSkeleton::QueryDBinderCallbackProxy(sptr<IRemoteObject> stub)
{
    std::shared_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
    for (auto it = dbinderSentCallback.begin(); it != dbinderSentCallback.end(); it++) {
        if (it->second.GetRefPtr() == stub.GetRefPtr() && it->second.promote() != nullptr) {
            return it->first;
        }
    }

    return nullptr;
}

#endif
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS

/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include <random>
#include <securec.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "check_instance_exit.h"
#include "ipc_debug.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "log_tags.h"
#include "process_skeleton.h"
#include "string_ex.h"
#include "sys_binder.h"

#ifndef CONFIG_IPC_SINGLE
#include "databus_socket_listener.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_PROC_SKELETON, "IPCProcessSkeleton" };
#ifndef CONFIG_IPC_SINGLE
static constexpr int32_t DETACH_PROXY_REF_COUNT = 2;
#endif

std::mutex IPCProcessSkeleton::procMutex_;
IPCProcessSkeleton *IPCProcessSkeleton::instance_ = nullptr;
IPCProcessSkeleton::DestroyInstance IPCProcessSkeleton::destroyInstance_;
std::atomic<bool> IPCProcessSkeleton::exitFlag_ = false;
static constexpr int32_t INT_MIDMAX = INT_MAX / 2;

IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
{
    if ((instance_ == nullptr) && !exitFlag_) {
        std::lock_guard<std::mutex> lockGuard(procMutex_);
        if ((instance_ == nullptr) && !exitFlag_) {
            IPCProcessSkeleton *temp = new (std::nothrow) IPCProcessSkeleton();
            if (temp == nullptr) {
                ZLOGE(LOG_LABEL, "create IPCProcessSkeleton object failed");
                return nullptr;
            }
            if (temp->SetMaxWorkThread(DEFAULT_WORK_THREAD_NUM)) {
                temp->SpawnThread(IPCWorkThread::SPAWN_ACTIVE);
#ifdef CONFIG_ACTV_BINDER
                temp->SpawnThread(IPCWorkThread::ACTV_ACTIVE);
#endif
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
    std::uniform_int_distribution<> range(1, DBINDER_HANDLE_COUNT * DBINDER_HANDLE_RANG);
    int temp = range(baseRand);
    randNum_ = static_cast<uint64_t>(temp);
#endif
}

std::string IPCProcessSkeleton::ConvertToSecureString(const std::string &str)
{
    size_t len = str.size();
    if (len <= ENCRYPT_LENGTH) {
        return "****";
    }
    return str.substr(0, ENCRYPT_LENGTH) + "****" + str.substr(len - ENCRYPT_LENGTH);
}

#ifndef CONFIG_IPC_SINGLE
void IPCProcessSkeleton::ClearDataResource()
{
    {
        std::unique_lock<std::shared_mutex> lockGuard(rawDataMutex_);
        rawData_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lockGuard(threadLockMutex_);
        threadLockInfo_.clear();
    }
    {
        std::lock_guard<std::mutex> lockGuard(findThreadMutex_);
        seqNumberToThread_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lockGuard(stubObjectsMutex_);
        stubObjects_.clear();
    }
    {
        std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
        proxyToSession_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lockGuard(databusSessionMutex_);
        dbinderSessionObjects_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
        noticeStub_.clear();
    }
    {
        std::lock_guard<std::mutex> lockGuard(idleDataMutex_);
        idleDataThreads_.clear();
    }
    {
        std::lock_guard<std::mutex> lockGuard(dataQueueMutex_);
        dataInfoQueue_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lockGuard(appAuthMutex_);
        appInfoToStubIndex_.clear();
        commAuth_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
        dbinderSentCallback_.clear();
    }
}
#endif

IPCProcessSkeleton::~IPCProcessSkeleton()
{
    ZLOGI(LOG_LABEL, "enter");
    std::lock_guard<std::mutex> lockGuard(procMutex_);
    exitFlag_ = true;
    delete threadPool_;
    threadPool_ = nullptr;

#ifndef CONFIG_IPC_SINGLE
    ClearDataResource();
    if (listenSocketId_ > 0) {
        DBinderSoftbusClient::GetInstance().Shutdown(listenSocketId_);
        listenSocketId_ = 0;
    }
#endif
}

sptr<IRemoteObject> IPCProcessSkeleton::GetRegistryObject()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
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

sptr<IRemoteObject> IPCProcessSkeleton::FindOrNewObject(int handle, const dbinder_negotiation_data *dbinderData)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    bool newFlag = false;
    sptr<IRemoteObject> result = GetProxyObject(handle, newFlag);
    if (result == nullptr) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        if (ProcessSkeleton::IsPrint(handle, lastErrHandle_, lastErrCnt_)) {
            ZLOGE(LOG_LABEL, "GetProxyObject failed, handle:%{public}d time:%{public}" PRIu64, handle, curTime);
        }
        return result;
    }
    sptr<IPCObjectProxy> proxy = reinterpret_cast<IPCObjectProxy *>(result.GetRefPtr());
    proxy->WaitForInit(dbinderData);
#ifndef CONFIG_IPC_SINGLE
    if (proxy->GetProto() == IRemoteObject::IF_PROT_ERROR) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LOG_LABEL, "init rpc proxy failed, handle:%{public}d %{public}u, time:%{public}" PRIu64, handle,
            ProcessSkeleton::ConvertAddr(result.GetRefPtr()), curTime);
        if (proxy->GetSptrRefCount() <= DETACH_PROXY_REF_COUNT) {
            DetachObject(result.GetRefPtr());
        }
        return nullptr;
    }
#endif
    ZLOGD(LOG_LABEL, "handle:%{public}d proto:%{public}d new:%{public}d", handle, proxy->GetProto(), newFlag);
    return result;
}

sptr<IRemoteObject> IPCProcessSkeleton::GetProxyObject(int handle, bool &newFlag)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    sptr<IRemoteObject> result = nullptr;
    std::u16string descriptor = MakeHandleDescriptor(handle);
    if (descriptor.length() == 0) {
        ZLOGE(LOG_LABEL, "make handle descriptor failed");
        return result;
    }

    auto current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "get process skeleton failed");
        return result;
    }

    if (!current->LockObjectMutex()) {
        ZLOGE(LOG_LABEL, "LockObjectMutex failed!");
        return result;
    }
    result = QueryObject(descriptor, false);
    if (result != nullptr) {
        current->UnlockObjectMutex();
        return result;
    }
    // Either this is a new handle or attemptIncStrong failed(strong refcount has been decreased to zero),
    // we need to create a new proxy and initialize it. Meanwhile, the old proxy is destroying concurrently.
    if (handle == REGISTRY_HANDLE) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
        if (invoker == nullptr) {
            ZLOGE(LOG_LABEL, "failed to get invoker");
            current->UnlockObjectMutex();
            return result;
        }
        if (!invoker->PingService(REGISTRY_HANDLE)) {
            current->UnlockObjectMutex();
            return result;
        }
    }
    // OnFirstStrongRef will be called.
    result = new (std::nothrow) IPCObjectProxy(handle, descriptor);
    if (result == nullptr) {
        ZLOGE(LOG_LABEL, "new IPCObjectProxy failed!");
        current->UnlockObjectMutex();
        return result;
    }
    if (!AttachObject(result.GetRefPtr(), false)) {
        ZLOGE(LOG_LABEL, "AttachObject failed!");
        current->UnlockObjectMutex();
        return nullptr;
    }
    newFlag = true;
    current->UnlockObjectMutex();
    return result;
}

bool IPCProcessSkeleton::SetRegistryObject(sptr<IRemoteObject> &object)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
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
    ZLOGI(LOG_LABEL, "set registry result:%{public}d", ret);
    return ret;
}

bool IPCProcessSkeleton::SetMaxWorkThread(int maxThreadNum)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (maxThreadNum <= 0 || maxThreadNum >= INT_MIDMAX) {
        ZLOGE(LOG_LABEL, "Set Invalid thread Number:%{public}d", maxThreadNum);
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

bool IPCProcessSkeleton::SpawnThread(int policy, int proto)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (threadPool_ != nullptr) {
        return threadPool_->SpawnThread(policy, proto);
    }

    /* can NOT reach here */
    return false;
}

bool IPCProcessSkeleton::OnThreadTerminated(const std::string &threadName)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (threadPool_ != nullptr) {
        return threadPool_->RemoveThread(threadName);
    }

    return true;
}

bool IPCProcessSkeleton::IsContainsObject(IRemoteObject *object)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (object == nullptr) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGD(LOG_LABEL, "object is null, time:%{public}" PRIu64, curTime);
        return false;
    }
    auto current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "get process skeleton failed");
        return false;
    }
    return current->IsContainsObject(object);
}

bool IPCProcessSkeleton::DetachObject(IRemoteObject *object)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "object is null");
        return false;
    }
    std::u16string descriptor = object->GetObjectDescriptor();
    if (descriptor.empty()) {
        return false;
    }
    auto current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "get process skeleton failed");
        return false;
    }
    return current->DetachObject(object, descriptor);
}

bool IPCProcessSkeleton::AttachObject(IRemoteObject *object, bool lockFlag)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "object is null");
        return false;
    }
    std::u16string descriptor = object->GetObjectDescriptor();

    auto current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "get process skeleton failed");
        return false;
    }
    return current->AttachObject(object, descriptor, lockFlag);
}

sptr<IRemoteObject> IPCProcessSkeleton::QueryObject(const std::u16string &descriptor, bool lockFlag)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    if (descriptor.length() == 0) {
        ZLOGE(LOG_LABEL, "enter descriptor is empty");
        return nullptr;
    }
    auto current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "get process skeleton failed");
        return nullptr;
    }
    return current->QueryObject(descriptor, lockFlag);
}

void IPCProcessSkeleton::BlockUntilThreadAvailable()
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    std::unique_lock<std::mutex> lock(mutex_);
    numWaitingForThreads_++;
    constexpr int maxIPCThreadNum = 10;
    if (numExecuting_ > maxIPCThreadNum) {
        ZLOGE(LOG_LABEL, "numExecuting_++ is %{public}d", numExecuting_);
    }
    while (numExecuting_ >= threadPool_->GetMaxThreadNum()) {
        cv_.wait(lock);
    }
    numWaitingForThreads_--;
}

void IPCProcessSkeleton::LockForNumExecuting()
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    if (getuid() != FOUNDATION_UID) {
        return;
    }
    std::lock_guard<std::mutex> lockGuard(mutex_);
    numExecuting_++;
}

void IPCProcessSkeleton::UnlockForNumExecuting()
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    if (getuid() != FOUNDATION_UID) {
        return;
    }
    std::lock_guard<std::mutex> lockGuard(mutex_);
    numExecuting_--;
    if (numWaitingForThreads_ > 0) {
        cv_.notify_all();
    }
}

bool IPCProcessSkeleton::SetIPCProxyLimit(uint64_t num, std::function<void (uint64_t num)> callback)
{
    auto current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "get process skeleton failed");
        return false;
    }
    return current->SetIPCProxyLimit(num, callback);
}

#ifndef CONFIG_IPC_SINGLE
sptr<IRemoteObject> IPCProcessSkeleton::GetSAMgrObject()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, "");
    std::lock_guard<std::mutex> lockGuard(databusProcMutex_);

    std::string pkgName = std::string(DBINDER_PKG_NAME) + "_" + std::to_string(getpid());
    std::string networkId;

    if (DBinderSoftbusClient::GetInstance().GetLocalNodeDeviceId(
        pkgName.c_str(), networkId) != SOFTBUS_CLIENT_SUCCESS) {
        ZLOGE(LOG_LABEL, "Get local node device id failed");
    }

    return networkId;
}

bool IPCProcessSkeleton::IsHandleMadeByUser(uint32_t handle)
{
    if (handle >= DBINDER_HANDLE_BASE && handle <= (DBINDER_HANDLE_BASE + DBINDER_HANDLE_COUNT)) {
        ZLOGD(LOG_LABEL, "handle:%{public}u is make by user, not kernel", handle);
        return true;
    }
    return false;
}

uint32_t IPCProcessSkeleton::GetDBinderIdleHandle(std::shared_ptr<DBinderSessionObject> session)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    uint32_t tempHandle = dBinderHandle_;
    int count = DBINDER_HANDLE_COUNT;
    bool insertResult = false;
    do {
        count--;
        tempHandle++;
        if (tempHandle > DBINDER_HANDLE_BASE + DBINDER_HANDLE_COUNT) {
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    std::shared_ptr<DBinderSessionObject> tmp = nullptr;
    auto it = proxyToSession_.find(handle);
    if (it != proxyToSession_.end() && it->second != nullptr && it->second->GetProxy() == proxy) {
        tmp = it->second;
        proxyToSession_.erase(it);
        ZLOGI(LOG_LABEL, "detach handle:%{public}u from SocketId:%{public}d"
            " service:%{public}s stubIndex:%{public}" PRIu64, handle,
            tmp->GetSocketId(), tmp->GetServiceName().c_str(),
            tmp->GetStubIndex());
    } else {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGW(LOG_LABEL, "detach handle: %{public}u, not found, time: %{public}" PRIu64, handle, curTime);
    }

    return tmp;
}

bool IPCProcessSkeleton::ProxyAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    auto result = proxyToSession_.insert(std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handle, object));
    ZLOGI(LOG_LABEL, "attach handle:%{public}u to socketId:%{public}d"
        " service:%{public}s stubIndex:%{public}" PRIu64 " result:%{public}d",
        handle, object->GetSocketId(), object->GetServiceName().c_str(),
        object->GetStubIndex(), result.second);
    return result.second;
}

std::shared_ptr<DBinderSessionObject> IPCProcessSkeleton::ProxyQueryDBinderSession(uint32_t handle)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    auto it = proxyToSession_.find(handle);
    if (it != proxyToSession_.end()) {
        return it->second;
    }
    return nullptr;
}

bool IPCProcessSkeleton::ProxyMoveDBinderSession(uint32_t handle, IPCObjectProxy *proxy)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    auto it = proxyToSession_.find(handle);
    if (it != proxyToSession_.end()) {
        if (it->second == nullptr) {
            ZLOGE(LOG_LABEL, "find object is null");
            return false;
        }
        ZLOGI(LOG_LABEL, "move proxy of handle:%{public}u old==new:%{public}d", handle,
            it->second->GetProxy() == proxy);
        // moves ownership to this new proxy, so old proxy should not detach this session and stubIndex
        // see QueryHandleByDatabusSession
        it->second->SetProxy(proxy);
        return true;
    }
    return false;
}

bool IPCProcessSkeleton::QueryProxyBySocketId(int32_t socketId, std::vector<uint32_t> &proxyHandle)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);
    for (auto it = proxyToSession_.begin(); it != proxyToSession_.end(); it++) {
        if (it->second == nullptr) {
            ZLOGE(LOG_LABEL, "find object is null");
            return false;
        }
        if (socketId == it->second->GetSocketId()) {
            proxyHandle.push_back(it->first);
        }
    }
    ZLOGD(LOG_LABEL, "query proxys of session handle:%{public}d size:%{public}zu", socketId, proxyHandle.size());
    return true;
}

uint32_t IPCProcessSkeleton::QueryHandleByDatabusSession(const std::string &name, const std::string &deviceId,
    uint64_t stubIndex)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);

    for (auto it = proxyToSession_.begin(); it != proxyToSession_.end(); it++) {
        if (it->second == nullptr) {
            ZLOGE(LOG_LABEL, "find object is null");
            return 0;
        }
        if ((it->second->GetStubIndex() == stubIndex) && (it->second->GetDeviceId().compare(deviceId) == 0) &&
            (it->second->GetServiceName().compare(name) == 0)) {
            ZLOGI(LOG_LABEL, "found handle:%{public}u of session, stubIndex:%{public}" PRIu64, it->first, stubIndex);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::lock_guard<std::recursive_mutex> lockGuard(proxyToSessionMutex_);

    for (auto it = proxyToSession_.begin(); it != proxyToSession_.end(); it++) {
        if (it->second == nullptr) {
            ZLOGE(LOG_LABEL, "find object is null");
            return nullptr;
        }
        if ((it->second->GetDeviceId().compare(deviceId) == 0) && (it->second->GetServiceName().compare(name) == 0)) {
            return it->second;
        }
    }

    return nullptr;
}

bool IPCProcessSkeleton::StubDetachDBinderSession(uint32_t handle, uint32_t &tokenId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(databusSessionMutex_);
    auto it = dbinderSessionObjects_.find(handle);
    if (it != dbinderSessionObjects_.end()) {
        if (it->second == nullptr) {
            ZLOGE(LOG_LABEL, "find object is null");
            return false;
        }
        tokenId = it->second->GetTokenId();
        ZLOGI(LOG_LABEL, "detach handle:%{public}u stubIndex:%{public}" PRIu64 " tokenId:%{public}u",
            handle, it->second->GetStubIndex(), tokenId);
        dbinderSessionObjects_.erase(it);
        return true;
    }
    return false;
}

bool IPCProcessSkeleton::StubAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(databusSessionMutex_);
    auto result =
        dbinderSessionObjects_.insert(std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handle, object));
    ZLOGI(LOG_LABEL, "attach handle:%{public}u stubIndex:%{public}" PRIu64 " tokenId:%{public}u result:%{public}u",
        handle, object->GetStubIndex(), object->GetTokenId(), result.second);
    return result.second;
}

std::shared_ptr<DBinderSessionObject> IPCProcessSkeleton::StubQueryDBinderSession(uint32_t handle)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::shared_lock<std::shared_mutex> lockGuard(databusSessionMutex_);
    auto it = dbinderSessionObjects_.find(handle);
    if (it != dbinderSessionObjects_.end()) {
        return it->second;
    }

    return nullptr;
}

bool IPCProcessSkeleton::DetachThreadLockInfo(const std::thread::id &threadId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(threadLockMutex_);

    return (threadLockInfo_.erase(threadId) > 0);
}

bool IPCProcessSkeleton::AttachThreadLockInfo(std::shared_ptr<SocketThreadLockInfo> object,
    const std::thread::id &threadId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(threadLockMutex_);
    auto result =
        threadLockInfo_.insert(std::pair<std::thread::id, std::shared_ptr<SocketThreadLockInfo>>(threadId, object));
    return result.second;
}

std::shared_ptr<SocketThreadLockInfo> IPCProcessSkeleton::QueryThreadLockInfo(const std::thread::id &threadId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::shared_lock<std::shared_mutex> lockGuard(threadLockMutex_);

    auto it = threadLockInfo_.find(threadId);
    if (it != threadLockInfo_.end()) {
        return it->second;
    }

    return nullptr;
}


bool IPCProcessSkeleton::AddDataThreadToIdle(const std::thread::id &threadId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::mutex> lockGuard(idleDataMutex_);

    idleDataThreads_.push_front(threadId);
    return true;
}

bool IPCProcessSkeleton::DeleteDataThreadFromIdle(const std::thread::id &threadId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, std::thread::id());
    std::lock_guard<std::mutex> lockGuard(idleDataMutex_);

    if (idleDataThreads_.size() == 0) {
        return std::thread::id();
    }

    std::thread::id threadId = idleDataThreads_.back();
    return threadId;
}

int IPCProcessSkeleton::GetSocketIdleThreadNum() const
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
    if (threadPool_ != nullptr) {
        return threadPool_->GetSocketIdleThreadNum();
    }

    return 0;
}

int IPCProcessSkeleton::GetSocketTotalThreadNum() const
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
    if (threadPool_ != nullptr) {
        return threadPool_->GetSocketTotalThreadNum();
    }
    return 0;
}

void IPCProcessSkeleton::AddDataInfoToThread(const std::thread::id &threadId,
    std::shared_ptr<ThreadProcessInfo> processInfo)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    std::lock_guard<std::mutex> lockGuard(dataQueueMutex_);

    (dataInfoQueue_[threadId]).push_back(processInfo);
}

std::shared_ptr<ThreadProcessInfo> IPCProcessSkeleton::PopDataInfoFromThread(const std::thread::id &threadId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
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
    CHECK_INSTANCE_EXIT(exitFlag_);
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
    CHECK_INSTANCE_EXIT(exitFlag_);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
    std::lock_guard<std::mutex> lockGuard(seqNumberMutex_);
    if (seqNumber_ == std::numeric_limits<uint64_t>::max()) {
        seqNumber_ = 0;
    }
    seqNumber_++;
    return seqNumber_;
}

std::shared_ptr<ThreadMessageInfo> IPCProcessSkeleton::QueryThreadBySeqNumber(uint64_t seqNumber)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::lock_guard<std::mutex> lockGuard(findThreadMutex_);

    auto it = seqNumberToThread_.find(seqNumber);
    if (it != seqNumberToThread_.end()) {
        return it->second;
    }

    return nullptr;
}

void IPCProcessSkeleton::EraseThreadBySeqNumber(uint64_t seqNumber)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    std::lock_guard<std::mutex> lockGuard(findThreadMutex_);
    seqNumberToThread_.erase(seqNumber);
}


bool IPCProcessSkeleton::AddThreadBySeqNumber(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::mutex> lockGuard(findThreadMutex_);

    auto result =
        seqNumberToThread_.insert(std::pair<uint64_t, std::shared_ptr<ThreadMessageInfo>>(seqNumber, messageInfo));

    return result.second;
}

void IPCProcessSkeleton::WakeUpThreadBySeqNumber(uint64_t seqNumber, uint32_t handle)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    std::shared_ptr<ThreadMessageInfo> messageInfo;

    messageInfo = QueryThreadBySeqNumber(seqNumber);
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "error! messageInfo is nullptr");
        return;
    }
    if (handle != messageInfo->socketId) {
        ZLOGE(LOG_LABEL, "handle is not equal, handle:%{public}d socketId:%{public}u",
            handle, messageInfo->socketId);
        return;
    }

    std::unique_lock<std::mutex> lock_unique(messageInfo->mutex);
    messageInfo->ready = true;
    messageInfo->condition.notify_one();
}

bool IPCProcessSkeleton::AddSendThreadInWait(uint64_t seqNumber, std::shared_ptr<ThreadMessageInfo> messageInfo,
    int userWaitTime)
{
    if (messageInfo == nullptr) {
        ZLOGE(LOG_LABEL, "messageInfo is nullptr");
        return false;
    }
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (!AddThreadBySeqNumber(seqNumber, messageInfo)) {
        ZLOGE(LOG_LABEL, "add seqNumber:%{public}" PRIu64 " failed", seqNumber);
        return false;
    }

    std::unique_lock<std::mutex> lock_unique(messageInfo->mutex);
    if (messageInfo->condition.wait_for(lock_unique, std::chrono::seconds(userWaitTime),
        [&messageInfo] { return messageInfo->ready; }) == false) {
        messageInfo->ready = false;
        ZLOGE(LOG_LABEL, "thread timeout, seqNumber:%{public}" PRIu64 " waittime:%{public}d", seqNumber, userWaitTime);
        return false;
    }
    messageInfo->ready = false;
    return true;
}

IRemoteObject *IPCProcessSkeleton::QueryStubByIndex(uint64_t stubIndex)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, 0);
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
    const std::string &deviceId, uint64_t stubIndex, int32_t listenFd)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);
    bool result = false;
    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        std::map<uint64_t, int32_t> &indexes = it->second;
        auto it2 = indexes.find(stubIndex);
        if (it2 != indexes.end() && it2->second == listenFd) {
            indexes.erase(it2);
            result = true;
        }
        if (indexes.empty()) {
            appInfoToStubIndex_.erase(it);
        }
    }
    ZLOGI(LOG_LABEL, "pid:%{public}u uid:%{public}u tokenId:%{public}u deviceId:%{public}s stubIndex:%{public}" PRIu64
        " listenFd:%{public}u result:%{public}d", pid, uid, tokenId, ConvertToSecureString(deviceId).c_str(),
        stubIndex, listenFd, result);
    return result;
}

std::list<uint64_t> IPCProcessSkeleton::DetachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, int32_t listenFd)
{
    std::list<uint64_t> indexes;
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, indexes);
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    uint32_t indexCnt = 0;
    bool appInfoErase = false;
    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        std::map<uint64_t, int32_t> &stubIndexes = it->second;
        for (auto it2 = stubIndexes.begin(); it2 != stubIndexes.end();) {
            if (it2->second == listenFd) {
                indexes.push_back(it2->first);
                it2 = stubIndexes.erase(it2);
                indexCnt++;
            } else {
                it2++;
            }
        }
        if (stubIndexes.empty()) {
            appInfoToStubIndex_.erase(it);
            appInfoErase = true;
        }
    }
    ZLOGI(LOG_LABEL, "pid:%{public}u uid:%{public}u tokenId:%{public}u deviceId:%{public}s listenFd:%{public}d"
        " indexCnt:%{public}u appInfoErase:%{public}d",
        pid, uid, tokenId, ConvertToSecureString(deviceId).c_str(), listenFd, indexCnt, appInfoErase);
    return indexes;
}

void IPCProcessSkeleton::DetachAppInfoToStubIndex(uint64_t stubIndex)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    for (auto it = appInfoToStubIndex_.begin(); it != appInfoToStubIndex_.end();) {
        if (it->second.erase(stubIndex) > 0) {
            ZLOGI(LOG_LABEL, "earse stubIndex:%{public}" PRIu64 " of appInfo:%{public}s",
                stubIndex, ConvertToSecureString(it->first).c_str());
        }
        if (it->second.size() == 0) {
            it = appInfoToStubIndex_.erase(it);
        } else {
            it++;
        }
    }
}

std::list<uint64_t> IPCProcessSkeleton::DetachAppInfoToStubIndex(int32_t listenFd)
{
    std::list<uint64_t> indexes;
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, indexes);
    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);
    uint32_t indexCnt = 0;
    bool appInfoErase = false;
    for (auto it = appInfoToStubIndex_.begin(); it != appInfoToStubIndex_.end();) {
        std::map<uint64_t, int32_t> &mapItem = it->second;
        for (auto it2 = mapItem.begin(); it2 != mapItem.end();) {
            if (it2->second == listenFd) {
                indexes.push_back(it2->first);
                it2 = mapItem.erase(it2);
                indexCnt++;
            } else {
                it2++;
            }
        }
        if (mapItem.empty()) {
            it = appInfoToStubIndex_.erase(it);
            appInfoErase = true;
        } else {
            it++;
        }
    }
    ZLOGI(LOG_LABEL, "listenFd:%{public}d indexCnt:%{public}u appInfoErase:%{public}d",
        listenFd, indexCnt, appInfoErase);
    return indexes;
}

bool IPCProcessSkeleton::AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, uint64_t stubIndex, int32_t listenFd)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    ZLOGI(LOG_LABEL, "pid:%{public}u uid:%{public}u tokenId:%{public}u deviceId:%{public}s stubIndex:%{public}" PRIu64
        " listenFd:%{public}d", pid, uid, tokenId, ConvertToSecureString(deviceId).c_str(), stubIndex, listenFd);
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        auto result = it->second.insert_or_assign(stubIndex, listenFd);
        return result.second;
    }

    std::map<uint64_t, int32_t> mapItem { { stubIndex, listenFd } };
    auto result = appInfoToStubIndex_.insert(std::pair<std::string, std::map<uint64_t, int32_t>>(appInfo, mapItem));
    return result.second;
}

bool IPCProcessSkeleton::AttachAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, int32_t listenFd)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    ZLOGI(LOG_LABEL, "pid:%{public}u uid:%{public}u tokenId:%{public}u deviceId:%{public}s listenFd:%{public}d",
        pid, uid, tokenId, ConvertToSecureString(deviceId).c_str(), listenFd);
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        std::map<uint64_t, int32_t> &indexes = it->second;
        // OnSessionOpen update listenFd
        for (auto it2 = indexes.begin(); it2 != indexes.end(); it2++) {
            it2->second = listenFd;
        }
    }
    return true;
}

bool IPCProcessSkeleton::QueryAppInfoToStubIndex(uint32_t pid, uint32_t uid, uint32_t tokenId,
    const std::string &deviceId, uint64_t stubIndex, int32_t listenFd)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::string appInfo = deviceId + UIntToString(pid) + UIntToString(uid) + UIntToString(tokenId);

    std::shared_lock<std::shared_mutex> lockGuard(appInfoToIndexMutex_);

    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        auto it2 = it->second.find(stubIndex);
        // listenFd may be marked as 0
        if (it2 != it->second.end() && (it2->second == 0 || it2->second == listenFd)) {
            ZLOGD(LOG_LABEL, "found appInfo:%{public}s stubIndex:%{public}" PRIu64,
                ConvertToSecureString(appInfo).c_str(), stubIndex);
            return true;
        }
    }

    return false;
}

bool IPCProcessSkeleton::AttachCallbackStub(IPCObjectProxy *ipcProxy, sptr<IPCObjectStub> callbackStub)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    auto result = noticeStub_.insert(std::pair<IPCObjectProxy *, sptr<IPCObjectStub>>(ipcProxy, callbackStub));
    return result.second;
}

sptr<IPCObjectStub> IPCProcessSkeleton::DetachCallbackStub(IPCObjectProxy *ipcProxy)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::shared_lock<std::shared_mutex> lockGuard(callbackStubMutex_);
    auto it = noticeStub_.find(ipcProxy);
    if (it != noticeStub_.end()) {
        return it->second;
    }

    return nullptr;
}

sptr<IPCObjectProxy> IPCProcessSkeleton::QueryCallbackProxy(IPCObjectStub *callbackStub)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, "");
    std::lock_guard<std::mutex> lockGuard(sessionNameMutex_);

    return sessionName_;
}

bool IPCProcessSkeleton::CreateSoftbusServer(const std::string &name)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (name.empty()) {
        ZLOGE(LOG_LABEL, "server name is empty");
        return false;
    }
    std::shared_ptr<DatabusSocketListener> listener =
        DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        ZLOGE(LOG_LABEL, "fail to get socket listener");
        return false;
    }

    int32_t socketId = listener->StartServerListener(name);
    if (socketId <= 0) {
        ZLOGE(LOG_LABEL, "fail to start server listener");
        return false;
    }
    listenSocketId_ = socketId;
    if (name != sessionName_) {
        SpawnThread(IPCWorkThread::PROCESS_ACTIVE, IRemoteObject::IF_PROT_DATABUS);
    }
    sessionName_ = name;
    return true;
}

bool IPCProcessSkeleton::AttachRawData(int32_t socketId, std::shared_ptr<InvokerRawData> rawData)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(rawDataMutex_);
    /* always discard the old one if exists */
    rawData_.erase(socketId);
    auto result = rawData_.insert(std::pair<uint32_t, std::shared_ptr<InvokerRawData>>(socketId, rawData));
    return result.second;
}

bool IPCProcessSkeleton::DetachRawData(int32_t socketId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(rawDataMutex_);
    return (rawData_.erase(socketId) > 0);
}

std::shared_ptr<InvokerRawData> IPCProcessSkeleton::QueryRawData(int32_t socketId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::shared_lock<std::shared_mutex> lockGuard(rawDataMutex_);
    auto it = rawData_.find(socketId);
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
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    auto check = [&stub, &pid, &uid, &tokenId, &deviceId, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(stub, pid, uid, tokenId, deviceId, auth);
    };
    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    auto it = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (it != commAuth_.end()) {
        return false;
    }

    std::shared_ptr<CommAuthInfo> authObject = std::make_shared<CommAuthInfo>(stub, pid, uid, tokenId, deviceId);
    if (authObject == nullptr) {
        ZLOGE(LOG_LABEL, "make_share CommonAuthInfo fail, device:%{public}s pid:%{public}d uid:%{public}d",
            IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(), pid, uid);
        return false;
    }
    commAuth_.push_front(authObject);
    return true;
}

bool IPCProcessSkeleton::DetachCommAuthInfo(IRemoteObject *stub, int pid, int uid, uint32_t tokenId,
    const std::string &deviceId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
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

void IPCProcessSkeleton::DetachCommAuthInfoBySocketId(int32_t socketId)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    auto check = [&socketId](const std::shared_ptr<CommAuthInfo> &auth) {
        ZLOGI(LOG_LABEL, "socketId:%{public}d", socketId);
        return (auth != nullptr) && (auth->GetRemoteSocketId() == socketId);
    };

    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    commAuth_.erase(std::remove_if(commAuth_.begin(), commAuth_.end(), check), commAuth_.end());
}

bool IPCProcessSkeleton::QueryCommAuthInfo(int pid, int uid, uint32_t &tokenId, const std::string &deviceId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
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
    ZLOGE(LOG_LABEL, "NOT exist, deviceId:%{public}s pid:%{public}u uid:%{public}u",
        IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str(), pid, uid);
    tokenId = 0;
    return false;
}

void IPCProcessSkeleton::UpdateCommAuthSocketInfo(int pid, int uid, uint32_t &tokenId, const std::string &deviceId,
    int32_t socketId)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    auto check = [&pid, &uid, &deviceId, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(pid, uid, deviceId, auth);
    };
    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    auto it = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (it != commAuth_.end()) {
        (*it)->SetRemoteSocketId(socketId);
    }
}

bool IPCProcessSkeleton::AttachOrUpdateAppAuthInfo(const AppAuthInfo &appAuthInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    ZLOGI(LOG_LABEL, "pid:%{public}u uid:%{public}u tokenId:%{public}u deviceId:%{public}s stubIndex:%{public}" PRIu64
        " socketId:%{public}d", appAuthInfo.pid, appAuthInfo.uid, appAuthInfo.tokenId,
        ConvertToSecureString(appAuthInfo.deviceId).c_str(), appAuthInfo.stubIndex, appAuthInfo.socketId);

    std::unique_lock<std::shared_mutex> lockGuard(appAuthMutex_);
    std::string appInfo = appAuthInfo.deviceId + UIntToString(appAuthInfo.pid) +
        UIntToString(appAuthInfo.uid) + UIntToString(appAuthInfo.tokenId);
    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        if (appAuthInfo.stubIndex != 0) {
            it->second.insert_or_assign(appAuthInfo.stubIndex, appAuthInfo.socketId);
        } else if (appAuthInfo.socketId != 0) {
            for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++) {
                it2->second = appAuthInfo.socketId;
            }
            ZLOGW(LOG_LABEL, "app info already existed, update socketId:%{public}d", appAuthInfo.socketId);
        } else {
            ZLOGE(LOG_LABEL, "stubindex and socketid are both invalid");
        }
    } else {
        appInfoToStubIndex_[appInfo].insert(std::make_pair(appAuthInfo.stubIndex, appAuthInfo.socketId));
    }

    if (appAuthInfo.stub == nullptr) {
        return false;
    }

    auto check = [&appAuthInfo, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(appAuthInfo.stub, appAuthInfo.pid, appAuthInfo.uid,
            appAuthInfo.tokenId, appAuthInfo.deviceId, auth);
    };
    auto iter = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if ((iter != commAuth_.end()) && (appAuthInfo.socketId != 0)) {
        (*iter)->SetRemoteSocketId(appAuthInfo.socketId);
        ZLOGW(LOG_LABEL, "comm auth info already existed, update socketId:%{public}d", appAuthInfo.socketId);
        return false;
    }

    std::shared_ptr<CommAuthInfo> authObject = std::make_shared<CommAuthInfo>(
        appAuthInfo.stub, appAuthInfo.pid, appAuthInfo.uid,
        appAuthInfo.tokenId, appAuthInfo.deviceId, appAuthInfo.socketId);
    commAuth_.push_front(authObject);
    return true;
}

bool IPCProcessSkeleton::DetachAppAuthInfo(const AppAuthInfo &appAuthInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::string appInfo = appAuthInfo.deviceId + UIntToString(appAuthInfo.pid) +
        UIntToString(appAuthInfo.uid) + UIntToString(appAuthInfo.tokenId);

    std::unique_lock<std::shared_mutex> lockGuard(appAuthMutex_);
    bool result = false;
    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        std::map<uint64_t, int32_t> &indexes = it->second;
        auto it2 = indexes.find(appAuthInfo.stubIndex);
        if (it2 != indexes.end() && it2->second == appAuthInfo.socketId) {
            indexes.erase(it2);
            result = true;
        }
        if (indexes.empty()) {
            appInfoToStubIndex_.erase(it);
        }
    }
    if (!result) {
        return false;
    }

    auto check = [&appAuthInfo, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(appAuthInfo.stub, appAuthInfo.pid, appAuthInfo.uid,
            appAuthInfo.tokenId, appAuthInfo.deviceId, auth);
    };

    auto iter = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (iter != commAuth_.end()) {
        commAuth_.erase(iter);
    }
    ZLOGI(LOG_LABEL, "pid:%{public}u uid:%{public}u tokenId:%{public}u deviceId:%{public}s"
        " stubIndex:%{public}" PRIu64 " socketId:%{public}u result:%{public}d",
        appAuthInfo.pid, appAuthInfo.uid, appAuthInfo.tokenId, ConvertToSecureString(appAuthInfo.deviceId).c_str(),
        appAuthInfo.stubIndex, appAuthInfo.socketId, result);

    return true;
}

void IPCProcessSkeleton::DetachAppAuthInfoByStub(IRemoteObject *stub, uint64_t stubIndex)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    auto check = [&stub](const std::shared_ptr<CommAuthInfo> &auth) {
        return (auth != nullptr) && (auth->GetStubObject() == stub);
    };
    std::unique_lock<std::shared_mutex> lockGuard(appAuthMutex_);
    commAuth_.erase(std::remove_if(commAuth_.begin(), commAuth_.end(), check), commAuth_.end());

    for (auto it = appInfoToStubIndex_.begin(); it != appInfoToStubIndex_.end();) {
        if (it->second.erase(stubIndex) > 0) {
            ZLOGI(LOG_LABEL, "earse stubIndex:%{public}" PRIu64 " of appInfo:%{public}s",
                stubIndex, ConvertToSecureString(it->first).c_str());
        }
        if (it->second.size() == 0) {
            it = appInfoToStubIndex_.erase(it);
        } else {
            ++it;
        }
    }
}

std::list<uint64_t> IPCProcessSkeleton::DetachAppAuthInfoBySocketId(int32_t socketId)
{
    std::list<uint64_t> indexes;
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, indexes);
    auto check = [&socketId](const std::shared_ptr<CommAuthInfo> &auth) {
        return (auth != nullptr) && (auth->GetRemoteSocketId() == socketId);
    };

    std::unique_lock<std::shared_mutex> lockGuard(appAuthMutex_);
    commAuth_.erase(std::remove_if(commAuth_.begin(), commAuth_.end(), check), commAuth_.end());

    uint32_t indexCnt = 0;
    bool appInfoErase = false;
    for (auto it = appInfoToStubIndex_.begin(); it != appInfoToStubIndex_.end();) {
        std::map<uint64_t, int32_t> &mapItem = it->second;
        for (auto it2 = mapItem.begin(); it2 != mapItem.end();) {
            if (it2->second == socketId) {
                indexes.push_back(it2->first);
                it2 = mapItem.erase(it2);
                indexCnt++;
            } else {
                ++it2;
            }
        }
        if (mapItem.empty()) {
            it = appInfoToStubIndex_.erase(it);
            appInfoErase = true;
        } else {
            ++it;
        }
    }
    ZLOGI(LOG_LABEL, "socketId:%{public}d, indexCnt:%{public}u appInfoErase:%{public}d",
        socketId, indexCnt, appInfoErase);
    return indexes;
}

bool IPCProcessSkeleton::QueryCommAuthInfo(AppAuthInfo &appAuthInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    auto check = [&appAuthInfo, this](const std::shared_ptr<CommAuthInfo> &auth) {
        return IsSameRemoteObject(appAuthInfo.pid, appAuthInfo.uid, appAuthInfo.deviceId, auth);
    };

    std::shared_lock<std::shared_mutex> lockGuard(appAuthMutex_);
    auto it = std::find_if(commAuth_.begin(), commAuth_.end(), check);
    if (it != commAuth_.end()) {
        if ((*it) == nullptr) {
            ZLOGE(LOG_LABEL, "CommAuthInfo is nullptr");
            return false;
        }
        appAuthInfo.tokenId = (*it)->GetRemoteTokenId();
        return true;
    }
    ZLOGE(LOG_LABEL, "NOT exist, deviceId:%{public}s pid:%{public}u uid:%{public}u",
        IPCProcessSkeleton::ConvertToSecureString(appAuthInfo.deviceId).c_str(), appAuthInfo.pid, appAuthInfo.uid);
    return false;
}

bool IPCProcessSkeleton::QueryAppInfoToStubIndex(const AppAuthInfo &appAuthInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::string appInfo = appAuthInfo.deviceId + UIntToString(appAuthInfo.pid) +
        UIntToString(appAuthInfo.uid) + UIntToString(appAuthInfo.tokenId);

    std::shared_lock<std::shared_mutex> lockGuard(appAuthMutex_);
    auto it = appInfoToStubIndex_.find(appInfo);
    if (it != appInfoToStubIndex_.end()) {
        auto it2 = it->second.find(appAuthInfo.stubIndex);
        // listenFd may be marked as 0
        if (it2 != it->second.end() && (it2->second == 0 || it2->second == appAuthInfo.socketId)) {
            ZLOGD(LOG_LABEL, "found appInfo:%{public}s stubIndex:%{public}" PRIu64,
                ConvertToSecureString(appInfo).c_str(), appAuthInfo.stubIndex);
            return true;
        }
    }

    return false;
}

void IPCProcessSkeleton::DetachCommAuthInfoByStub(IRemoteObject *stub)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    auto check = [&stub](const std::shared_ptr<CommAuthInfo> &auth) {
        return (auth != nullptr) && (auth->GetStubObject() == stub);
    };
    std::unique_lock<std::shared_mutex> lockGuard(commAuthMutex_);
    commAuth_.erase(std::remove_if(commAuth_.begin(), commAuth_.end(), check), commAuth_.end());
}

bool IPCProcessSkeleton::AttachDBinderCallbackStub(sptr<IRemoteObject> proxy, sptr<DBinderCallbackStub> stub)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
    auto result = dbinderSentCallback_.insert(std::pair<sptr<IRemoteObject>, wptr<DBinderCallbackStub>>(proxy, stub));
    return result.second;
}

bool IPCProcessSkeleton::DetachDBinderCallbackStubByProxy(sptr<IRemoteObject> proxy)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);

    return (dbinderSentCallback_.erase(proxy) > 0);
}

void IPCProcessSkeleton::DetachDBinderCallbackStub(DBinderCallbackStub *stub)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    std::unique_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
    for (auto it = dbinderSentCallback_.begin(); it != dbinderSentCallback_.end(); it++) {
        if (it->second == stub) {
            dbinderSentCallback_.erase(it);
            break;
        }
    }
}

sptr<DBinderCallbackStub> IPCProcessSkeleton::QueryDBinderCallbackStub(sptr<IRemoteObject> proxy)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::shared_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
    auto it = dbinderSentCallback_.find(proxy);
    if (it != dbinderSentCallback_.end()) {
        wptr<DBinderCallbackStub> cache = it->second;
        return cache.promote();
    }
    return nullptr;
}

sptr<IRemoteObject> IPCProcessSkeleton::QueryDBinderCallbackProxy(sptr<IRemoteObject> stub)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::shared_lock<std::shared_mutex> lockGuard(dbinderSentMutex_);
    for (auto it = dbinderSentCallback_.begin(); it != dbinderSentCallback_.end(); it++) {
        if (it->second.GetRefPtr() == stub.GetRefPtr() && it->second.promote() != nullptr) {
            return it->first;
        }
    }

    return nullptr;
}
#endif

IPCProcessSkeleton::DestroyInstance::~DestroyInstance()
{
    if (instance_ == nullptr) {
        return;
    }

    // notify other threads to stop running
    auto process = ProcessSkeleton::GetInstance();
    if (process != nullptr) {
        process->NotifyChildThreadStop();
    }

    delete instance_;
    instance_ = nullptr;
}
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS

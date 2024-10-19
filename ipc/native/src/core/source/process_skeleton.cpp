/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "process_skeleton.h"

#include <cinttypes>
#include <unistd.h>

#include "binder_connector.h"
#include "check_instance_exit.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "securec.h"
#include "string_ex.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "ProcessSkeleton" };
static constexpr int PRINT_ERR_CNT = 100;

#ifdef __aarch64__
static constexpr uint32_t IPC_OBJECT_MASK = 0xffffffff;
#else
static constexpr uint32_t IPC_OBJECT_MASK = 0xffffff;
#endif

ProcessSkeleton* ProcessSkeleton::instance_ = nullptr;
std::mutex ProcessSkeleton::mutex_;
ProcessSkeleton::DestroyInstance ProcessSkeleton::destroyInstance_;
std::atomic<bool> ProcessSkeleton::exitFlag_ = false;

ProcessSkeleton* ProcessSkeleton::GetInstance()
{
    if ((instance_ == nullptr) && !exitFlag_) {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        if ((instance_ == nullptr) && !exitFlag_) {
            instance_ = new (std::nothrow) ProcessSkeleton();
            if (instance_ == nullptr) {
                ZLOGE(LOG_LABEL, "create ProcessSkeleton object failed");
                return nullptr;
            }
        }
    }
    return instance_;
}

ProcessSkeleton::~ProcessSkeleton()
{
    ZLOGI(LOG_LABEL, "enter");
    std::lock_guard<std::mutex> lockGuard(mutex_);
    exitFlag_ = true;
    {
        std::unique_lock<std::shared_mutex> objLock(objMutex_);
        objects_.clear();
        isContainStub_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> validObjLock(validObjectMutex_);
        validObjectRecord_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> invokerProcLock(invokerProcMutex_);
        invokerProcInfo_.clear();
    }
}

sptr<IRemoteObject> ProcessSkeleton::GetRegistryObject()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return registryObject_;
}

void ProcessSkeleton::SetRegistryObject(sptr<IRemoteObject> &object)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    std::lock_guard<std::mutex> lockGuard(mutex_);
    registryObject_ = object;
}

void ProcessSkeleton::SetSamgrFlag(bool flag)
{
    isSamgr_ = flag;
}

bool ProcessSkeleton::GetSamgrFlag()
{
    return isSamgr_;
}

bool ProcessSkeleton::IsContainsObject(IRemoteObject *object)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (object == nullptr) {
        return false;
    }
    // check whether it is a valid IPCObjectStub object.
    std::shared_lock<std::shared_mutex> lockGuard(objMutex_);
    auto it = isContainStub_.find(object);
    if (it != isContainStub_.end()) {
        return it->second;
    }

    return false;
}

bool ProcessSkeleton::DetachObject(IRemoteObject *object, const std::u16string &descriptor)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(objMutex_);
    (void)isContainStub_.erase(object);

    // This handle may have already been replaced with a new IPCObjectProxy,
    // if someone failed the AttemptIncStrong.
    auto iterator = objects_.find(descriptor);
    if (iterator == objects_.end()) {
        ZLOGD(LOG_LABEL, "not found, desc:%{public}s maybe has been updated",
            ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str());
        return false;
    }

    if (object->IsProxyObject()) {
        proxyObjectCountNum_.fetch_sub(1, std::memory_order_relaxed);
    }

    if (iterator->second.GetRefPtr() != object) {
        ZLOGI(LOG_LABEL, "can not erase it because addr if different, "
            "desc:%{public}s, recorded object:%{public}u, detach object:%{public}u",
            ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str(), ConvertAddr(iterator->second.GetRefPtr()),
            ConvertAddr(object));
        return true;
    }

    objects_.erase(iterator);
    ZLOGD(LOG_LABEL, "erase desc:%{public}s", ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str());
    return true;
}

bool ProcessSkeleton::AttachObject(IRemoteObject *object, const std::u16string &descriptor, bool lockFlag)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(objMutex_, std::defer_lock);
    if (lockFlag) {
        lockGuard.lock();
    }
    (void)isContainStub_.insert(std::pair<IRemoteObject *, bool>(object, true));

    if (descriptor.empty()) {
        ZLOGE(LOG_LABEL, "descriptor is null %{public}u", ConvertAddr(object));
        return false;
    }
    // If attemptIncStrong failed, old proxy might still exist, replace it with the new proxy.
    wptr<IRemoteObject> wp = object;

    if (object->IsProxyObject()) {
        uint64_t proxyObjectCountNum = proxyObjectCountNum_.fetch_add(1, std::memory_order_relaxed) + 1;
        if (ipcProxyCallback_ != nullptr && ipcProxyLimitNum_ > 0 && proxyObjectCountNum > ipcProxyLimitNum_) {
                ZLOGW(LOG_LABEL, "ipc proxy num:%{public}" PRIu64 " exceeds limit:%{public}" PRIu64,
                      proxyObjectCountNum, ipcProxyLimitNum_);
                ipcProxyCallback_(proxyObjectCountNum);
        }
    }
    auto result = objects_.insert_or_assign(descriptor, wp);
    ZLOGD(LOG_LABEL, "attach %{public}u desc:%{public}s type:%{public}s",
        ConvertAddr(object), ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str(), result.second ? "insert" : "assign");
    return true;
}

sptr<IRemoteObject> ProcessSkeleton::QueryObject(const std::u16string &descriptor, bool lockFlag)
{
    sptr<IRemoteObject> result = nullptr;
    if (descriptor.empty()) {
        ZLOGE(LOG_LABEL, "descriptor is null");
        return result;
    }
    IRemoteObject *remoteObject = nullptr;
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    {
        std::shared_lock<std::shared_mutex> lockGuard(objMutex_, std::defer_lock);
        ZLOGD(LOG_LABEL, "The value of lockflag is:%{public}d", lockFlag);
        if (lockFlag) {
            lockGuard.lock();
        }
        auto it = objects_.find(descriptor);
        if (it != objects_.end()) {
            // Life-time of IPCObjectProxy is extended to WEAK
            // now it's weak reference counted, so it's safe to get raw pointer
            remoteObject = it->second.GetRefPtr();
        }
    }

    if (remoteObject == nullptr) {
        ZLOGD(LOG_LABEL, "not found object, desc:%{public}s", ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str());
        return result;
    }
    std::u16string desc;
    if (!IsValidObject(remoteObject, desc)) {
        ZLOGD(LOG_LABEL, "object %{public}u is inValid", ConvertAddr(remoteObject));
        return result;
    }

    if (!remoteObject->AttemptIncStrong(this)) {
        ZLOGD(LOG_LABEL, "object %{public}u AttemptIncStrong failed", ConvertAddr(remoteObject));
        return result;
    }

    result = remoteObject;
    result->CheckIsAttemptAcquireSet(this);

    return result;
}

bool ProcessSkeleton::LockObjectMutex()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    objMutex_.lock();
    return true;
}

bool ProcessSkeleton::UnlockObjectMutex()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    objMutex_.unlock();
    return true;
}

bool ProcessSkeleton::AttachValidObject(IRemoteObject *object, const std::u16string &desc)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(validObjectMutex_);
    auto result = validObjectRecord_.insert_or_assign(object, desc);
    ZLOGD(LOG_LABEL, "%{public}u descriptor:%{public}s", ConvertAddr(object),
        ConvertToSecureDesc(Str16ToStr8(desc)).c_str());
    return result.second;
}

bool ProcessSkeleton::DetachValidObject(IRemoteObject *object)
{
    bool ret = false;
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(validObjectMutex_);
    auto it = validObjectRecord_.find(object);
    if (it != validObjectRecord_.end()) {
        ZLOGD(LOG_LABEL, "erase %{public}u ", ConvertAddr(object));
        validObjectRecord_.erase(it);
        ret = true;
    }
    return ret;
}

bool ProcessSkeleton::IsValidObject(IRemoteObject *object, std::u16string &desc)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    if (object == nullptr) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lockGuard(validObjectMutex_);
    auto it = validObjectRecord_.find(object);
    if (it != validObjectRecord_.end()) {
        desc = it->second;
        ZLOGD(LOG_LABEL, "%{public}u descriptor:%{public}s", ConvertAddr(object),
            ConvertToSecureDesc(Str16ToStr8(desc)).c_str());
        return true;
    }
    return false;
}

bool ProcessSkeleton::AttachInvokerProcInfo(bool isLocal, InvokerProcInfo &invokeInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(invokerProcMutex_);
    std::string key = std::to_string(gettid()) + "_" + std::to_string(isLocal);
    auto result = invokerProcInfo_.insert_or_assign(key, invokeInfo);
    auto &info = result.first->second;
    ZLOGD(LOG_LABEL, "%{public}u, %{public}u %{public}u %{public}u %{public}" PRIu64 " %{public}" PRIu64,
        info.invoker, info.pid, info.realPid, info.uid, info.tokenId, info.firstTokenId);
    return result.second;
}

bool ProcessSkeleton::QueryInvokerProcInfo(bool isLocal, InvokerProcInfo &invokeInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::shared_lock<std::shared_mutex> lockGuard(invokerProcMutex_);
    std::string key = std::to_string(gettid()) + "_" + std::to_string(isLocal);
    auto it = invokerProcInfo_.find(key);
    if (it == invokerProcInfo_.end()) {
        return false;
    }
    invokeInfo = it->second;
    ZLOGD(LOG_LABEL, "%{public}u, %{public}u %{public}u %{public}u %{public}" PRIu64 " %{public}" PRIu64,
        invokeInfo.invoker, invokeInfo.pid, invokeInfo.realPid, invokeInfo.uid, invokeInfo.tokenId,
        invokeInfo.firstTokenId);
    return true;
}

bool ProcessSkeleton::DetachInvokerProcInfo(bool isLocal)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(invokerProcMutex_);
    std::string key = std::to_string(gettid()) + "_" + std::to_string(isLocal);
    auto it = invokerProcInfo_.find(key);
    if (it != invokerProcInfo_.end()) {
        auto &invokeInfo = it->second;
        ZLOGD(LOG_LABEL, "%{public}u, %{public}u %{public}u %{public}u %{public}" PRIu64 " %{public}" PRIu64,
            invokeInfo.invoker, invokeInfo.pid, invokeInfo.realPid, invokeInfo.uid, invokeInfo.tokenId,
            invokeInfo.firstTokenId);
        invokerProcInfo_.erase(it);
        return true;
    }
    return false;
}

bool ProcessSkeleton::IsPrint(int err, std::atomic<int> &lastErr, std::atomic<int> &lastErrCnt)
{
    bool isPrint = false;
    if (err == lastErr) {
        if (lastErrCnt >= INT_MAX) {
            lastErrCnt = 0;
        }
        if (++lastErrCnt % PRINT_ERR_CNT == 0) {
            isPrint = true;
        }
    } else {
        isPrint = true;
        lastErrCnt = 0;
        lastErr = err;
    }
    return isPrint;
}

std::string ProcessSkeleton::ConvertToSecureDesc(const std::string &str)
{
    auto pos = str.find_last_of(".");
    if (pos != std::string::npos) {
        return "*" + str.substr(pos);
    }
    return str;
}

bool ProcessSkeleton::SetIPCProxyLimit(uint64_t num, std::function<void (uint64_t num)> callback)
{
    ipcProxyLimitNum_ = num;
    ipcProxyCallback_ = callback;
    return true;
}

uint32_t ProcessSkeleton::ConvertAddr(const void *ptr)
{
    if (ptr == nullptr) {
        ZLOGE(LOG_LABEL, "ptr is null");
        return 0;
    }
    return static_cast<uint32_t>((reinterpret_cast<uintptr_t>(ptr)) & IPC_OBJECT_MASK);
}

bool ProcessSkeleton::FlattenDBinderData(Parcel &parcel, const dbinder_negotiation_data *&dbinderData)
{
    size_t start = parcel.GetWritePosition();
    binder_buffer_object obj;
    obj.hdr.type = BINDER_TYPE_PTR;
    obj.flags = BINDER_BUFFER_FLAG_HAS_DBINDER;
    obj.buffer = reinterpret_cast<binder_uintptr_t>(dbinderData);
    obj.length = sizeof(dbinder_negotiation_data);
    if (!parcel.WriteBuffer(&obj, sizeof(binder_buffer_object))) {
        ZLOGE(LOG_LABEL, "WriteBuffer fail");
        return false;
    }
    size_t stop = parcel.GetWritePosition();
    ZLOGD(LOG_LABEL, "serialization:%{public}zu sizeof:%{public}zu", stop - start, sizeof(binder_buffer_object));
    return true;
}

bool ProcessSkeleton::UnFlattenDBinderData(Parcel &parcel, dbinder_negotiation_data *&dbinderData)
{
    auto *buf = parcel.ReadBuffer(sizeof(binder_buffer_object), false);
    if (buf == nullptr) {
        return false;
    }
    auto obj = reinterpret_cast<const binder_buffer_object *>(buf);
    auto ret = memcpy_s(dbinderData, sizeof(dbinder_negotiation_data),
        reinterpret_cast<const void *>(obj->buffer), obj->length);
    return (ret == EOK);
}

bool ProcessSkeleton::GetSubStr(const std::string &str, std::string &substr, size_t offset, size_t length)
{
    if (str.empty() || str.length() < offset + length) {
        ZLOGE(LOG_LABEL, "strLen:%{public}zu, offset:%{public}zu, subLen:%{public}zu", str.length(), offset, length);
        return false;
    }
    substr = str.substr(offset, length);
    return true;
}

bool ProcessSkeleton::IsNumStr(const std::string &str)
{
    if (str.empty()) {
        return false;
    }
    return std::all_of(str.begin(), str.end(), ::isdigit);
}

bool ProcessSkeleton::GetThreadStopFlag()
{
    return stopThreadFlag_.load();
}

void ProcessSkeleton::IncreaseThreadCount()
{
    std::unique_lock<std::mutex> lockGuard(threadCountMutex_);
    runningChildThreadNum_.fetch_add(1);
}

void ProcessSkeleton::DecreaseThreadCount()
{
    std::unique_lock<std::mutex> lockGuard(threadCountMutex_);
    if (runningChildThreadNum_.load() > 0) {
        runningChildThreadNum_.fetch_sub(1);

        if (runningChildThreadNum_.load() == 0) {
            threadCountCon_.notify_one();
        }
    }
}

void ProcessSkeleton::NotifyChildThreadStop()
{
    // set child thread exit flag
    stopThreadFlag_.store(true);
    // after closeing fd, child threads will be not block in the 'WriteBinder' function
    BinderConnector *connector = BinderConnector::GetInstance();
    if (connector != nullptr) {
        connector->CloseDriverFd();
    }
    ZLOGI(LOG_LABEL, "start waiting for child thread to exit, child thread num:%{public}zu",
        runningChildThreadNum_.load());
    std::unique_lock<std::mutex> lockGuard(threadCountMutex_);
    threadCountCon_.wait_for(lockGuard,
        std::chrono::seconds(MAIN_THREAD_MAX_WAIT_TIME),
        [&threadNum = this->runningChildThreadNum_] { return threadNum.load() == 0; });
    if (runningChildThreadNum_.load() != 0) {
        ZLOGI(LOG_LABEL, "wait timeout, %{public}zu child threads not exiting", runningChildThreadNum_.load());
        return;
    }
    ZLOGI(LOG_LABEL, "wait finished, all child thread have exited");
}
} // namespace OHOS
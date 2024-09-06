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

#include "check_instance_exit.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "securec.h"
#include "string_ex.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "ProcessSkeleton" };
static constexpr uint64_t DEAD_OBJECT_TIMEOUT = 20 * (60 * 1000); // min
static constexpr uint64_t DEAD_OBJECT_CHECK_INTERVAL = 11 * (60 * 1000); // min
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
        std::unique_lock<std::shared_mutex> deadObjLock(deadObjectMutex_);
        deadObjectRecord_.clear();
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
    if (iterator != objects_.end()) {
        if (object->IsProxyObject()) {
            proxyObjectCountNum_.fetch_sub(1, std::memory_order_relaxed);
        }
        objects_.erase(iterator);
        ZLOGD(LOG_LABEL, "erase desc:%{public}s", ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str());
        return true;
    }
    ZLOGD(LOG_LABEL, "not found, desc:%{public}s maybe has been updated",
        ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str());
    return false;
}

bool ProcessSkeleton::AttachObject(IRemoteObject *object, const std::u16string &descriptor, bool lockFlag)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(objMutex_, std::defer_lock);
    ZLOGD(LOG_LABEL, "The value of lockflag is:%{public}d", lockFlag);
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
    if (result.second) {
        ZLOGD(LOG_LABEL, "attach %{public}d desc:%{public}s inserted",
            ConvertAddr(object), ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str());
    } else {
        ZLOGW(LOG_LABEL, "attach %{public}d desc:%{public}s assign",
            ConvertAddr(object), ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str());
    }
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
    DeadObjectInfo deadInfo;
    bool isNullObject = (remoteObject == nullptr);
    bool isDeadObject = IsDeadObject(remoteObject, deadInfo);
    if (isNullObject || isDeadObject || !remoteObject->AttemptIncStrong(this)) {
        ZLOGE(LOG_LABEL, "remoteObject is null or dead or AttemptIncStrong failed, "
            "isNullObject:%{public}d, isDeadObject:%{public}d", isNullObject, isDeadObject);
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

bool ProcessSkeleton::AttachDeadObject(IRemoteObject *object, DeadObjectInfo &objInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(deadObjectMutex_);
    auto result = deadObjectRecord_.insert_or_assign(object, objInfo);
    ZLOGD(LOG_LABEL, "%{public}u handle:%{public}d desc:%{public}s inserted:%{public}d",
        ConvertAddr(object), objInfo.handle,
        ConvertToSecureDesc(Str16ToStr8(objInfo.desc)).c_str(), result.second);
    DetachTimeoutDeadObject();
    return result.second;
}

bool ProcessSkeleton::DetachDeadObject(IRemoteObject *object)
{
    bool ret = false;
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::unique_lock<std::shared_mutex> lockGuard(deadObjectMutex_);
    auto it = deadObjectRecord_.find(object);
    if (it != deadObjectRecord_.end()) {
        ZLOGD(LOG_LABEL, "erase %{public}u handle:%{public}d desc:%{public}s", ConvertAddr(object),
            it->second.handle, ConvertToSecureDesc(Str16ToStr8(it->second.desc)).c_str());
        deadObjectRecord_.erase(it);
        ret = true;
    }
    DetachTimeoutDeadObject();
    return ret;
}

bool ProcessSkeleton::IsDeadObject(IRemoteObject *object, DeadObjectInfo &deadInfo)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::shared_lock<std::shared_mutex> lockGuard(deadObjectMutex_);
    auto it = deadObjectRecord_.find(object);
    if (it != deadObjectRecord_.end()) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        auto &info = it->second;
        info.agingTime = curTime;
        deadInfo = info;
        return true;
    }
    return false;
}

void ProcessSkeleton::DetachTimeoutDeadObject()
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    // don't lock in the function.
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    if (curTime < DEAD_OBJECT_CHECK_INTERVAL + deadObjectClearTime_) {
        return;
    }
    deadObjectClearTime_ = curTime;
    size_t index = 0;
    size_t recordSize = deadObjectRecord_.size();
    for (auto it = deadObjectRecord_.begin(); it != deadObjectRecord_.end() && index < recordSize; ++index) {
        if (curTime - it->second.agingTime >= DEAD_OBJECT_TIMEOUT) {
            ZLOGD(LOG_LABEL, "erase %{public}u handle:%{public}d desc:%{public}s time:%{public}" PRIu64,
                ConvertAddr(it->first), it->second.handle,
                ConvertToSecureDesc(Str16ToStr8(it->second.desc)).c_str(), it->second.deadTime);
            it = deadObjectRecord_.erase(it);
            continue;
        }
        ++it;
    }
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
} // namespace OHOS
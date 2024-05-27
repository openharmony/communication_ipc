/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "string_ex.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "ProcessSkeleton" };
static constexpr uint64_t DEAD_OBJECT_TIMEOUT = 20 * (60 * 1000); // min
static constexpr uint64_t DEAD_OBJECT_CHECK_INTERVAL = 11 * (60 * 1000); // min
static constexpr int PRINT_ERR_CNT = 100;

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
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    ZLOGW(LOG_LABEL, "destroy time:%{public}" PRIu64, curTime);
    exitFlag_ = true;
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
        ZLOGE(LOG_LABEL, "descriptor is null %{public}zu", reinterpret_cast<uintptr_t>(object));
        return false;
    }
    // If attemptIncStrong failed, old proxy might still exist, replace it with the new proxy.
    wptr<IRemoteObject> wp = object;
    auto result = objects_.insert_or_assign(descriptor, wp);
    ZLOGD(LOG_LABEL, "attach desc:%{public}s inserted:%{public}d",
        ConvertToSecureDesc(Str16ToStr8(descriptor)).c_str(), result.second);
    return result.second;
}

sptr<IRemoteObject> ProcessSkeleton::QueryObject(const std::u16string &descriptor, bool lockFlag)
{
    sptr<IRemoteObject> result = nullptr;
    if (descriptor.empty()) {
        ZLOGE(LOG_LABEL, "descriptor is null");
        return result;
    }

    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    std::shared_lock<std::shared_mutex> lockGuard(objMutex_, std::defer_lock);
    ZLOGD(LOG_LABEL, "The value of lockflag is:%{public}d", lockFlag);
    if (lockFlag) {
        lockGuard.lock();
    }
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
    ZLOGD(LOG_LABEL, "%{public}zu handle:%{public}d desc:%{public}s inserted:%{public}d",
        reinterpret_cast<uintptr_t>(object), objInfo.handle,
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
        ZLOGD(LOG_LABEL, "erase %{public}zu handle:%{public}d desc:%{public}s", reinterpret_cast<uintptr_t>(object),
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
    if (curTime - deadObjectClearTime_ < DEAD_OBJECT_CHECK_INTERVAL) {
        return;
    }
    deadObjectClearTime_ = curTime;
    for (auto it = deadObjectRecord_.begin(); it != deadObjectRecord_.end();) {
        if (curTime - it->second.agingTime >= DEAD_OBJECT_TIMEOUT) {
            ZLOGD(LOG_LABEL, "erase %{public}zu handle:%{public}d desc:%{public}s time:%{public}" PRIu64,
                reinterpret_cast<uintptr_t>(it->first), it->second.handle,
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
    ZLOGD(LOG_LABEL, "%{public}zu, %{public}u %{public}u %{public}u %{public}" PRIu64 " %{public}" PRIu64,
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
    ZLOGD(LOG_LABEL, "%{public}zu, %{public}u %{public}u %{public}u %{public}" PRIu64 " %{public}" PRIu64,
        invokeInfo.invoker, invokeInfo.pid, invokeInfo.realPid, invokeInfo.uid, invokeInfo.tokenId,
        invokeInfo.firstTokenId);
    return true;
}

bool ProcessSkeleton::IsPrint(int err, int &lastErr, int &lastErrCnt)
{
    bool isPrint = false;
    if (err == lastErr) {
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
} // namespace OHOS
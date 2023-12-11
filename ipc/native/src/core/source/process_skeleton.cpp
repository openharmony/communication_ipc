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

#include "log_tags.h"
#include "ipc_debug.h"
#include "string_ex.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "ProcessSkeleton" };

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
    ZLOGW(LOG_LABEL, "destroy");
    std::lock_guard<std::mutex> lockGuard(mutex_);
    exitFlag_ = true;
    {
        std::unique_lock<std::shared_mutex> objLock(objMutex_);
        objects_.clear();
        isContainStub_.clear();
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
        ZLOGD(LOG_LABEL, "erase desc:%{public}s", Str16ToStr8(descriptor).c_str());
        return true;
    }
    ZLOGW(LOG_LABEL, "not found, desc:%{public}s maybe has been updated", Str16ToStr8(descriptor).c_str());
    return false;
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
        ZLOGE(LOG_LABEL, "descriptor is null");
        return false;
    }
    // If attemptIncStrong failed, old proxy might still exist, replace it with the new proxy.
    wptr<IRemoteObject> wp = object;
    auto result = objects_.insert_or_assign(descriptor, wp);
    ZLOGD(LOG_LABEL, "attac desc:%{public}s inserted:%{public}d", Str16ToStr8(descriptor).c_str(), result.second);
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
} // namespace OHOS
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

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "ProcessSkeleton" };

sptr<ProcessSkeleton> ProcessSkeleton::instance_ = nullptr;
std::mutex ProcessSkeleton::mutex_;

sptr<ProcessSkeleton> ProcessSkeleton::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) ProcessSkeleton();
            if (instance_ == nullptr) {
                ZLOGE(LOG_LABEL, "create ProcessSkeleton object failed");
                return nullptr;
            }
        }
    }
    return instance_;
}

sptr<IRemoteObject> ProcessSkeleton::GetRegistryObject()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return registryObject_;
}

void ProcessSkeleton::SetRegistryObject(sptr<IRemoteObject> &object)
{
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
} // namespace OHOS
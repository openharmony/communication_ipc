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

#include "iremote_broker.h"

#include <utility>

#include "__mutex_base"
#include "functional"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "ipc_debug.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "refbase.h"
#include "string"
#include "type_traits"
#include "unordered_map"

namespace OHOS {
[[maybe_unused]] static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC_COMMON, "BrokerRegistration" };
BrokerRegistration &BrokerRegistration::Get()
{
    static BrokerRegistration instance;
    return instance;
}

BrokerRegistration::~BrokerRegistration()
{
    std::lock_guard<std::mutex> lockGuard(creatorMutex_);
    isUnloading = true;
    for (auto it1 = objects_.begin(); it1 != objects_.end();) {
        BrokerDelegatorBase *object = reinterpret_cast<BrokerDelegatorBase *>(*it1);
        object->isSoUnloaded = true;
        it1 = objects_.erase(it1);
    }
}

bool BrokerRegistration::Register(const std::u16string &descriptor, const Constructor &creator,
    const BrokerDelegatorBase *object)
{
    if (descriptor.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lockGuard(creatorMutex_);
    if (isUnloading) {
        ZLOGE(LABEL, "BrokerRegistration is Unloading");
        return false;
    }
    auto it = creators_.find(descriptor);
    bool ret = false;
    if (it == creators_.end()) {
        ret = creators_.insert({ descriptor, creator }).second;
    }
    auto it1 = std::find_if(objects_.begin(), objects_.end(), [descriptor](uintptr_t id) {
        const BrokerDelegatorBase *object = reinterpret_cast<BrokerDelegatorBase *>(id);
        return object->descriptor_ == descriptor;
    });
    if (it1 == objects_.end()) {
        objects_.push_back(reinterpret_cast<uintptr_t>(object));
    }
    return ret;
}

void BrokerRegistration::Unregister(const std::u16string &descriptor)
{
    std::lock_guard<std::mutex> lockGuard(creatorMutex_);
    if (isUnloading) {
        ZLOGE(LABEL, "BrokerRegistration is Unloading");
        return;
    }
    if (!descriptor.empty()) {
        auto it = creators_.find(descriptor);
        if (it != creators_.end()) {
            creators_.erase(it);
        }
        auto it1 = std::find_if(objects_.begin(), objects_.end(), [descriptor](uintptr_t id) {
            const BrokerDelegatorBase *object = reinterpret_cast<BrokerDelegatorBase *>(id);
            return object->descriptor_ == descriptor;
        });
        if (it1 != objects_.end()) {
            objects_.erase(it1);
        }
    }
}

sptr<IRemoteBroker> BrokerRegistration::NewInstance(const std::u16string &descriptor, const sptr<IRemoteObject> &object)
{
    std::lock_guard<std::mutex> lockGuard(creatorMutex_);

    sptr<IRemoteBroker> broker;
    if (object != nullptr) {
        if (object->IsProxyObject()) {
            auto it = creators_.find(descriptor);
            if (it != creators_.end()) {
                broker = it->second(object);
            }
        } else if (descriptor == object->GetObjectDescriptor()) {
            broker = object->AsInterface().GetRefPtr();
        }
    }
    return broker;
}
} // namespace OHOS

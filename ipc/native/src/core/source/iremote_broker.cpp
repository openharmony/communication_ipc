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
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
[[maybe_unused]] static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "BrokerRegistration" };
BrokerRegistration &BrokerRegistration::Get()
{
    static BrokerRegistration instance;
    return instance;
}

BrokerRegistration::~BrokerRegistration()
{
    std::lock_guard<std::mutex> lockGuard(creatorMutex_);
    for (auto it = creators_.begin(); it != creators_.end();) {
        it = creators_.erase(it);
    }
}

bool BrokerRegistration::Register(const std::u16string &descriptor, const Constructor &creator)
{
    if (descriptor.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lockGuard(creatorMutex_);
    auto it = creators_.find(descriptor);
    if (it == creators_.end()) {
        return creators_.insert({ descriptor, creator }).second;
    }
    return false;
}

void BrokerRegistration::Unregister(const std::u16string &descriptor)
{
    std::lock_guard<std::mutex> lockGuard(creatorMutex_);
    if (!descriptor.empty()) {
        auto it = creators_.find(descriptor);
        if (it != creators_.end()) {
            creators_.erase(it);
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
        } else {
            broker = object->AsInterface().GetRefPtr();
        }
    }
    return broker;
}
} // namespace OHOS

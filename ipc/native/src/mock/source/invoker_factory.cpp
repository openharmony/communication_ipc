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

#include "invoker_factory.h"
#include <utility>

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif
bool InvokerFactory::isAvailable_ = true;

InvokerFactory::InvokerFactory() {}

InvokerFactory::~InvokerFactory()
{
    isAvailable_ = false;
    creators_.clear();
}

InvokerFactory &InvokerFactory::Get()
{
    static InvokerFactory instance;
    return instance;
}

bool InvokerFactory::Register(int protocol, InvokerCreator creator)
{
    if (isAvailable_ != true) {
        return false;
    }
    std::lock_guard<std::mutex> lockGuard(factoryMutex_);

    /* check isAvailable_ == true again when a thread take mutex */
    if (isAvailable_ != true) {
        return false;
    }
    return creators_.insert(std::make_pair(protocol, creator)).second;
}

void InvokerFactory::Unregister(int protocol)
{
    if (isAvailable_ != true) {
        return;
    }
    std::lock_guard<std::mutex> lockGuard(factoryMutex_);

    /* check isAvailable_ == true again when a thread take mutex */
    if (isAvailable_ != true) {
        return;
    }
    (void)creators_.erase(protocol);
}

IRemoteInvoker *InvokerFactory::newInstance(int protocol)
{
    if (isAvailable_ != true) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lockGuard(factoryMutex_);

    /* check isAvailable_ == true again when a thread take mutex */
    if (isAvailable_ != true) {
        return nullptr;
    }
    auto it = creators_.find(protocol);
    if (it != creators_.end() && (it->second != nullptr)) {
        return it->second();
    }
    return nullptr;
}
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
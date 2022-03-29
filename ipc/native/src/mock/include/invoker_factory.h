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

#ifndef OHOS_IPC_INVOKER_FACTORY_H
#define OHOS_IPC_INVOKER_FACTORY_H

#include <functional>
#include <unordered_map>
#include "iremote_invoker.h"

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
namespace IPC_SINGLE {
#endif
class InvokerFactory {
public:
    using InvokerCreator = std::function<IRemoteInvoker *()>;
    static InvokerFactory &Get();
    bool Register(int protocol, InvokerCreator creator);
    void Unregister(int protocol);
    IRemoteInvoker *newInstance(int protocol);

private:
    InvokerFactory &operator = (const InvokerFactory &) = delete;
    InvokerFactory(const InvokerFactory &) = delete;
    InvokerFactory();
    ~InvokerFactory();
    static bool isAvailable_;
    std::mutex factoryMutex_;
    std::unordered_map<int, InvokerCreator> creators_;
};

template <typename T> class InvokerDelegator {
public:
    InvokerDelegator(int prot);
    ~InvokerDelegator();

private:
    int prot_;
    InvokerDelegator &operator = (const InvokerDelegator &) = delete;
    InvokerDelegator(const InvokerDelegator &) = delete;
};

template <typename T> InvokerDelegator<T>::InvokerDelegator(int prot)
{
    prot_ = prot;
    InvokerFactory::Get().Register(prot, []() { return static_cast<IRemoteInvoker *>(new T()); });
}

template <typename T> InvokerDelegator<T>::~InvokerDelegator()
{
    InvokerFactory::Get().Unregister(prot_);
}
#ifdef CONFIG_IPC_SINGLE
} // namespace IPC_SINGLE
#endif
} // namespace OHOS
#endif // OHOS_IPC_INVOKER_FACTORY_H
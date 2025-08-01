/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "iremotebroker_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "iremote_broker.h"

namespace OHOS {
std::u16string CreateDescriptor(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString();
    return std::u16string(descriptor.begin(), descriptor.end());
}

void RegisterFuzzTest(FuzzedDataProvider &provider)
{
    std::u16string descriptor;
    auto creator = [](const sptr<IRemoteObject> &obj) { return sptr<IRemoteBroker>(nullptr); };
    BrokerDelegatorBase obj;
    BrokerRegistration registration;
    registration.Register(descriptor, creator, &obj);
    descriptor = CreateDescriptor(provider);
    registration.Register(descriptor, creator, &obj);
}

void UnregisterFuzzTest(FuzzedDataProvider &provider)
{
    std::u16string descriptor = CreateDescriptor(provider);
    auto creator = [](const sptr<IRemoteObject> &obj) { return sptr<IRemoteBroker>(nullptr); };
    BrokerDelegatorBase obj;
    BrokerRegistration registration;
    registration.Register(descriptor, creator, &obj);
    registration.Unregister(std::u16string());
    registration.Unregister(descriptor);
}

void NewInstanceFuzzTest001(FuzzedDataProvider &provider)
{
    std::u16string descriptor = CreateDescriptor(provider);
    auto creator = [](const sptr<IRemoteObject> &obj) { return sptr<IRemoteBroker>(nullptr); };
    BrokerDelegatorBase obj;
    int handle = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (proxy == nullptr) {
        return;
    }
    BrokerRegistration registration;
    registration.Register(descriptor, creator, &obj);
    registration.NewInstance(descriptor, static_cast<sptr<IRemoteObject>>(proxy));
}

void NewInstanceFuzzTest002(FuzzedDataProvider &provider)
{
    std::u16string descriptor = CreateDescriptor(provider);
    sptr<IPCObjectStub> stub = sptr<IPCObjectStub>::MakeSptr(descriptor);
    if (stub == nullptr) {
        return;
    }
    BrokerRegistration registration;
    registration.NewInstance(descriptor, static_cast<sptr<IRemoteObject>>(stub));
}

void GetObjectSoPathFuzzTest(FuzzedDataProvider &provider)
{
    uintptr_t ptr = provider.ConsumeIntegral<uintptr_t>();
    BrokerRegistration registration;
    registration.GetObjectSoPath(ptr);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::RegisterFuzzTest(provider);
    OHOS::UnregisterFuzzTest(provider);
    OHOS::NewInstanceFuzzTest001(provider);
    OHOS::NewInstanceFuzzTest002(provider);
    OHOS::GetObjectSoPathFuzzTest(provider);
    return 0;
}

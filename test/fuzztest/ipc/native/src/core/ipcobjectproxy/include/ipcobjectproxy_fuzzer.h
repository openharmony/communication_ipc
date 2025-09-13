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

#ifndef IPCOBJECTPROXY_FUZZER_H
#define IPCOBJECTPROXY_FUZZER_H

#include "ipc_object_proxy.h"
#include "message_parcel.h"
#include "securec.h"
#include "sys_binder.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr size_t STR_MAX_LEN = 100;

class MockDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    MockDeathRecipient() = default;
    ~MockDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object)
    {
        (void)object;
    }
};

sptr<IPCObjectProxy> CreateIPCObjectProxy(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    int32_t proto = provider.ConsumeIntegral<int32_t>();
    std::string descriptor = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle, descriptor16, proto);
    return proxy;
}
} // namespace OHOS

#define FUZZ_PROJECT_NAME "ipcobjectproxy_fuzzer"

#endif // IPCOBJECTPROXY_FUZZER_H
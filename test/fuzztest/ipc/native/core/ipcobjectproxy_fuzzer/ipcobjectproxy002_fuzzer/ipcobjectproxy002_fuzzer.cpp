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

#include "ipcobjectproxy_fuzzer.h"

namespace OHOS {
sptr<IPCObjectProxy> CreateIPCObjectProxy(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return nullptr;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t handle = parcel.ReadInt32();
    int32_t proto = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return nullptr;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return nullptr;
    }
    std::string descriptor_str(bufData, length);
    std::u16string descriptor(descriptor_str.begin(), descriptor_str.end());
    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(handle, descriptor, proto);
    return proxy;
}

void AddDeathRecipientFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(data, size);
    if (proxy == nullptr) {
        return;
    }
    sptr<IRemoteObject::DeathRecipient> death = new MockDeathRecipient();
    proxy->AddDeathRecipient(death.GetRefPtr());
}

void RemoveDeathRecipientFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(data, size);
    if (proxy == nullptr) {
        return;
    }
    sptr<IRemoteObject::DeathRecipient> death = new MockDeathRecipient();
    proxy->RemoveDeathRecipient(death.GetRefPtr());
}

void InvokeListenThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(data, size);
    if (proxy == nullptr) {
        return;
    }
    MessageParcel data_parcel;
    MessageParcel reply_parcel;
    data_parcel.WriteBuffer(data, size);
    proxy->InvokeListenThread(data_parcel, reply_parcel);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AddDeathRecipientFuzzTest(data, size);
    OHOS::RemoveDeathRecipientFuzzTest(data, size);
    OHOS::InvokeListenThreadFuzzTest(data, size);
    return 0;
}

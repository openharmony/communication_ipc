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

#include "binderinvoker_fuzzer.h"
#include "binder_invoker.h"
#include "ipc_object_stub.h"
#include "message_parcel.h"

#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr size_t MAX_BYTES_SIZE = 50;

void SendRequestFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    MessageParcel reply;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t handle = dataParcel.ReadInt32();
    uint32_t code = dataParcel.ReadUint32();
    BinderInvoker invoker;
    MessageOption option{ MessageOption::TF_ASYNC };
    invoker.SendRequest(handle, code, dataParcel, reply, option);
}

void SetMaxWorkThreadFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t maxThreadNum = parcel.ReadInt32();
    BinderInvoker invoker;
    invoker.SetMaxWorkThread(maxThreadNum);
}

void SetRegistryObjectFuzzTest001(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    sptr<IRemoteObject> object = parcel.ReadRemoteObject();
    BinderInvoker invoker;
    invoker.SetRegistryObject(object);
}

void SetRegistryObjectFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());

    int32_t handle = parcel.ReadInt32();
    int32_t proto = parcel.ReadInt32();
    std::u16string desc;
    size_t length = parcel.GetReadableBytes();
    if (length != 0) {
        const char16_t *bufData = reinterpret_cast<const char16_t *>(parcel.ReadBuffer(length));
        if (bufData == nullptr) {
            return;
        }
        size_t charCount = length / sizeof(char16_t);
        desc.assign(bufData, charCount);
    }

    sptr<IRemoteObject> proxy = new IPCObjectProxy(handle, desc, proto);
    if (proxy == nullptr) {
        return;
    }
    BinderInvoker invoker;
    invoker.SetRegistryObject(proxy);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SendRequestFuzzTest(provider);
    OHOS::SetMaxWorkThreadFuzzTest(provider);
    OHOS::SetRegistryObjectFuzzTest001(provider);
    OHOS::SetRegistryObjectFuzzTest002(provider);
    return 0;
}

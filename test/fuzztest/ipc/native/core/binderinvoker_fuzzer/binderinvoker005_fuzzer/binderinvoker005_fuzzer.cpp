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

void SetRegistryObjectFuzzTest003(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());

    bool serialInvokeFlag = parcel.ReadBool();
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

    sptr<IRemoteObject> stub = new IPCObjectStub(desc, serialInvokeFlag);
    if (stub == nullptr) {
        return;
    }
    BinderInvoker invoker;
    invoker.SetRegistryObject(stub);
}

void SetStatusFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    uint32_t status = parcel.ReadUint32();
    BinderInvoker invoker;
    invoker.SetStatus(status);
}

void WriteFileDescriptorFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t fd = parcel.ReadInt32();
    bool takeOwnership = parcel.ReadBool();

    MessageParcel dataParcel;
    BinderInvoker invoker;
    (void)invoker.WriteFileDescriptor(dataParcel, fd, takeOwnership);
}

void SamgrServiceSendRequestFuzzTest(FuzzedDataProvider &provider)
{
    binder_transaction_data tr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    BinderInvoker invoker;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    data.WriteBuffer(bytes.data(), bytes.size());
    invoker.SamgrServiceSendRequest(tr, data, reply, option);
}

void UpdateConsumedDataFuzzTest(FuzzedDataProvider &provider)
{
    size_t outAvail = provider.ConsumeIntegral<size_t>();
    binder_write_read bwr;
    bwr.write_consumed = provider.ConsumeIntegralInRange<uint32_t>(0, bwr.write_consumed);
    bwr.read_consumed = provider.ConsumeIntegralInRange<uint32_t>(0, bwr.write_consumed);
    BinderInvoker invoker;
    invoker.UpdateConsumedData(bwr, outAvail);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SetRegistryObjectFuzzTest003(provider);
    OHOS::SetStatusFuzzTest(provider);
    OHOS::WriteFileDescriptorFuzzTest(provider);
    OHOS::SamgrServiceSendRequestFuzzTest(provider);
    OHOS::UpdateConsumedDataFuzzTest(provider);
    return 0;
}

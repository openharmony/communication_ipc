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
static constexpr size_t MAX_DATA_SIZE = 100;
static constexpr size_t FLAT_OBJ_SIZE = sizeof(flat_binder_object);
static constexpr size_t MAX_OFFSETS = 10;

void TransactionFuzzTest(FuzzedDataProvider &provider)
{
    BinderInvoker invoker;
    size_t data_size = provider.ConsumeIntegralInRange<size_t>(0, MAX_DATA_SIZE);
    std::vector<uint8_t> data_buffer(data_size);
    for (size_t i = 0; i < data_size; ++i) {
        data_buffer[i] = provider.ConsumeIntegral<uint8_t>();
    }

    MessageParcel parcel;
    if (data_size > 0) {
        if (!parcel.WriteBuffer(data_buffer.data(), data_size)) {
            return;
        }
    }

    std::vector<binder_size_t> fake_offsets;
    if (data_size >= FLAT_OBJ_SIZE) {
        size_t max_index = (data_size - FLAT_OBJ_SIZE) / FLAT_OBJ_SIZE;
        size_t num_offsets = provider.ConsumeIntegralInRange<size_t>(0, std::min(max_index + 1, MAX_OFFSETS));

        for (size_t i = 0; i < num_offsets; ++i) {
            size_t index = provider.ConsumeIntegralInRange<size_t>(0, max_index);
            binder_size_t offset = static_cast<binder_size_t>(index * FLAT_OBJ_SIZE);
            offset &= ~7U;
            fake_offsets.push_back(offset);
        }
    }

    binder_transaction_data_secctx trSecctx = {};
    binder_transaction_data& tr = trSecctx.transaction_data;

    tr.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(data_buffer.data());
    tr.data_size = data_size;

    if (!fake_offsets.empty()) {
        tr.data.ptr.offsets = reinterpret_cast<binder_uintptr_t>(const_cast<binder_size_t*>(fake_offsets.data()));
        tr.offsets_size = fake_offsets.size() * sizeof(binder_size_t);
    } else {
        tr.data.ptr.offsets = 0;
        tr.offsets_size = 0;
    }

    tr.code = provider.ConsumeIntegral<uint32_t>();
    tr.flags = provider.ConsumeIntegral<uint32_t>();
    tr.sender_pid = provider.ConsumeIntegral<int>();
    tr.sender_euid = provider.ConsumeIntegral<int>();
    trSecctx.secctx = 0;

    invoker.Transaction(trSecctx);
}

void AddDeathRecipientFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t handle = parcel.ReadInt32();
    sptr<IRemoteObject> point = parcel.ReadRemoteObject();
    BinderInvoker invoker;
    invoker.AddDeathRecipient(handle, reinterpret_cast<void*>(point.GetRefPtr()));
}

void FlattenObjectFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());

    int handle;
    int proto;
    if (!parcel.ReadInt32(handle) || !parcel.ReadInt32(proto)) {
        return;
    }
    sptr<IRemoteObject> obj = new IPCObjectProxy(handle, u"proxyTest", proto);
    IRemoteObject *object = obj.GetRefPtr();
    BinderInvoker binderInvoker;
    binderInvoker.FlattenObject(parcel, object);
    binderInvoker.UnflattenObject(parcel);
}

void GetCallerInfoFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());

    int32_t status = parcel.ReadInt32();
    pid_t pid = static_cast<pid_t>(parcel.ReadInt32());

    BinderInvoker invoker;
    invoker.SetStatus(status);
    invoker.invokerInfo_.pid = pid;

    invoker.GetCallerSid();
    invoker.GetCallerPid();
    invoker.GetCallerRealPid();
    invoker.GetCallerUid();
    invoker.GetCallerTokenID();
    invoker.GetFirstCallerTokenID();
    invoker.GetSelfTokenID();
    invoker.GetSelfFirstCallerTokenID();
    invoker.IsLocalCalling();
    invoker.GetStatus();
    invoker.GetLocalDeviceID();
    invoker.GetCallerDeviceID();
    invoker.ExitCurrentThread();
}

void SetCallingIdentityFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());

    bool flag = parcel.ReadBool();

    std::string identity;
    size_t length = parcel.GetReadableBytes();
    if (length != 0) {
        const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
        if (bufData == nullptr) {
            return;
        }
        identity.assign(bufData, length);
    }

    BinderInvoker invoker;
    invoker.SetCallingIdentity(identity, flag);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TransactionFuzzTest(provider);
    OHOS::AddDeathRecipientFuzzTest(provider);
    OHOS::FlattenObjectFuzzTest(provider);
    OHOS::GetCallerInfoFuzzTest(provider);
    OHOS::SetCallingIdentityFuzzTest(provider);
    return 0;
}

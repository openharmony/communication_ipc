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

void ResetCallingIdentityFuzzTest(FuzzedDataProvider &provider)
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

    invoker.ResetCallingIdentity();
}

void FlushCommandsFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    BinderInvoker binderInvoker;
    IRemoteObject* iRemoteObject = parcel.ReadRemoteObject();
    binderInvoker.FlushCommands(iRemoteObject);
}

void FreeBufferFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    uintptr_t point = parcel.ReadPointer();
    BinderInvoker invoker;
    invoker.FreeBuffer(reinterpret_cast<void*>(point));
}

void GetStrongRefCountForStubFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    uint32_t handle = parcel.ReadUint32();
    BinderInvoker invoker;
    invoker.GetStrongRefCountForStub(handle);
}

void PingServiceFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t handle = parcel.ReadInt32();
    BinderInvoker invoker;
    invoker.PingService(handle);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FlushCommandsFuzzTest(provider);
    OHOS::FreeBufferFuzzTest(provider);
    OHOS::GetStrongRefCountForStubFuzzTest(provider);
    OHOS::PingServiceFuzzTest(provider);
    return 0;
}

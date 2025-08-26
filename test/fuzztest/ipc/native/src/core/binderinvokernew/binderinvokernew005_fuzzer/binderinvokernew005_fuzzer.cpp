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

#include "binderinvokernew_fuzzer.h"
#include "binder_invoker.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "message_parcel.h"
#include "string_ex.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr size_t MAX_BYTES_SIZE = 50;

void WriteTransactionFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    int cmd = provider.ConsumeIntegral<int32_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    size_t statusSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> statusBytes = provider.ConsumeBytes<uint8_t>(statusSize);
    int32_t *status = reinterpret_cast<int32_t *>(statusBytes.data());
    size_t totalDBinderBufSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);

    BinderInvoker invoker;
    invoker.WriteTransaction(cmd, flags, handle, code, dataParcel, status, totalDBinderBufSize);
}

void OnReplyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel reply;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    reply.WriteBuffer(bytes.data(), bytes.size());
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    bool continueLoop;
    int32_t error;

    BinderInvoker invoker;
    invoker.OnReply(&reply, continueLoop, error, cmd);
}

void DealWithCmdFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel reply;
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    bool continueLoop;
    int32_t error;

    BinderInvoker invoker;
    invoker.DealWithCmd(&reply, continueLoop, error, cmd);
}

void SetRegistryObjectFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    sptr<OHOS::IRemoteObject> object = dataParcel.ReadRemoteObject();

    BinderInvoker invoker;
    invoker.SetRegistryObject(object);
}

void EnableIPCThreadReclaimFuzzTest(FuzzedDataProvider &provider)
{
    bool enable = provider.ConsumeBool();

    BinderInvoker invoker;
    invoker.EnableIPCThreadReclaim(enable);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::WriteTransactionFuzzTest(provider);
    OHOS::OnReplyFuzzTest(provider);
    OHOS::DealWithCmdFuzzTest(provider);
    OHOS::SetRegistryObjectFuzzTest(provider);
    OHOS::EnableIPCThreadReclaimFuzzTest(provider);
    return 0;
}
} // namespace OHOS
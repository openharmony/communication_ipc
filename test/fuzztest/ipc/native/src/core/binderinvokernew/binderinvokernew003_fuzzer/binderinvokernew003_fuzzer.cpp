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

void SamgrServiceSendRequestFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    binder_transaction_data transData;
    MessageParcel reply;
    MessageOption option;

    BinderInvoker invoker;
    invoker.SamgrServiceSendRequest(transData, dataParcel, reply, option);
}

void GeneralServiceSendRequestFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    binder_transaction_data transData;
    transData.target.ptr = 0;
    transData.code = provider.ConsumeIntegral<uint32_t>();
    transData.cookie = provider.ConsumeIntegral<uint32_t>();
    MessageParcel reply;
    MessageOption option;

    BinderInvoker invoker;
    invoker.GeneralServiceSendRequest(transData, dataParcel, reply, option);
}

void TargetStubSendRequestFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    binder_transaction_data transData;
    transData.target.ptr = provider.ConsumeIntegral<uint64_t>();
    transData.flags = provider.ConsumeIntegral<uint32_t>();
    MessageParcel reply;
    MessageOption option;
    uint32_t flagValue;

    BinderInvoker invoker;
    invoker.TargetStubSendRequest(transData, dataParcel, reply, option, flagValue);
}

void OnTransactionFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    int32_t error;

    BinderInvoker invoker;
    invoker.OnTransaction(cmd, error);
}

void OnTransactionFuzzTest002(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();
    int32_t error;
    MessageParcel dataParcel;

    BinderInvoker invoker;
    if (cmd != static_cast<uint32_t>(BR_TRANSACTION_SEC_CTX)) {
        binder_transaction_data tr {};
        invoker.input_.WriteBuffer(&tr, sizeof(binder_transaction_data));
        invoker.OnTransaction(cmd, error);
    }
    cmd = static_cast<uint32_t>(BR_TRANSACTION_SEC_CTX);
    binder_transaction_data_secctx trSecctx {};
    invoker.input_.WriteBuffer(&trSecctx, sizeof(binder_transaction_data_secctx));
    invoker.OnTransaction(cmd, error);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SamgrServiceSendRequestFuzzTest(provider);
    OHOS::GeneralServiceSendRequestFuzzTest(provider);
    OHOS::TargetStubSendRequestFuzzTest(provider);
    OHOS::OnTransactionFuzzTest001(provider);
    OHOS::OnTransactionFuzzTest002(provider);
    return 0;
}
} // namespace OHOS
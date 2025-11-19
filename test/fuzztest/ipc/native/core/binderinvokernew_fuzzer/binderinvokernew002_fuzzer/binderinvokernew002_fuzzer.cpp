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

void TranslateDBinderStubFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    bool isReply = provider.ConsumeBool();
    size_t totalDBinderBufSize;

    BinderInvoker invoker;
    invoker.TranslateDBinderStub(handle, dataParcel, isReply, totalDBinderBufSize);
}

void OnAcquireObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();

    BinderInvoker invoker;
    invoker.OnAcquireObject(cmd);
}

void OnReleaseObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t cmd = provider.ConsumeIntegral<uint32_t>();

    BinderInvoker invoker;
    invoker.OnReleaseObject(cmd);
}

void GetAccessTokenFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t callerTokenID = provider.ConsumeIntegral<uint64_t>();
    uint64_t firstTokenID = provider.ConsumeIntegral<uint64_t>();

    BinderInvoker invoker;
    invoker.GetAccessToken(callerTokenID, firstTokenID);
}

void GetSenderInfoFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t callerTokenID = provider.ConsumeIntegral<uint64_t>();
    uint64_t firstTokenID = provider.ConsumeIntegral<uint64_t>();
    pid_t realPid;

    BinderInvoker invoker;
    invoker.GetSenderInfo(callerTokenID, firstTokenID, realPid);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TranslateDBinderStubFuzzTest(provider);
    OHOS::OnAcquireObjectFuzzTest(provider);
    OHOS::OnReleaseObjectFuzzTest(provider);
    OHOS::GetAccessTokenFuzzTest(provider);
    OHOS::GetSenderInfoFuzzTest(provider);
    return 0;
}
} // namespace OHOS
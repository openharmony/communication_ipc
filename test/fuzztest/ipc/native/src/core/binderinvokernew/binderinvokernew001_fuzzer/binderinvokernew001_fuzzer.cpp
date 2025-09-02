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
static constexpr pid_t INVALID_PID = -1;

void AcquireHandleFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();

    BinderInvoker invoker;
    invoker.AcquireHandle(handle);
}

void TranslateDBinderProxyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    int32_t handle = provider.ConsumeIntegral<int32_t>();

    BinderInvoker invoker;
    invoker.TranslateDBinderProxy(handle, dataParcel);
}

void AddCommAuthFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    flat_binder_object flat;
    flat.handle = provider.ConsumeIntegral<int32_t>();

    BinderInvoker invoker;
    invoker.AddCommAuth(handle, &flat);
}

void GetDBinderCallingPidUidFuzzTest001(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    bool isReply = provider.ConsumeBool();
    pid_t pid = static_cast<pid_t>(provider.ConsumeIntegral<int32_t>());
    uid_t uid = static_cast<uid_t>(provider.ConsumeIntegral<int32_t>());

    BinderInvoker invoker;
    invoker.GetDBinderCallingPidUid(handle, isReply, pid, uid);
}

void GetDBinderCallingPidUidFuzzTest002(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    bool isReply = provider.ConsumeBool();
    pid_t pid = INVALID_PID;
    uid_t uid = static_cast<uid_t>(provider.ConsumeIntegral<int32_t>());

    BinderInvoker invoker;
    invoker.GetDBinderCallingPidUid(handle, isReply, pid, uid);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AcquireHandleFuzzTest(provider);
    OHOS::TranslateDBinderProxyFuzzTest(provider);
    OHOS::AddCommAuthFuzzTest(provider);
    OHOS::GetDBinderCallingPidUidFuzzTest001(provider);
    OHOS::GetDBinderCallingPidUidFuzzTest002(provider);
    return 0;
}
} // namespace OHOS
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
static constexpr size_t STR_MAX_LEN = 100;
static constexpr size_t MAX_BYTES_SIZE = 50;

void PrintParcelDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    std::string parcelName = provider.ConsumeRandomLengthString(STR_MAX_LEN);

    BinderInvoker invoker;
    invoker.PrintParcelData(dataParcel, parcelName);
}

void GetUint64ValueByStrSliceFuzzTest(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    size_t offset = provider.ConsumeIntegral<size_t>();
    size_t length = provider.ConsumeIntegralInRange<size_t>(0, std::numeric_limits<size_t>::max() - offset);
    uint64_t value;

    BinderInvoker invoker;
    invoker.GetUint64ValueByStrSlice(str, offset, length, value);
}

void GetCallerRealPidByStrFuzzTest001(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    size_t offset = provider.ConsumeIntegral<size_t>();
    size_t length = provider.ConsumeIntegralInRange<size_t>(0, std::numeric_limits<size_t>::max() - offset);
    pid_t callerRealPid;

    BinderInvoker invoker;
    invoker.GetCallerRealPidByStr(str, offset, length, callerRealPid);
}

void GetCallerRealPidByStrFuzzTest002(FuzzedDataProvider &provider)
{
    int32_t num = provider.ConsumeIntegral<int32_t>();
    std::string identity = "<" + std::to_string(num);
    size_t offset = provider.ConsumeIntegralInRange<size_t>(0, identity.length());
    size_t length = provider.ConsumeIntegralInRange<size_t>(0, identity.length());
    pid_t callerRealPid;

    BinderInvoker invoker;
    invoker.GetCallerRealPidByStr(identity, offset, length, callerRealPid);
}

void GetCallerPidAndUidByStrFuzzTest(FuzzedDataProvider &provider)
{
    int32_t num = provider.ConsumeIntegral<int32_t>();
    std::string str = "<" + std::to_string(num);
    size_t offset = provider.ConsumeIntegralInRange<size_t>(0, str.length());
    pid_t pid = 0;
    pid_t uid = 0;

    BinderInvoker binderInvoker;
    binderInvoker.GetCallerPidAndUidByStr(str, offset, pid, uid);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::PrintParcelDataFuzzTest(provider);
    OHOS::GetUint64ValueByStrSliceFuzzTest(provider);
    OHOS::GetCallerRealPidByStrFuzzTest001(provider);
    OHOS::GetCallerRealPidByStrFuzzTest002(provider);
    OHOS::GetCallerPidAndUidByStrFuzzTest(provider);
    return 0;
}
} // namespace OHOS
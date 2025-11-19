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

#include "processskeleton_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "ipc_object_stub.h"
#include "message_parcel.h"
#include "process_skeleton.h"

namespace OHOS {
void IsPrintFuzzTest(FuzzedDataProvider &provider)
{
    int err = provider.ConsumeIntegral<int>();
    std::atomic<int> lastErr(err);
    std::atomic<int> lastErrCnt = provider.ConsumeIntegral<int>();
    ProcessSkeleton::IsPrint(err, lastErr, lastErrCnt);
}

void ConvertAddrFuzzTest(FuzzedDataProvider &provider)
{
    ProcessSkeleton::ConvertAddr(nullptr);
    sptr<IPCObjectStub> object = sptr<IPCObjectStub>::MakeSptr();
    if (object == nullptr) {
        return;
    }
    ProcessSkeleton::ConvertAddr(object.GetRefPtr());
}

void UnFlattenDBinderDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    dbinder_negotiation_data *dbinderData = nullptr;
    ProcessSkeleton::UnFlattenDBinderData(parcel, dbinderData);
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    ProcessSkeleton::UnFlattenDBinderData(parcel, dbinderData);
}

void IsNumStrFuzzTest(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    ProcessSkeleton::IsNumStr(str);
}

void StrToUint64FuzzTest(FuzzedDataProvider &provider)
{
    std::string str = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint64_t value = 0;
    ProcessSkeleton::StrToUint64(str, value);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::IsPrintFuzzTest(provider);
    OHOS::ConvertAddrFuzzTest(provider);
    OHOS::UnFlattenDBinderDataFuzzTest(provider);
    OHOS::IsNumStrFuzzTest(provider);
    OHOS::StrToUint64FuzzTest(provider);
    return 0;
}

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

#include "dbindercallbackstub_fuzzer.h"

namespace OHOS {
void DBinderCallbackStubFuzzTest(FuzzedDataProvider &provider)
{
    MakeDBinderCallbackStub(provider);
}

void MarshallingFuzzTest(FuzzedDataProvider &provider)
{
    auto stub = MakeDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    MessageParcel parcel;

    stub->Marshalling(parcel);
}

void MarshallingPSFuzzTest(FuzzedDataProvider &provider)
{
    auto stub = MakeDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    MessageParcel parcel;

    DBinderCallbackStub::Marshalling(parcel, stub);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DBinderCallbackStubFuzzTest(provider);
    OHOS::MarshallingFuzzTest(provider);
    OHOS::MarshallingPSFuzzTest(provider);
    return 0;
}

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

#include "messageparcel_fuzzer.h"

namespace OHOS {
void WriteInterfaceTokenFuzzTest(FuzzedDataProvider &provider)
{
    std::string interfaceToken = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string interfaceToken16(interfaceToken.begin(), interfaceToken.end());
    MessageParcel parcel;
    parcel.WriteInterfaceToken(interfaceToken16);
}

void WriteAshmemFuzzTest(FuzzedDataProvider &provider)
{
    std::string name = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    int memorySize = provider.ConsumeIntegral<int>();
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(name.c_str(), memorySize);
    if (ashmem == nullptr) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteAshmem(ashmem);
}

void AppendFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(MIN_BYTE_SIZE, MAX_BYTE_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteDataBytes(bytes.data(), bytes.size());
    parcel.Append(dataParcel);
}

void PrintBufferFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(MIN_BYTE_SIZE, MAX_BYTE_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteRawData(bytes.data(), bytes.size());
    parcel.PrintBuffer(__FUNCTION__, __LINE__);
}

void ReadRawDataInnerFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel(nullptr);
    size_t size = provider.ConsumeIntegral<size_t>();
    parcel.ReadRawDataInner(size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::WriteInterfaceTokenFuzzTest(provider);
    OHOS::WriteAshmemFuzzTest(provider);
    OHOS::AppendFuzzTest(provider);
    OHOS::PrintBufferFuzzTest(provider);
    OHOS::ReadRawDataInnerFuzzTest(provider);
    return 0;
}

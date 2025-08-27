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

void WriteRawDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize =
        provider.ConsumeIntegralInRange<size_t>(0, MessageParcel::MAX_RAWDATA_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteRawData(bytes.data(), bytes.size());
}

void RestoreRawDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t size = provider.ConsumeIntegral<size_t>();
    std::shared_ptr<char> rawData = std::make_shared<char>();
    parcel.RestoreRawData(nullptr, size);
    parcel.RestoreRawData(rawData, size);
}

void ReadRawDataFuzzTest001(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize =
        provider.ConsumeIntegralInRange<size_t>(MessageParcel::MIN_RAWDATA_SIZE, MessageParcel::MAX_RAWDATA_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    bytes.resize(bytesSize);
    parcel.WriteRawData(bytes.data(), bytesSize);
    parcel.ReadRawData(bytesSize);
}

void ReadRawDataFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize =
        provider.ConsumeIntegralInRange<size_t>(MessageParcel::MIN_RAWDATA_SIZE, MessageParcel::MAX_RAWDATA_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    bytes.resize(bytesSize);
    parcel.WriteRawData(bytes.data(), bytes.size());
    size_t size = provider.ConsumeIntegral<size_t>();
    std::shared_ptr<char> rawData = std::make_shared<char>();
    parcel.RestoreRawData(rawData, size);
    parcel.ReadRawData(bytesSize);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::WriteRawDataFuzzTest(provider);
    OHOS::RestoreRawDataFuzzTest(provider);
    OHOS::ReadRawDataFuzzTest001(provider);
    OHOS::ReadRawDataFuzzTest002(provider);
    return 0;
}

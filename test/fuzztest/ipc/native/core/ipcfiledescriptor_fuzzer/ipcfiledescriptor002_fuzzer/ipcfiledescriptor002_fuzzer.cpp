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

#include "ipcfiledescriptor_fuzzer.h"

namespace OHOS {
void MarshallingFuzzTest001(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    int fd = provider.ConsumeIntegral<int>();
    IPCFileDescriptor fileDesc(fd);
    fileDesc.Marshalling(parcel);
}

void MarshallingFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    IPCFileDescriptor::Marshalling(parcel, nullptr);
    int fd = provider.ConsumeIntegral<int>();
    auto fileDescriptor = sptr<IPCFileDescriptor>::MakeSptr(fd);
    if (fileDescriptor == nullptr) {
        return;
    }
    IPCFileDescriptor::Marshalling(parcel, fileDescriptor);
}

void UnmarshallingFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    parcel.WriteBuffer(bytes.data(), bytes.size());
    int fd = provider.ConsumeIntegral<int>();
    IPCFileDescriptor fileDesc(fd);
    IPCFileDescriptor::Unmarshalling(parcel);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::MarshallingFuzzTest001(provider);
    OHOS::MarshallingFuzzTest002(provider);
    OHOS::UnmarshallingFuzzTest(provider);
    return 0;
}

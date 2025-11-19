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

#include "ipcpayloadstatisticsnew_fuzzer.h"
#include "ipc_payload_statistics.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
void GetDescriptorCodeCountFuzzTest(FuzzedDataProvider &provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string descriptor = provider.ConsumeRandomLengthString();
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    int32_t code = provider.ConsumeIntegral<int32_t>();
    IPCPayloadStatistics::GetDescriptorCodeCount(pid, descriptor16, code);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetDescriptorCodeCountFuzzTest(provider);
    return 0;
}

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

#include "ipcpayloadstatisticsimpl_fuzzer.h"
#include "ipc_payload_statistics_impl.h"

namespace OHOS {
void GetCountFuzzTest(FuzzedDataProvider &provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string desc = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string desc16(desc.begin(), desc.end());
    int32_t code = provider.ConsumeIntegral<int32_t>();
    uint32_t currentCost = provider.ConsumeIntegral<uint32_t>();
    IPCPayloadStatisticsImpl::GetInstance().isStatisticsFlag_ = true;
    IPCPayloadStatisticsImpl::GetInstance().UpdatePayloadInfo(pid, desc16, code, currentCost);
    IPCPayloadStatisticsImpl::GetInstance().GetCount(pid);
}

void GetCostFuzzTest(FuzzedDataProvider &provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string desc = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string desc16(desc.begin(), desc.end());
    int32_t code = provider.ConsumeIntegral<int32_t>();
    uint32_t currentCost = provider.ConsumeIntegral<uint32_t>();
    IPCPayloadStatisticsImpl::GetInstance().isStatisticsFlag_ = true;
    IPCPayloadStatisticsImpl::GetInstance().UpdatePayloadInfo(pid, desc16, code, currentCost);
    IPCPayloadStatisticsImpl::GetInstance().GetCost(pid);
}

void GetDescriptorCodesFuzzTest(FuzzedDataProvider &provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string desc = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string desc16(desc.begin(), desc.end());
    int32_t code = provider.ConsumeIntegral<int32_t>();
    uint32_t currentCost = provider.ConsumeIntegral<uint32_t>();
    IPCPayloadStatisticsImpl::GetInstance().isStatisticsFlag_ = true;
    IPCPayloadStatisticsImpl::GetInstance().UpdatePayloadInfo(pid, desc16, code, currentCost);
    IPCPayloadStatisticsImpl::GetInstance().GetDescriptorCodes(pid);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetCountFuzzTest(provider);
    OHOS::GetCostFuzzTest(provider);
    OHOS::GetDescriptorCodesFuzzTest(provider);
    return 0;
}

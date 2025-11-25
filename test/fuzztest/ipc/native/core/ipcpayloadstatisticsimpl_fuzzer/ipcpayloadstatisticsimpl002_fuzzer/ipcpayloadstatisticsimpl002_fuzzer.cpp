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
void GetPayloadInfoFuzzTest(FuzzedDataProvider &provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string desc = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string desc16(desc.begin(), desc.end());
    int32_t code = provider.ConsumeIntegral<int32_t>();
    uint32_t currentCost = provider.ConsumeIntegral<uint32_t>();
    IPCPayloadInfo payloadInfo;
    IPCPayloadStatisticsImpl::GetInstance().isStatisticsFlag_ = true;
    IPCPayloadStatisticsImpl::GetInstance().UpdatePayloadInfo(pid, desc16, code, currentCost);
    IPCPayloadStatisticsImpl::GetInstance().GetPayloadInfo(pid, desc16, code, payloadInfo);
}

void UpdatePayloadInfoFuzzTest001(FuzzedDataProvider &provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string desc = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string desc16(desc.begin(), desc.end());
    int32_t code = provider.ConsumeIntegral<int32_t>();
    uint32_t currentCost = provider.ConsumeIntegral<uint32_t>();
    IPCPayloadStatisticsImpl::GetInstance().isStatisticsFlag_ = true;
    IPCPayloadStatisticsImpl::GetInstance().UpdatePayloadInfo(pid, desc16, code, currentCost);
}

void UpdatePayloadInfoFuzzTest002(FuzzedDataProvider &provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string desc = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string desc16(desc.begin(), desc.end());
    int32_t code = provider.ConsumeIntegral<int32_t>();
    uint32_t currentCost = provider.ConsumeIntegral<uint32_t>();
    IPCPayloadStatisticsImpl::GetInstance().isStatisticsFlag_ = true;
    IPCPayloadStatisticsImpl::GetInstance().payloadStat_.emplace(pid, std::map<std::u16string, IPCPayloadInfo>());
    IPCPayloadStatisticsImpl::GetInstance().UpdatePayloadInfo(pid, desc16, code, currentCost);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetPayloadInfoFuzzTest(provider);
    OHOS::UpdatePayloadInfoFuzzTest001(provider);
    OHOS::UpdatePayloadInfoFuzzTest002(provider);
    return 0;
}

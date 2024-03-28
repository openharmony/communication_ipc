/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "ipc_payload_statistics.h"

namespace OHOS {

uint64_t IPCPayloadStatistics::GetTotalCount()
{
    return IPCPayloadStatisticsImpl::GetInstance().GetTotalCount();
}

uint64_t IPCPayloadStatistics::GetTotalCost()
{
    return IPCPayloadStatisticsImpl::GetInstance().GetTotalCost();
}

std::vector<int32_t> IPCPayloadStatistics::GetPids()
{
    return IPCPayloadStatisticsImpl::GetInstance().GetPids();
}

uint64_t IPCPayloadStatistics::GetCount(const int32_t pid)
{
    return IPCPayloadStatisticsImpl::GetInstance().GetCount(pid);
}

uint64_t IPCPayloadStatistics::GetCost(const int32_t pid)
{
    return IPCPayloadStatisticsImpl::GetInstance().GetCost(pid);
}

std::vector<IPCInterfaceInfo> IPCPayloadStatistics::GetDescriptorCodes(const int32_t pid)
{
    return IPCPayloadStatisticsImpl::GetInstance().GetDescriptorCodes(pid);
}

uint64_t IPCPayloadStatistics::GetDescriptorCodeCount(
    const int32_t pid, const std::u16string &desc, const int32_t code)
{
    return IPCPayloadStatisticsImpl::GetInstance().GetDescriptorCodeCount(pid, desc, code);
}

IPCPayloadCost IPCPayloadStatistics::GetDescriptorCodeCost(
    const int32_t pid, const std::u16string &desc, const int32_t code)
{
    return IPCPayloadStatisticsImpl::GetInstance().GetDescriptorCodeCost(pid, desc, code);
}

bool IPCPayloadStatistics::StartStatistics()
{
    return IPCPayloadStatisticsImpl::GetInstance().StartStatistics();
}

bool IPCPayloadStatistics::StopStatistics()
{
    return IPCPayloadStatisticsImpl::GetInstance().StopStatistics();
}

bool IPCPayloadStatistics::GetStatisticsStatus()
{
    return IPCPayloadStatisticsImpl::GetInstance().GetStatisticsStatus();
}

bool IPCPayloadStatistics::ClearStatisticsData()
{
    return IPCPayloadStatisticsImpl::GetInstance().ClearStatisticsData();
}
}  // namespace OHOS
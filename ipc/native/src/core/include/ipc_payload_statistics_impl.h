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

#ifndef OHOS_IPC_PAYLOAD_STATISTICS_IMPL_H
#define OHOS_IPC_PAYLOAD_STATISTICS_IMPL_H

#include <map>
#include <shared_mutex>
#include <string>
#include <vector>
#include <atomic>

namespace OHOS {

struct IPCInterfaceInfo {
    std::u16string desc;
    int32_t code;
};

struct IPCPayloadCost {
    uint64_t totalCost;
    uint32_t maxCost;
    uint32_t minCost;
    uint32_t averCost;
};

struct IPCPayloadInfo {
    IPCInterfaceInfo interface;
    IPCPayloadCost cost;
    uint64_t count;
};

class IPCPayloadStatisticsImpl {
public:
    static IPCPayloadStatisticsImpl& GetInstance();
    IPCPayloadStatisticsImpl();
    ~IPCPayloadStatisticsImpl();

    uint64_t GetTotalCount();
    uint64_t GetTotalCost();

    std::vector<int32_t> GetPids();
    uint64_t GetCount(const int32_t pid);
    uint64_t GetCost(const int32_t pid);

    std::vector<IPCInterfaceInfo> GetDescriptorCodes(const int32_t pid);
    uint64_t GetDescriptorCodeCount(const int32_t pid, const std::u16string &desc, const int32_t code);
    IPCPayloadCost GetDescriptorCodeCost(const int32_t pid, const std::u16string &desc, const int32_t code);

    bool StartStatistics();
    bool StopStatistics();
    bool GetStatisticsStatus();
    bool ClearStatisticsData();

    bool UpdatePayloadInfo(
        const int32_t pid, const std::u16string &desc, const int32_t code, const uint32_t currentCost);
private:
    bool GetPayloadInfo(
        const int32_t pid, const std::u16string &desc, const int32_t code, IPCPayloadInfo &payloadInfo);
    std::shared_mutex dataMutex_;
    std::map<int32_t, std::map<std::u16string, IPCPayloadInfo>> payloadStat_;
    std::atomic<bool> isStatisticsFlag_;
};
} // namespace OHOS
#endif // OHOS_IPC_PAYLOAD_STATISTICS_IMPL_H

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

#include "ipc_payload_statistics_impl.h"

#include "ipc_debug.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "string_ex.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_PAYLOAD_STATISTICS_IMPL, "IPCPayloadStatisticsImpl"};

IPCPayloadStatisticsImpl::IPCPayloadStatisticsImpl() : isStatisticsFlag_(false)
{
}

IPCPayloadStatisticsImpl::~IPCPayloadStatisticsImpl()
{
    std::unique_lock<std::shared_mutex> lockGuard(dataMutex_);
    payloadStat_.clear();
}

IPCPayloadStatisticsImpl& IPCPayloadStatisticsImpl::GetInstance()
{
    static IPCPayloadStatisticsImpl instance;
    return instance;
}

uint64_t IPCPayloadStatisticsImpl::GetTotalCount()
{
    uint64_t totalCount = 0;

    std::shared_lock<std::shared_mutex> lockGuard(dataMutex_);
    for (auto iterPid = payloadStat_.begin(); iterPid != payloadStat_.end(); ++iterPid) {
        auto &mapTmp = iterPid->second;
        for (auto iterDesc = mapTmp.begin(); iterDesc != mapTmp.end(); ++iterDesc) {
            totalCount += iterDesc->second.count;
        }
    }
    if (totalCount == 0) {
        ZLOGD(LOG_LABEL, "Statistics may not be enabled.");
    }

    return totalCount;
}

uint64_t IPCPayloadStatisticsImpl::GetTotalCost()
{
    uint64_t totalCost = 0;

    std::shared_lock<std::shared_mutex> lockGuard(dataMutex_);
    for (auto iterPid = payloadStat_.begin(); iterPid != payloadStat_.end(); ++iterPid) {
        auto &mapTmp = iterPid->second;
        for (auto iterDesc = mapTmp.begin(); iterDesc != mapTmp.end(); ++iterDesc) {
            totalCost += iterDesc->second.cost.totalCost;
        }
    }
    if (totalCost == 0) {
        ZLOGD(LOG_LABEL, "Statistics may not be enabled.");
    }

    return totalCost;
}

std::vector<int32_t> IPCPayloadStatisticsImpl::GetPids()
{
    std::vector<int32_t> vec;

    std::shared_lock<std::shared_mutex> lockGuard(dataMutex_);
    for (auto iterPid = payloadStat_.begin(); iterPid != payloadStat_.end(); ++iterPid) {
        vec.emplace_back(iterPid->first);
    }
    if (vec.size() == 0) {
        ZLOGD(LOG_LABEL, "Statistics may not be enabled.");
    }

    return vec;
}

uint64_t IPCPayloadStatisticsImpl::GetCount(const int32_t pid)
{
    uint64_t count = 0;

    std::shared_lock<std::shared_mutex> lockGuard(dataMutex_);
    auto iterPid = payloadStat_.find(pid);
    if (iterPid != payloadStat_.end()) {
        auto &mapTmp = iterPid->second;
        for (auto iterDesc = mapTmp.begin(); iterDesc != mapTmp.end(); ++iterDesc) {
            count += iterDesc->second.count;
        }
    } else {
        ZLOGD(LOG_LABEL, "There is no data corresponding to the current PID.");
    }

    return count;
}

uint64_t IPCPayloadStatisticsImpl::GetCost(const int32_t pid)
{
    uint64_t cost = 0;

    std::shared_lock<std::shared_mutex> lockGuard(dataMutex_);
    auto iterPid = payloadStat_.find(pid);
    if (iterPid != payloadStat_.end()) {
        auto &mapTmp = iterPid->second;
        for (auto iterDesc = mapTmp.begin(); iterDesc != mapTmp.end(); ++iterDesc) {
            cost += iterDesc->second.cost.totalCost;
        }
    } else {
        ZLOGD(LOG_LABEL, "There is no data corresponding to the current PID.");
    }

    return cost;
}

std::vector<IPCInterfaceInfo> IPCPayloadStatisticsImpl::GetDescriptorCodes(const int32_t pid)
{
    std::vector<IPCInterfaceInfo> vec;
    IPCInterfaceInfo info;

    std::shared_lock<std::shared_mutex> lockGuard(dataMutex_);
    auto iterPid = payloadStat_.find(pid);
    if (iterPid == payloadStat_.end()) {
        ZLOGD(LOG_LABEL, "There is no data corresponding to the current PID.");
        return vec;
    }
    auto &mapTmp = iterPid->second;
    for (auto iterDesc = mapTmp.begin(); iterDesc != mapTmp.end(); ++iterDesc) {
        vec.emplace_back(iterDesc->second.interface);
    }

    return vec;
}

uint64_t IPCPayloadStatisticsImpl::GetDescriptorCodeCount(
    const int32_t pid, const std::u16string &desc, const int32_t code)
{
    IPCPayloadInfo payloadInfo = {{u"", 0}, {0, 0, 0, 0}, 0};

    bool ret = GetPayloadInfo(pid, desc, code, payloadInfo);
    if (!ret) {
        ZLOGD(LOG_LABEL, "Failed to obtain the total number of count.");
    }
    return payloadInfo.count;
}

IPCPayloadCost IPCPayloadStatisticsImpl::GetDescriptorCodeCost(
    const int32_t pid, const std::u16string &desc, const int32_t code)
{
    IPCPayloadInfo payloadInfo = {{u"", 0}, {0, 0, 0, 0}, 0};
    IPCPayloadCost cost = { 0, 0, 0, 0 };

    bool ret = GetPayloadInfo(pid, desc, code, payloadInfo);
    if (!ret) {
        ZLOGD(LOG_LABEL, "Failed to obtain IPCPayloadCost.");
        return cost;
    }
    if (payloadInfo.count == 0) {
        ZLOGD(LOG_LABEL, "Divisor cannot be 0.");
        return cost;
    }

    payloadInfo.cost.averCost = payloadInfo.cost.totalCost / payloadInfo.count;
    return payloadInfo.cost;
}

bool IPCPayloadStatisticsImpl::GetPayloadInfo(
    const int32_t pid, const std::u16string &desc, const int32_t code, IPCPayloadInfo &payloadInfo)
{
    bool ret = false;

    std::shared_lock<std::shared_mutex> lockGuard(dataMutex_);
    auto iterPid = payloadStat_.find(pid);
    if (iterPid == payloadStat_.end()) {
        ZLOGD(LOG_LABEL, "There is no data corresponding to the current PID.");
        return ret;
    }

    auto &mapTmp = iterPid->second;
    for (auto iterDesc = mapTmp.begin(); iterDesc != mapTmp.end(); ++iterDesc) {
        if ((code == iterDesc->second.interface.code) && (desc == iterDesc->second.interface.desc)) {
            payloadInfo = iterDesc->second;
            ret = true;
            break;
        }
    }
    if (!ret) {
        ZLOGD(LOG_LABEL, "There is no corresponding descriptor and code in the current process.");
    }
    return ret;
}

bool IPCPayloadStatisticsImpl::StartStatistics()
{
    if (!isStatisticsFlag_) {
        std::unique_lock<std::shared_mutex> lockGuard(dataMutex_);
        payloadStat_.clear();
    } else {
        ZLOGD(LOG_LABEL, "Statistics have started, no need to start again.");
        return true;
    }

    isStatisticsFlag_ = true;
    return true;
}

bool IPCPayloadStatisticsImpl::StopStatistics()
{
    if (!isStatisticsFlag_) {
        ZLOGD(LOG_LABEL, "Statistics have been stopped, no need to stop again.");
        return true;
    }

    isStatisticsFlag_ = false;
    return true;
}

bool IPCPayloadStatisticsImpl::GetStatisticsStatus()
{
    return isStatisticsFlag_;
}

bool IPCPayloadStatisticsImpl::ClearStatisticsData()
{
    std::unique_lock<std::shared_mutex> lockGuard(dataMutex_);
    payloadStat_.clear();
    return true;
}

bool IPCPayloadStatisticsImpl::UpdatePayloadInfo(
    const int32_t pid, const std::u16string &desc, const int32_t code, const uint32_t currentCost)
{
    if (currentCost == 0 || !isStatisticsFlag_) {
        return false;
    }

    IPCPayloadInfo payloadInfo;
    std::u16string descTmp = desc;
    std::u16string descKey = descTmp + u"_" + Str8ToStr16(std::to_string(code));

    payloadInfo.interface.desc = desc;
    payloadInfo.interface.code = code;
    payloadInfo.count = 1; // Update the map once and increase the count once.
    payloadInfo.cost.totalCost = currentCost;
    payloadInfo.cost.maxCost = currentCost;
    payloadInfo.cost.minCost = currentCost;
    payloadInfo.cost.averCost = 0; // To improve performance, the average time consumption is not calculated.

    std::unique_lock<std::shared_mutex> lockGuard(dataMutex_);
    auto iterPid = payloadStat_.find(pid);
    if (iterPid == payloadStat_.end()) {
        std::map<std::u16string, IPCPayloadInfo> temp;
        temp.insert(std::make_pair(descKey, payloadInfo));
        payloadStat_.insert(std::make_pair(pid, temp));
        return true;
    }

    auto iterDesc = iterPid->second.find(descKey);
    if (iterDesc == iterPid->second.end()) {
        iterPid->second.insert(std::make_pair(descKey, payloadInfo));
        return true;
    }

    iterDesc->second.count++;
    iterDesc->second.cost.totalCost += currentCost;
    if (iterDesc->second.cost.maxCost < currentCost) {
        iterDesc->second.cost.maxCost = currentCost;
    }
    if (iterDesc->second.cost.minCost > currentCost) {
        iterDesc->second.cost.minCost = currentCost;
    }

    return true;
}
}  // namespace OHOS

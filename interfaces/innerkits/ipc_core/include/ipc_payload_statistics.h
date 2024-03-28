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

#ifndef OHOS_IPC_PAYLOAD_STATISTICS_H
#define OHOS_IPC_PAYLOAD_STATISTICS_H

#include "ipc_payload_statistics_impl.h"

namespace OHOS {
class IPCPayloadStatistics {
public:
    IPCPayloadStatistics() = default;
    ~IPCPayloadStatistics() = default;

    /**
     * @brief Obtain the total number of times the entire process has been processed.
     * @return Returns the total number of times the entire process has been retrieved.
     * @since 12
     */
    static uint64_t GetTotalCount();

    /**
     * @brief Obtain the total time spent on all processes.
     * @return Returns the total time spent on all processes.
     * @since 12
     */
    static uint64_t GetTotalCost();

    /**
     * @brief Obtain the PID of all processes as a whole.
     * @return Return a vector<int32_t>, which internally stores the PID of all processes obtained.
     * @since 12
     */
    static std::vector<int32_t> GetPids();

    /**
     * @brief Obtain the total number of times the corresponding process has been processed.
     * @param pid is the process number.
     * @return Return the total number of times the corresponding process has been processed.
     * @since 12
     */
    static uint64_t GetCount(const int32_t pid);

    /**
     * @brief Obtain the total time spent on the corresponding process.
     * @param pid is the process number.
     * @return Return the total time taken by the corresponding process.
     * @since 12
     */
    static uint64_t GetCost(const int32_t pid);

    /**
     * @brief Obtain the descriptor and code of the corresponding process.
     * @param pid is the process number.
     * @return Return a vector<IPCInterfaceInfo>, which contains all the descriptor and
     * code of the corresponding process in the container.
     * @since 12
     */
    static std::vector<IPCInterfaceInfo> GetDescriptorCodes(const int32_t pid);

    /**
     * @brief Obtain the number of times corresponding to the specified pid, decs, and code.
     * @param pid is the process number.
     * @param desc is the interface descriptor used for IPC communication.
     * @param code is the communication code used for IPC communication.
     * @return Return the number of times corresponding to the specified pid, decs, and code.
     * @since 12
     */
    static uint64_t GetDescriptorCodeCount(const int32_t pid, const std::u16string &desc, const int32_t code);

    /**
     * @brief Obtain the total time consumption corresponding to the specified pid, decs, and code.
     * @param pid is the process number.
     * @param desc is the interface descriptor used for IPC communication.
     * @param code is the communication code used for IPC communication.
     * @return Returns the total time consumption corresponding to the specified pid, decs, and code.
     * @since 12
     */
    static IPCPayloadCost GetDescriptorCodeCost(const int32_t pid, const std::u16string &desc, const int32_t code);

    /**
     * @brief Start IPC load statistics.
     * @return Returns <b>true</b> if the operation succeeds; return <b>false</b> Otherwise.
     * @since 12
     */
    static bool StartStatistics();

    /**
     * @brief Stop IPC load statistics.
     * @return Returns <b>true</b> if the operation succeeds; return <b>false</b> Otherwise.
     * @since 12
     */
    static bool StopStatistics();

    /**
     * @brief Obtain the current IPC load statistics status.
     * @return Returns <b>true</b> if the operation succeeds,Indicates that statistics are currently enabled;
     * return <b>false</b>,Indicates that the statistics have been stopped currently.
     * @since 12
     */
    static bool GetStatisticsStatus();

    /**
     * @brief Clear all the data that has already been counted.
     * @return Returns <b>true</b> if the operation succeeds; return <b>false</b> Otherwise.
     * @since 12
     */
    static bool ClearStatisticsData();
};
} // namespace OHOS
#endif // OHOS_IPC_PAYLOAD_STATISTICS_H
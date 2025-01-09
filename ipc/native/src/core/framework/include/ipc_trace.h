/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_IPC_TRACE_H
#define OHOS_IPC_IPC_TRACE_H

#include <string>

namespace OHOS {
class IPCTrace {
public:
    /**
     * @brief Check whether the ipc tag is enabled.
     * @return Return <b>true</b> if the rpc ipc is enabled; returns <b>false</b> otherwise.
     * @since 15
     */
    static bool IsEnabled();

    /**
     * @brief Trace the begin of a ipc context.
     * @param value Trace information of ipc.
     * @return void
     * @since 15
     */
    static void Start(const std::string &value);

    /**
     * @brief Trace the end of a ipc context.
     * @return void
     * @since 15
     */
    static void Finish();

    /**
     * @brief Trace the begin of an asynchronous context.
     * @param value Trace information, It must be the same as the value of
     * the 'FinishAsync' function parameter 'value'.
     * @param taskId Task identify, It must be the same as the value of the 'FinishAsync' function parameter 'taskId'.
     * @return void
     * @since 15
     */
    static void StartAsync(const std::string &value, int32_t taskId);

    /**
     * @brief Trace the end of an asynchronous context.
     * @param value Trace information, It must be the same as the value of
     * the 'StartAsync' function parameter 'value'.
     * @param taskId Task identify, It must be the same as the value of the 'StartAsync' function parameter 'taskId'.
     * @return void
     * @since 15
     */
    static void FinishAsync(const std::string &value, int32_t taskId);

private:
    static IPCTrace &GetInstance();
    IPCTrace();
    ~IPCTrace();
    IPCTrace(const IPCTrace &other) = delete;
    IPCTrace &operator=(const IPCTrace &other) = delete;
    IPCTrace(IPCTrace &&other) = delete;
    IPCTrace &operator=(IPCTrace &&other) = delete;

    void Load();
    void Unload();

    using IsTagEnabledFunc = bool(*)(uint64_t);
    using StartFunc = void(*)(uint64_t, const std::string &);
    using EndFunc = void(*)(uint64_t);
    using StartAsyncFunc = void(*)(uint64_t, const std::string &, int32_t);
    using EndAsyncFunc = void(*)(uint64_t, const std::string &, int32_t);

    static constexpr uint64_t HITRACE_TAG_RPC = (1ULL << 46);
    static std::string HITRACE_METER_SO_NAME;

    void *traceSoHandler_ = nullptr;
    IsTagEnabledFunc isTagEnabledFunc_ = nullptr;
    StartFunc startFunc_ = nullptr;
    EndFunc finishFunc_ = nullptr;
    StartAsyncFunc startAsyncFunc_ = nullptr;
    EndAsyncFunc finishAsyncFunc_ = nullptr;
};
} // namespace OHOS
#endif // OHOS_IPC_IPC_TRACE_H
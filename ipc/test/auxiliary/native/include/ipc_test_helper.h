/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_TEST_HELPER_H
#define OHOS_IPC_TEST_HELPER_H

#include <map>
#include <mutex>
#include <string>
#include <dirent.h>
#include <iostream>
#include <sys/types.h>
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
const static int INVALID_PID = -1;

class IPCTestHelper {
public:
    enum {
        IPC_TEST_SAMGR,
        IPC_TEST_SERVER,
        IPC_TEST_CLIENT,
        IPC_TEST_MSG_SERVER,
        IPC_TEST_MSG_CLIENT,
        IPC_TEST_SERVER_EXTRA,
        IPC_TEST_NONE = 0xFF,
    };

    IPCTestHelper() = default;
    ~IPCTestHelper();
    static const std::string &GetTestAppName(int appId);
    pid_t GetPidByName(std::string task_name);
    bool  GetChildPids(std::vector<pid_t> &childPids);

    pid_t StartExecutable(std::string name, std::string args = "");

    bool StopExecutable(pid_t pid);
    bool StopExecutable(std::string name);

    bool PrepareTestSuite();
    bool TearDownTestSuite();

    void AddTestAppPid(const std::string &appName, const int &pid);
    void RemoveTestAppPid(const std::string &appName);

    bool StartTestApp(int appId, const int &cmdId = 0);
    bool StopTestApp(int appId);

    pid_t GetTestAppPid(int appId);

    pid_t GetPid();
    uid_t GetUid();

    long GetCurrentTimeMs();

private:
    std::mutex mutex_;
    std::map<std::string, pid_t> testPids_;
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCTestHelper" };
};
} // namespace OHOS
#endif // OHOS_IPC_TEST_HELPER_H

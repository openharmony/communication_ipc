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

#include "ipc_test_helper.h"
#include <vector>
#include <csignal>
#include <fstream>
#include <string>
#include <securec.h>
#include <sys/time.h>
#include <unistd.h>
#include "ipc_debug.h"
#include "test_service_client.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
static const int MAX_NAME_LEN = 256;
static const int MAX_BUFFER_SIZE = 1024;
static const int SLEEP_TIME = 500000; // ms
static const int SECOND_TO_MS = 1000;
static const int ONE_SECOND = 1; // seconds
static const int MAX_CHECK_COUNT = 10;
static const int SIG_KILL = 9;

const std::string &IPCTestHelper::GetTestAppName(int appId)
{
    static std::map<unsigned int, std::string> appNames = {
        { IPC_TEST_NONE,          ""},
        { IPC_TEST_SAMGR,         "samgr" },
        { IPC_TEST_SERVER,        "ipc_server_test" },
        { IPC_TEST_SERVER_EXTRA,  "ipc_server_test_extra" },
        { IPC_TEST_CLIENT,        "ipc_client_test" },
        { IPC_TEST_MSG_SERVER,    "ipcmsg_server" },
        { IPC_TEST_MSG_CLIENT,    "ipcmsg_client" },
    };

    if (appNames.count(appId)) {
        return appNames[appId];
    }

    return appNames[IPC_TEST_NONE];
}

IPCTestHelper::~IPCTestHelper()
{
    TearDownTestSuite();
}

pid_t IPCTestHelper::GetPidByName(std::string task_name)
{
    struct dirent *ptr = nullptr;
    FILE *fp = nullptr;

    char filepath[MAX_NAME_LEN + 1];
    char curTaskName[MAX_NAME_LEN + 1];
    char buf[MAX_BUFFER_SIZE];
    pid_t pid = INVALID_PID;

    DIR *dir = opendir("/proc");
    if (dir == nullptr) {
        return pid;
    }

    for (;;) {
        ptr = readdir(dir);
        if (ptr == nullptr) {
            break;
        }

        if ((strcmp(ptr->d_name, ".") == 0) ||
            (strcmp(ptr->d_name, "..") == 0) ||
            (ptr->d_type != DT_DIR)) {
            continue;
        }

        if (sprintf_s(filepath, sizeof(filepath), "/proc/%s/status", ptr->d_name) <= 0) {
            ZLOGE(LABEL, "format file failed");
            closedir(dir);
            return INVALID_PID;
        }

        fp = fopen(filepath, "r");
        if (fp == nullptr) {
            continue;
        }

        if (fgets(buf, MAX_BUFFER_SIZE - 1, fp) == nullptr) {
            fclose(fp);
            continue;
        }

        if (sscanf_s(buf, "%*s %s", curTaskName, sizeof(curTaskName)) <= 0) {
            ZLOGE(LABEL, "could not find current task");
        }

        if (!strcmp(task_name.c_str(), curTaskName)) {
            if (sscanf_s(ptr->d_name, "%d", &pid) <= 0) {
                ZLOGE(LABEL, "could not find target task");
            }
        }

        fclose(fp);
    }

    closedir(dir);

    return pid;
}

bool IPCTestHelper::GetChildPids(std::vector<pid_t> &childPids)
{
    pid_t current = getpid();
    ZLOGI(LABEL, "current pid %d\n", current);
    const std::string taskPath = "/proc/" + std::to_string(current) + "/task";
    DIR *dir = opendir(taskPath.c_str());
    if (dir == nullptr) {
        return false;
    }
    struct dirent *ptr = nullptr;
    for (;;) {
        ptr = readdir(dir);
        if (ptr == nullptr) {
            break;
        }

        if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) {
            continue;
        }

        if (ptr->d_type != DT_DIR) {
            continue;
        }

        pid_t child = std::stoi(ptr->d_name);
        if (child == current) {
            continue;
        }

        childPids.push_back(child);
        ZLOGI(LABEL, "child pid %d", child);
    }

    closedir(dir);

    return true;
}

pid_t IPCTestHelper::StartExecutable(std::string name, std::string args)
{
    pid_t execPid;
    int checkCount = 0;
    const char *ld_library_path = getenv("LD_LIBRARY_PATH");

    if (ld_library_path != nullptr) {
        unsetenv("LD_LIBRARY_PATH");
    }

    std::string cmd1 = "chmod +x /system/bin/" + name;
    int res = system(cmd1.c_str());
    ZLOGI(LABEL, "%s, res = %d\n", cmd1.c_str(), res);

    // kill the program if the program is already exist.
    execPid = GetPidByName(name);
    StopExecutable(execPid);

    std::string cmd2 = name + " " + args + "&";
    res = system(cmd2.c_str());

    if (ld_library_path != nullptr) {
        setenv("LD_LIBRARY_PATH", ld_library_path, 1);
    }

    ZLOGI(LABEL, "%s res = %d\n", cmd2.c_str(), res);

    do {
        execPid = GetPidByName(name);
        sleep(ONE_SECOND);

        if (execPid != INVALID_PID) {
            break;
        }
    } while (checkCount++ < MAX_CHECK_COUNT);

    ZLOGI(LABEL, "start %s done, pid:%d\n", name.c_str(), execPid);
    return execPid;
}

bool IPCTestHelper::StopExecutable(pid_t pid)
{
    if (pid != INVALID_PID) {
        ZLOGI(LABEL, "kill pid = %d\n", pid);
        kill(pid, SIG_KILL);
    }

    return true;
}

bool IPCTestHelper::StopExecutable(std::string name)
{
    pid_t pid = GetPidByName(name);
    if (pid != INVALID_PID) {
        ZLOGI(LABEL, "%s pid = %d, kill it\n", name.c_str(), pid);
        kill(pid, SIG_KILL);
    }

    return true;
}

bool IPCTestHelper::PrepareTestSuite()
{
    pid_t pid = GetTestAppPid(IPC_TEST_SAMGR);
    if (pid == INVALID_PID) {
        usleep(SLEEP_TIME);
        pid = StartTestApp(IPC_TEST_SAMGR);
        ZLOGI(LABEL, "StartSystemServer done");
    }

    return (pid != INVALID_PID);
}

bool IPCTestHelper::TearDownTestSuite()
{
    for (auto it = testPids_.begin(); it != testPids_.end();) {
        ZLOGI(LABEL, "kill %s", it->first.c_str());
        StopExecutable(it->second);
        it = testPids_.erase(it);
    }

    return true;
}
void IPCTestHelper::AddTestAppPid(const std::string &appName, const int &pid)
{
    std::lock_guard<std::mutex> auto_lock(mutex_);
    testPids_.insert(std::make_pair(appName, pid));
}

void IPCTestHelper::RemoveTestAppPid(const std::string &appName)
{
    std::lock_guard<std::mutex> auto_lock(mutex_);
    auto it = testPids_.find(appName);
    if (it != testPids_.end()) {
        testPids_.erase(appName);
    }
}

bool IPCTestHelper::StartTestApp(int appId, const int &cmdId)
{
    int pid = INVALID_PID;
    std::string appName = GetTestAppName(appId);
    if (!appName.empty()) {
        if (cmdId > 0) {
            pid = StartExecutable(appName, std::to_string(cmdId));
        } else {
            pid = StartExecutable(appName);
        }
    }

    if (pid != INVALID_PID) {
        RemoveTestAppPid(appName); // should remove it if exist;
        AddTestAppPid(appName, pid);
    }

    ZLOGI(LABEL, "StartTestApp:%d cmdId=%d pid = %d", appId, cmdId, pid);
    return (pid != INVALID_PID);
}

bool IPCTestHelper::StopTestApp(int appId)
{
    std::string appName = GetTestAppName(appId);
    if (appName.empty()) {
        return false;
    }

    pid_t pid = GetTestAppPid(appId);
    if (pid != INVALID_PID) {
        pid = StopExecutable(pid);
        RemoveTestAppPid(appName);
        usleep(SLEEP_TIME);
    }

    return (pid != INVALID_PID);
}


pid_t IPCTestHelper::GetTestAppPid(int appId)
{
    ZLOGE(LABEL, "GetTestAppPid appId=%d", appId);
    int pid = INVALID_PID;
    std::string appName = GetTestAppName(appId);
    if (appName.empty()) {
        return INVALID_PID;
    }

    auto it = testPids_.find(appName);
    if (it != testPids_.end()) {
        pid = it->second;
    } else {
        pid = GetPidByName(appName);
    }

    ZLOGE(LABEL, "GetTestAppPid return pid=%d", pid);
    return pid;
}

pid_t IPCTestHelper::GetPid()
{
    pid_t pid = getpid();
    ZLOGI(LABEL, "return pid=%{public}d", pid);
    return pid;
}

uid_t IPCTestHelper::GetUid()
{
    uid_t uid = getuid();
    ZLOGI(LABEL, "return uid=%{public}d", uid);
    return uid;
}

long IPCTestHelper::GetCurrentTimeMs()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return tv.tv_sec * SECOND_TO_MS + tv.tv_usec / SECOND_TO_MS;
}
} // namespace OHOS

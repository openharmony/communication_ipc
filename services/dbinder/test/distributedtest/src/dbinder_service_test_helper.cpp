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

#include "dbinder_service_test_helper.h"
#include <sys/time.h>
#include <csignal>
#include <unistd.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <securec.h>
#include "ipc_types.h"
#include "hilog/log.h"
#include "log_tags.h"

using namespace OHOS;
using namespace OHOS::HiviewDFX;

#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DbinderTestHelper" };
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

pid_t GetPidByName(std::string taskName)
{
    DIR *dir = nullptr;
    struct dirent *ptr = nullptr;
    FILE *fp = nullptr;
    char filepath[PATH_LENGTH];
    char curTaskName[PATH_LENGTH];
    char buf[BUF_SIZE];
    pid_t pid = INVALID_PID;

    dir = opendir("/proc");
    if (dir == nullptr) {
        return pid;
    }
    while ((ptr = readdir(dir)) != nullptr) {
        if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
            continue;
        if (DT_DIR != ptr->d_type) {
            continue;
        }

        if (sprintf_s(filepath, sizeof(filepath), "/proc/%s/status", ptr->d_name) <= EOK) {
            DBINDER_LOGI("sprintf_s fail");
            closedir(dir);
            return INVALID_PID;
        }

        fp = fopen(filepath, "r");
        if (fp != nullptr) {
            if (fgets(buf, BUF_SIZE - 1, fp) == nullptr) {
                fclose(fp);
                continue;
            }
            if (sscanf_s(buf, "%*s %s", curTaskName, sizeof(curTaskName)) <= EOK) {
                DBINDER_LOGI("sscanf fail");
            }

            if (!strcmp(taskName.c_str(), curTaskName)) {
                if (sscanf_s(ptr->d_name, "%d", &pid) <= EOK) {
                    DBINDER_LOGI("sscanf fail");
                }
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return pid;
}

int GetChildPids(std::vector<pid_t> &childPids)
{
    pid_t current = getpid();
    DBINDER_LOGI("current pid %{public}d", current);
    const std::string TASK_PATH = "/proc/" + std::to_string(current) + "/task";
    DIR *dir = nullptr;
    struct dirent *ptr = nullptr;

    dir = opendir(TASK_PATH.c_str());
    if (dir != nullptr) {
        while ((ptr = readdir(dir)) != nullptr) {
            if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) {
                continue;
            }
            if (DT_DIR != ptr->d_type) {
                continue;
            }

            pid_t child = std::stoi(ptr->d_name);
            if (child == current) {
                continue;
            }
            childPids.push_back(child);
            DBINDER_LOGI("child pid %{public}d", child);
        }
        closedir(dir);
    }

    return ERR_NONE;
}

pid_t StartExecutable(std::string name, std::string args)
{
    const char *ldLibraryPath = getenv("LD_LIBRARY_PATH");
    if (ldLibraryPath != nullptr) {
        unsetenv("LD_LIBRARY_PATH");
    }
    pid_t pid = GetPidByName(name);
    if (pid != INVALID_PID) {
        DBINDER_LOGI("test.service is already started, do nothing");
        return pid;
    }

    std::string cmd1 = "chmod +x /data/test/" + name;
    int res = system(cmd1.c_str());
    DBINDER_LOGI("%{public}s res = %d, errno = %{public}d %{public}s", cmd1.c_str(), res, errno, strerror(errno));

    std::string cmd2 = "/data/test/" + name + " " + args + "&";
    res = system(cmd2.c_str());
    DBINDER_LOGI("%{public}s res = %{public}d", cmd2.c_str(), res);

    if (ldLibraryPath != nullptr) {
        setenv("LD_LIBRARY_PATH", ldLibraryPath, 1);
    }
    res = 0;
    while (pid == INVALID_PID && res < 10) { // 10:try-time to wait for exe start
        pid = GetPidByName(name);
        DBINDER_LOGI("StartExecutable pid = %{public}d && name = %{public}s", pid, name.c_str());
        usleep(100 * 1000); // 100:time-length 1000:time-unit
        res++;
    }

    DBINDER_LOGI("start %{public}s done", name.c_str());
    return GetPidByName(name);
}

void StopExecutable(pid_t pid)
{
    kill(pid, SIGKILL);
}

void StopExecutable(std::string name)
{
    pid_t pid = GetPidByName(name);
    DBINDER_LOGI("StopExecutable %{public}s pid = %{public}d, prepare to kill it", name.c_str(), pid);

    if (pid != INVALID_PID) {
        DBINDER_LOGI("%{public}s pid = %{public}d, kill it", name.c_str(), pid);
        kill(pid, SIGKILL);
    }
}

int StartDBinderServiceSARegistry()
{
    pid_t registryPid = GetPidByName(SYSTEM_ABILITY_MANAGER_NAME);
    if (registryPid != -1) {
        DBINDER_LOGI("SYSTEM_ABILITY_MANAGER_NAME Already Started pid=%{public}d", registryPid);
        return registryPid;
    }
    StartExecutable(SYSTEM_ABILITY_MANAGER_NAME);
    usleep(200 * 1000); // 100:200-length 1000:time-unit
    DBINDER_LOGI("Start SYSTEM_ABILITY_MANAGER_NAME done");
    return ERR_NONE;
}

void StopDBinderServiceSARegistry()
{
    StopExecutable(SYSTEM_ABILITY_MANAGER_NAME);
}

void StartDBinderServiceTestService()
{
    pid_t pid = StartExecutable(DBINDER_TEST_SERVICE_NAME);
    DBINDER_LOGE("DBINDER_TEST_SERVICE_NAME pid : %{public}d", pid);

    pid = StartExecutable(DBINDER_TEST_SERVICE_NAME_SECOND);
    DBINDER_LOGE("DBINDER_TEST_SERVICE_NAME_SECOND pid : %{public}d", pid);
}

void StopDBinderServiceTestService()
{
    StopExecutable(DBINDER_TEST_SERVICE_NAME);
    DBINDER_LOGE("Stop DBINDER_TEST_SERVICE_NAME");

    StopExecutable(DBINDER_TEST_SERVICE_NAME_SECOND);
    DBINDER_LOGE("Stop DBINDER_TEST_SERVICE_NAME_SECOND");
}

int SetCurrentTestCase(int caseNum)
{
    if (caseNum > DBINDER_TEST_START && caseNum < DBINDER_TEST_END) {
        printf("SetCurrentTestCase to : %d\n", caseNum);
        return g_currentTestCase = caseNum;
    }
    printf("SetCurrentTestCase to : %d\n", DBINDER_TEST_INIT);
    return DBINDER_TEST_INIT;
}

int GetCurrentTestCase(void)
{
    if (g_currentTestCase > DBINDER_TEST_START && g_currentTestCase < DBINDER_TEST_END) {
        printf("GetCurrentTestCase is : %d\n", g_currentTestCase);
        return g_currentTestCase;
    }
    printf("GetCurrentTestCase is : %d\n", DBINDER_TEST_INIT);
    return DBINDER_TEST_INIT;
}

int64_t GetCurrentTime()
{
    struct timeval timeInterval = {};
    gettimeofday(&timeInterval, nullptr);
    return timeInterval.tv_sec * SECOND_TO_MS + timeInterval.tv_usec / SECOND_TO_MS;
}

float GetSpeed(int64_t timeInterval, int size, int times)
{
    if (timeInterval == 0) {
        return 0;
    }
    float dataSize { times * size };
    float costTime { timeInterval };
    float speed = dataSize / costTime;
    return speed * SECOND_TO_MS / KB_TO_B;
}

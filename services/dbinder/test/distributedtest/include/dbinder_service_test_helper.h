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

#ifndef OHOS_DBINDER_SERVICE_TEST_HELPER_INCLUDE_H
#define OHOS_DBINDER_SERVICE_TEST_HELPER_INCLUDE_H

#include <sys/types.h>
#include <dirent.h>
#include <iostream>
#include <string>

const std::string DBINDER_TEST_SERVICE_NAME = "dbinder_test";
const std::string DBINDER_TEST_SERVICE_NAME_SECOND = "dbinder_send";
const std::string SYSTEM_ABILITY_MANAGER_NAME = "SaManager";

const int BUF_SIZE = 1024 * 4;
const int PATH_LENGTH = 1024 * 4;
const static int INVALID_PID = -1;
const static int SECOND_TO_MS = 1000;
const static int KB_TO_B = 1024;

enum {
    /*
     * Here's the list of DBinderService Test Case List.
     * This list should be used for Trans-Mock.
     */
    DBINDER_TEST_INIT = -1,
    DBINDER_TEST_START = 0,
    DBINDER_TEST_REGISTRY_001,
    DBINDER_TEST_REGISTRY_002,
    DBINDER_TEST_REGISTRY_003,
    DBINDER_TEST_REGISTRY_004,
    DBINDER_TEST_REMOTE_CALL_001,
    DBINDER_TEST_REMOTE_CALL_002,
    DBINDER_TEST_REMOTE_CALL_003,
    DBINDER_TEST_REMOTE_CALL_004,
    DBINDER_TEST_REMOTE_CALL_005,
    DBINDER_TEST_REMOTE_CALL_006,
    DBINDER_TEST_REMOTE_CALL_007,
    DBINDER_TEST_REMOTE_CALL_008,
    DBINDER_TEST_REMOTE_CALL_009,
    DBINDER_TEST_REMOTE_CALL_010,
    DBINDER_TEST_REMOTE_CALL_011,
    DBINDER_TEST_REMOTE_CALL_012,
    DBINDER_TEST_REMOTE_CALL_013,
    DBINDER_TEST_REMOTE_CALL_014,
    DBINDER_TEST_REMOTE_CALL_015,
    DBINDER_TEST_REMOTE_CALL_016,
    DBINDER_TEST_DEATH_RECIPIENT_001,
    DBINDER_TEST_DEATH_RECIPIENT_002,
    DBINDER_TEST_DEATH_RECIPIENT_003,
    DBINDER_TEST_DEATH_RECIPIENT_004,
    DBINDER_TEST_DEATH_RECIPIENT_005,
    DBINDER_TEST_DEATH_RECIPIENT_006,
    DBINDER_TEST_DEATH_RECIPIENT_007,
    DBINDER_TEST_RAW_DATA_001,
    DBINDER_TEST_RAW_DATA_002,
    DBINDER_TEST_RAW_DATA_003,
    DBINDER_TEST_RAW_DATA_004,
    DBINDER_TEST_RAW_DATA_005,
    DBINDER_TEST_RAW_DATA_006,
    DBINDER_TEST_TRACE_001,
    DBINDER_TEST_TRANS_STUB_001,
    DBINDER_TEST_FLUSH_COMMAND_001,
    DBINDER_TEST_END,
};

static int g_currentTestCase = DBINDER_TEST_INIT;

pid_t GetPidByName(std::string taskName);
int StartDBinderServiceSARegistry();
void StopDBinderServiceSARegistry();
void StartDBinderServiceTestService();
void StopDBinderServiceTestService();
int GetChildPids(std::vector<pid_t> &childPids);
pid_t StartExecutable(std::string name, std::string args = "");
void StopExecutable(pid_t pid);
void StopExecutable(std::string name);
int SetCurrentTestCase(int caseNum);
int GetCurrentTestCase(void);
int64_t GetCurrentTime();
float GetSpeed(int64_t timeInterval, int size, int times);

bool MakeIpLoop(void);
bool RevertIpLoop(void);

#endif // OHOS_DBINDER_SERVICE_TEST_HELPER_INCLUDE_H

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

#include <string>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "test_service_command.h"
#include "test_service_client.h"
#include "test_service_skeleton.h"
#include "if_system_ability_manager.h"
#include "log_tags.h"

using namespace OHOS;
using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCTestClient" };

std::vector<std::string> GetArgvOptions(int argc, char **argv)
{
    std::vector<std::string> argvOptions;
    for (int i = 1; i < argc; i++) {
        argvOptions.emplace_back(std::string(argv[i]));
    }
    return argvOptions;
}

int main(int argc, char *argv[])
{
    int result = 0;
    TestCommand commandId = TestCommand::TEST_CMD_SYNC_TRANS;
    if (argc > 1) {
        commandId = { atoi(argv[1]) };
    } else {
        ZLOGE(LABEL, "unknown command");
    }
    std::vector<std::string> argvOptions;
    argvOptions = GetArgvOptions(argc, argv);
    std::unique_ptr<TestServiceClient> testClient = std::make_unique<TestServiceClient>();
    if (testClient->ConnectService()) {
        return -1;
    }

    ZLOGE(LABEL, "commandId= : %{public}d", commandId);
    switch (commandId) {
        case TestCommand::TEST_CMD_SYNC_TRANS:
            testClient->StartSyncTransaction();
            break;
        case TestCommand::TEST_CMD_ASYNC_TRANS: {
            testClient->StartAsyncTransaction();
            break;
        }
        case TestCommand::TEST_CMD_PING_SERVICE: {
            testClient->StartPingService();
            break;
        }
        case TestCommand::TEST_CMD_GET_FOO_SERVICE: {
            testClient->StartGetFooService();
            break;
        }
        case TestCommand::TEST_CMD_TRANS_FILE_DESC: {
            testClient->StartTestFileDescriptor();
            break;
        }
        case TestCommand::TEST_CMD_LOOP_TRANSACTION: {
            constexpr int maxTestCount = 1000;
            testClient->StartLoopTest(maxTestCount);
            break;
        }
        case TestCommand::TEST_CMD_DUMP_SERVICE: {
            testClient->StartDumpService();
            break;
        }
        case TestCommand::TEST_CMD_ASYNC_DUMP_SERVICE: {
            testClient->StartAsyncDumpService();
            break;
        }
        default:
            ZLOGI(LABEL, "main arg error");
            break;
    }

    ZLOGE(LABEL, "get from service: %{public}d", result);
    IPCSkeleton::JoinWorkThread();
    return 0;
}

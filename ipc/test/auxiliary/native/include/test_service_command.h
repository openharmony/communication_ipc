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

#ifndef OHOS_IPC_TEST_SERVICE_COMMAND_H
#define OHOS_IPC_TEST_SERVICE_COMMAND_H

enum class TestCommand : int {
    TEST_CMD_NONE = 0,
    TEST_CMD_SYNC_TRANS = 1,
    TEST_CMD_ASYNC_TRANS = 2,
    TEST_CMD_PING_SERVICE = 3,
    TEST_CMD_GET_FOO_SERVICE = 4,
    TEST_CMD_TRANS_FILE_DESC = 5,
    TEST_CMD_TRANSACTION = 6,
    TEST_CMD_DUMP_SERVICE = 8,
    TEST_CMD_LOOP_TRANSACTION = 9,
    TEST_CMD_ASYNC_DUMP_SERVICE = 10,
};
#endif // OHOS_IPC_TEST_SERVICE_COMMAND_H

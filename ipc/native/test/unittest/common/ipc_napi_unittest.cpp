/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "napi_remote_object.h"
#include <unistd.h>
#include <securec.h>

using namespace testing::ext;

class IPCNapiTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCNapiTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void IPCNapiTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void IPCNapiTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void IPCNapiTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 * @tc.name: ipc_napi_001
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(IPCNapiTest, IPC_NAPI_TEST_001, TestSize.Level1)
{
    napi_env env_ = nullptr;
    OHOS::NAPI_CallingInfo oldCallingInfo;
    OHOS::CallingInfo callingInfo;

    (void)memset_s(&oldCallingInfo, sizeof(oldCallingInfo), 0, sizeof(oldCallingInfo));
    (void)memset_s(&callingInfo, sizeof(callingInfo), 0, sizeof(callingInfo));
    OHOS::NAPI_RemoteObject_getCallingInfo(callingInfo);
    OHOS::NAPI_RemoteObject_saveOldCallingInfo(env_, oldCallingInfo);
    OHOS::NAPI_RemoteObject_setNewCallingInfo(env_, callingInfo);
    OHOS::NAPI_RemoteObject_resetOldCallingInfo(env_, oldCallingInfo);
    EXPECT_EQ(callingInfo.callingPid, getpid());
    EXPECT_EQ(callingInfo.callingUid, 0);
}
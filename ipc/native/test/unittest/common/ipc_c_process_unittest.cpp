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

#include <nativetoken_kit.h>
#include <token_setproc.h>
#include <unistd.h>
#include "c_process.h"

using namespace testing::ext;

class IpcCProcessUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IpcCProcessUnitTest::SetUpTestCase()
{}

void IpcCProcessUnitTest::TearDownTestCase()
{}

void IpcCProcessUnitTest::SetUp()
{}

void IpcCProcessUnitTest::TearDown()
{}

static void InitTokenId(void)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = NULL,
        .acls = NULL,
        .processName = "com.ipc.test",
        .aplStr = "normal",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}

/**
 * @tc.name: CProcessCallingInfo
 * @tc.desc: Verify the CProcess calling info functions
 * @tc.type: FUNC
 */
HWTEST_F(IpcCProcessUnitTest, CProcessCallingInfo, TestSize.Level1)
{
    InitTokenId();
    uint64_t selfTokenId = GetSelfToekenId();
    EXPECT_EQ(GetCallingTokenId(), selfTokenId);
    EXPECT_EQ(GetFirstToekenId(), 0);
    EXPECT_EQ(GetCallingPid(), static_cast<uint64_t>(getpid()));
    EXPECT_EQ(GetCallingUid(), static_cast<uint64_t>(getuid()));
}
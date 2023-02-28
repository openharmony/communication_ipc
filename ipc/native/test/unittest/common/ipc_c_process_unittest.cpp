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
#include <securec.h>
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

static bool BytesAllocator(void *stringData, char **buffer, int32_t len)
{
    if (buffer == nullptr || len < 0) {
        return false;
    }
    if (len != 0) {
        *buffer = (char *)malloc(len);
        if (*buffer == nullptr) {
            return false;
        }
        (void)memset_s(*buffer, len, 0, len);
    }
    void **ptr = reinterpret_cast<void **>(stringData);
    if (ptr != nullptr) {
        *ptr = *buffer;
    }
    return true;
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

/**
 * @tc.name: SetMaxWorkThreadNum
 * @tc.desc: Verify set max work thread
 * @tc.type: FUNC
 */
HWTEST_F(IpcCProcessUnitTest, SetMaxWorkThreadNum, TestSize.Level1)
{
    EXPECT_EQ(true, SetMaxWorkThreadNum(3));
}

/**
 * @tc.name: CallingIdentity
 * @tc.desc: Verify reset and set calling identity
 * @tc.type: FUNC
 */
HWTEST_F(IpcCProcessUnitTest, CallingIdentity, TestSize.Level1)
{
    void *value = nullptr;
    bool ret = ResetCallingIdentity(reinterpret_cast<void *>(&value), BytesAllocator);
    EXPECT_EQ(true, ret);
    ret = SetCallingIdentity(reinterpret_cast<const char *>(value));
    EXPECT_EQ(false, ret);
    if (value != nullptr) {
        free(value);
    }
}

/**
 * @tc.name: IsLocalCalling
 * @tc.desc: Verify whether it is local calling
 * @tc.type: FUNC
 */
HWTEST_F(IpcCProcessUnitTest, IsLocalCalling, TestSize.Level1)
{
    EXPECT_EQ(true, IsLocalCalling());
}

/**
 * @tc.name: GetCallingDeviceID
 * @tc.desc: Get calling device ID
 * @tc.type: FUNC
 */
HWTEST_F(IpcCProcessUnitTest, GetCallingDeviceID, TestSize.Level1)
{
    void *value = nullptr;
    EXPECT_EQ(GetCallingDeviceID(value, BytesAllocator), true);
    if (value != nullptr) {
        free(value);
    }
}

/**
 * @tc.name: GetLocalDeviceID
 * @tc.desc: Get local device ID
 * @tc.type: FUNC
 */
HWTEST_F(IpcCProcessUnitTest, GetLocalDeviceID, TestSize.Level1)
{
    void *value = nullptr;
    EXPECT_EQ(GetLocalDeviceID(value, BytesAllocator), true);
    if (value != nullptr) {
        free(value);
    }
}
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
#include <gmock/gmock.h>

#include "databus_session_callback.h"
#include "ipc_types.h"
#include "mock_session_impl.h"

using namespace testing::ext;
using namespace OHOS;

namespace {
constexpr int UID_TEST = 100;
constexpr int PID_TEST = 200;
const std::string DEVICE_ID_TEST = "deviceidTest";
const std::string SESSION_NAME_TEST = "sessionNameTest";
const std::string PEER_SESSION_NAME_TEST = "PeersessionNameTest";
}

class DbSessionCallbackUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DbSessionCallbackUnitTest::SetUpTestCase()
{
}

void DbSessionCallbackUnitTest::TearDownTestCase()
{
}

void DbSessionCallbackUnitTest::SetUp() {}

void DbSessionCallbackUnitTest::TearDown() {}

/**
 * @tc.name: OnSessionOpenedTest001
 * @tc.desc: Verify the OnSessionOpened function
 * @tc.type: FUNC
 */
HWTEST_F(DbSessionCallbackUnitTest, OnSessionOpenedTest001, TestSize.Level1)
{
    std::shared_ptr<MockSessionImpl> session = std::make_shared<MockSessionImpl>();

    EXPECT_CALL(*session, GetChannelId())
        .Times(1)
        .WillOnce(testing::Return(-1));

    DatabusSessionCallback dbSessionCallback;
    int ret = dbSessionCallback.OnSessionOpened(session);
    EXPECT_EQ(ret, SESSION_WRONG_FD_ERR);
}

/**
 * @tc.name: OnSessionOpenedTest002
 * @tc.desc: Verify the OnSessionOpened function
 * @tc.type: FUNC
 */
HWTEST_F(DbSessionCallbackUnitTest, OnSessionOpenedTest002, TestSize.Level1)
{
    std::shared_ptr<MockSessionImpl> session = std::make_shared<MockSessionImpl>();

    EXPECT_CALL(*session, GetChannelId())
        .Times(1)
        .WillOnce(testing::Return(1));

    EXPECT_CALL(*session, IsServerSide())
        .Times(1)
        .WillOnce(testing::Return(false));

    DatabusSessionCallback dbSessionCallback;
    int ret = dbSessionCallback.OnSessionOpened(session);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: OnSessionOpenedTest003
 * @tc.desc: Verify the OnSessionOpened function
 * @tc.type: FUNC
 */
HWTEST_F(DbSessionCallbackUnitTest, OnSessionOpenedTest003, TestSize.Level1)
{
    std::shared_ptr<MockSessionImpl> session = std::make_shared<MockSessionImpl>();

    EXPECT_CALL(*session, GetChannelId())
        .WillRepeatedly(testing::Return(1));

    EXPECT_CALL(*session, IsServerSide())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*session, GetPeerPid())
        .WillRepeatedly(testing::Return(PID_TEST));

    EXPECT_CALL(*session, GetPeerUid())
        .WillRepeatedly(testing::Return(UID_TEST));

    EXPECT_CALL(*session, GetPeerDeviceId())
        .WillRepeatedly(testing::ReturnRef(DEVICE_ID_TEST));

    EXPECT_CALL(*session, GetMySessionName())
        .WillRepeatedly(testing::ReturnRef(SESSION_NAME_TEST));

    EXPECT_CALL(*session, GetPeerSessionName())
        .WillRepeatedly(testing::ReturnRef(PEER_SESSION_NAME_TEST));

    DatabusSessionCallback dbSessionCallback;
    int ret = dbSessionCallback.OnSessionOpened(session);

    char data[] = "testdata";
    ssize_t len = strlen(data);
    dbSessionCallback.OnBytesReceived(session, data, len);
    dbSessionCallback.OnSessionClosed(session);

    EXPECT_EQ(ret, SESSION_UNOPEN_ERR);
}

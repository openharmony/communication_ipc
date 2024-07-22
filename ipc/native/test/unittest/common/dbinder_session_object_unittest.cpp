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

#include "dbinder_session_object.h"
#include "ipc_types.h"

using namespace testing::ext;
using namespace OHOS;

namespace {
const uint64_t STUB_INDEX = 1;
const uint32_t TOKEN_ID = 1;
const int SOCKET_ID = 123;
const int PEER_PID = 5678;
const int PEER_UID = 1234;
}

class DBinderSessionObjectTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DBinderSessionObjectTest::SetUpTestCase()
{
}

void DBinderSessionObjectTest::TearDownTestCase()
{
}

void DBinderSessionObjectTest::SetUp()
{
}

void DBinderSessionObjectTest::TearDown()
{
}

/**
 * @tc.name: SetServiceNameTest001
 * @tc.desc: Verify the DBinderSessionObject::SetServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, SetServiceNameTest001, TestSize.Level1)
{
    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    DBinderSessionObject object(serviceName, serverDeviceId, STUB_INDEX, nullptr, TOKEN_ID);

    std::string name = "testname";
    object.SetServiceName(name);
    EXPECT_STREQ(name.c_str(), object.GetServiceName().c_str());
}

/**
 * @tc.name: SetDeviceIdTest001
 * @tc.desc: Verify the DBinderSessionObject::SetDeviceId function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, SetDeviceIdTest001, TestSize.Level1)
{
    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    DBinderSessionObject object(serviceName, serverDeviceId, STUB_INDEX, nullptr, TOKEN_ID);

    std::string deviceId = "testid";
    object.SetDeviceId(deviceId);
    EXPECT_STREQ(deviceId.c_str(), object.GetDeviceId().c_str());
}

/**
 * @tc.name: SetProxyTest001
 * @tc.desc: Verify the DBinderSessionObject::SetProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, SetProxyTest001, TestSize.Level1)
{
    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    IPCObjectProxy *testProxy = new IPCObjectProxy(1, u"testproxy");
    DBinderSessionObject object(serviceName, serverDeviceId, STUB_INDEX, nullptr, TOKEN_ID);

    object.SetProxy(testProxy);
    EXPECT_NE(object.GetProxy(), nullptr);
}

/**
 * @tc.name: GetFlatSessionLenTest001
 * @tc.desc: Verify the DBinderSessionObject::GetFlatSessionLen function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, GetFlatSessionLenTest001, TestSize.Level1)
{
    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    DBinderSessionObject object(serviceName, serverDeviceId, STUB_INDEX, nullptr, TOKEN_ID);

    uint32_t len = object.GetFlatSessionLen();
    EXPECT_EQ(sizeof(FlatDBinderSession), len);
}

/**
 * @tc.name: GetSessionBuffTest001
 * @tc.desc: Verify the DBinderSessionObject::GetSessionBuff function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, GetSessionBuffTest001, TestSize.Level1)
{
    DBinderSessionObject object("testserviceName", "testserverDeviceId", STUB_INDEX, nullptr, TOKEN_ID);

    auto buff = object.GetSessionBuff();
    EXPECT_NE(buff, nullptr);
}

/**
 * @tc.name: GetStubIndexTest001
 * @tc.desc: Verify the DBinderSessionObject::GetStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, GetStubIndexTest001, TestSize.Level1)
{
    DBinderSessionObject object("testserviceName", "testserverDeviceId", STUB_INDEX, nullptr, TOKEN_ID);

    uint64_t stubIndex = object.GetStubIndex();
    EXPECT_EQ(stubIndex, STUB_INDEX);
}

/**
 * @tc.name: GetTokenIdTest001
 * @tc.desc: Verify the DBinderSessionObject::GetTokenId function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, GetTokenIdTest001, TestSize.Level1)
{
    DBinderSessionObject object("testserviceName", "testserverDeviceId", STUB_INDEX, nullptr, TOKEN_ID);

    uint32_t tokenId = object.GetTokenId();
    EXPECT_EQ(tokenId, TOKEN_ID);
}

/**
 * @tc.name: SetSocketIdTest001
 * @tc.desc: Verify the DBinderSessionObject::SetSocketId and GetSocketId functions
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, SetSocketIdTest001, TestSize.Level1)
{
    DBinderSessionObject object("testserviceName", "testserverDeviceId", STUB_INDEX, nullptr, TOKEN_ID);

    object.SetSocketId(SOCKET_ID);
    EXPECT_EQ(object.GetSocketId(), SOCKET_ID);
}

/**
 * @tc.name: SetPeerPidTest001
 * @tc.desc: Verify the DBinderSessionObject::SetPeerPid and GetPeerPid functions
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, SetPeerPidTest001, TestSize.Level1)
{
    DBinderSessionObject object("testserviceName", "testserverDeviceId", STUB_INDEX, nullptr, TOKEN_ID);

    object.SetPeerPid(PEER_PID);
    EXPECT_EQ(object.GetPeerPid(), PEER_PID);
}

/**
 * @tc.name: SetPeerUidTest001
 * @tc.desc: Verify the DBinderSessionObject::SetPeerUid and GetPeerUid functions
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, SetPeerUidTest001, TestSize.Level1)
{
    DBinderSessionObject object("testserviceName", "testserverDeviceId", STUB_INDEX, nullptr, TOKEN_ID);

    object.SetPeerUid(PEER_UID);
    EXPECT_EQ(object.GetPeerUid(), PEER_UID);
}

/**
 * @tc.name: CloseDatabusSessionTest001
 * @tc.desc: Verify the DBinderSessionObject::CloseDatabusSession function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSessionObjectTest, CloseDatabusSessionTest001, TestSize.Level1)
{
    DBinderSessionObject object("testserviceName", "testserverDeviceId", STUB_INDEX, nullptr, TOKEN_ID);

    object.SetSocketId(SOCKET_ID);
    object.CloseDatabusSession();
    EXPECT_EQ(object.GetSocketId(), SOCKET_ID_INVALID);
}

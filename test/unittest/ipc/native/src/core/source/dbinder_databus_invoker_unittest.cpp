/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>

#include "buffer_object.h"
#include "dbinder_databus_invoker.h"
#include "dbinder_session_object.h"
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "mock_iremote_invoker.h"
#include "mock_iremote_object.h"
#include "sys_binder.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace {
const std::string DEVICE_ID_TEST = "deviceidTest";
const std::string SESSION_NAME_TEST = "sessionNameTest";
const std::string SERVICE_NAME_TEST = "serviceNameTest";
const int32_t TEST_HANDLE_INVALID = 0;
}

namespace OHOS {
class MockIPCProcessSkeleton : public IPCProcessSkeleton {
public:
    MockIPCProcessSkeleton() {}

    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton* ());
    MOCK_METHOD2(FindOrNewObject, sptr<IRemoteObject>(int handle, const dbinder_negotiation_data *data));
    MOCK_METHOD1(QueryCommAuthInfo, bool(AppAuthInfo &appAuthInfo));
    MOCK_METHOD2(StubAttachDBinderSession, bool(uint32_t handle, std::shared_ptr<DBinderSessionObject> object));
    MOCK_METHOD2(StubDetachDBinderSession, bool(uint32_t handle, uint32_t &tokenId));
};

class MockBufferObject : public BufferObject {
public:
    MOCK_METHOD1(GetSendBufferAndLock, char *(uint32_t size));
    MOCK_CONST_METHOD0(GetSendBufferWriteCursor, ssize_t());
    MOCK_CONST_METHOD0(GetSendBufferReadCursor, ssize_t());
};
} //namespace OHOS

class DbinderDataBusInvokerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DbinderDataBusInvokerTest::SetUpTestCase()
{
}

void DbinderDataBusInvokerTest::TearDownTestCase()
{
}

void DbinderDataBusInvokerTest::SetUp()
{
}

void DbinderDataBusInvokerTest::TearDown()
{
}

/**
 * @tc.name: AcquireHandle001
 * @tc.desc: Verify the AcquireHandle function when return true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AcquireHandle001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t handle = 0;
    bool res = testInvoker.AcquireHandle(handle);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: ReleaseHandle001
 * @tc.desc: Verify the ReleaseHandle function when return true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, ReleaseHandle001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t handle = TEST_HANDLE_INVALID;
    bool res = testInvoker.ReleaseHandle(handle);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: NewSessionOfBinderProxy001
 * @tc.desc: Verify the NewSessionOfBinderProxy function when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy001, TestSize.Level1)
{
    uint32_t handle = 0;

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.NewSessionOfBinderProxy(handle, nullptr);
    EXPECT_TRUE(res == nullptr);
}

/**
 * @tc.name: NewSessionOfBinderProxy002
 * @tc.desc: Verify the NewSessionOfBinderProxy function when session is valid
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy002, TestSize.Level1)
{
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (remoteSession != nullptr);
}

/**
 * @tc.name: NewSessionOfBinderProxy003
 * @tc.desc: Verify the NewSessionOfBinderProxy function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy003, TestSize.Level1)
{
    uint32_t handle = REGISTRY_HANDLE;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (ret == nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: NewSessionOfBinderProxy004
 * @tc.desc: Verify the NewSessionOfBinderProxy function when FindOrNewObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy004, TestSize.Level1)
{
    uint32_t handle = REGISTRY_HANDLE;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, FindOrNewObject(handle, nullptr))
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (ret == nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: NewSessionOfBinderProxy005
 * @tc.desc: Verify the NewSessionOfBinderProxy function
 * when GetProto function return IRemoteObject::IF_PROT_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy005, TestSize.Level1)
{
    uint32_t handle = REGISTRY_HANDLE;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();
    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();

    EXPECT_CALL(*instance, FindOrNewObject(handle, nullptr))
        .WillRepeatedly(testing::Return(proxy));

    EXPECT_CALL(*proxy, GetProto())
        .WillRepeatedly(testing::Return(IRemoteObject::IF_PROT_ERROR));

    current->instance_ = instance;
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (ret == nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: GetSessionForProxy001
 * @tc.desc: Verify the GetSessionForProxy function when sessionName is empty
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetSessionForProxy001, TestSize.Level1)
{
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();
    std::string sessionName;

    EXPECT_CALL(*proxy, GetSessionName())
        .WillRepeatedly(testing::Return(sessionName));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, DEVICE_ID_TEST);
    EXPECT_TRUE (ret == nullptr);
}

/**
 * @tc.name: GetSessionForProxy002
 * @tc.desc: Verify the GetSessionForProxy function
 * when InvokeListenThread function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetSessionForProxy002, TestSize.Level1)
{
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();
    EXPECT_CALL(*proxy, GetSessionName())
        .WillRepeatedly(testing::Return(SESSION_NAME_TEST));

    EXPECT_CALL(*proxy, InvokeListenThread(testing::_, testing::_))
        .WillRepeatedly(testing::Return(0));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, DEVICE_ID_TEST);
    EXPECT_TRUE (ret == nullptr);
}

/**
 * @tc.name: AuthSession2Proxy001
 * @tc.desc: Verify the AuthSession2Proxy function when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AuthSession2Proxy001, TestSize.Level1)
{
    uint32_t handle = 0;
    DBinderDatabusInvoker testInvoker;
    bool res = testInvoker.AuthSession2Proxy(handle, nullptr);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: QuerySessionOfBinderProxy001
 * @tc.desc: Verify the QuerySessionOfBinderProxy function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QuerySessionOfBinderProxy001, TestSize.Level1)
{
    uint32_t handle = 0;
    std::string serverName = SERVICE_NAME_TEST;
    std::string deviceId = DEVICE_ID_TEST;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(serverName, deviceId, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.QuerySessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE(res == nullptr);
}

/**
 * @tc.name: QueryClientSessionObjectTest001
 * @tc.desc: Verify the QueryClientSessionObject function when StubQueryDBinderSession function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryClientSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryClientSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryClientSessionObjectTest002
 * @tc.desc: Verify the QueryClientSessionObject function valid value
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryClientSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);
    bool ret = current->StubAttachDBinderSession(handle, remoteSession);
    EXPECT_TRUE(ret);

    std::shared_ptr<DBinderSessionObject> session = testInvoker.QueryClientSessionObject(handle);
    EXPECT_TRUE(session != nullptr);
}

/**
 * @tc.name: QueryClientSessionObjectTest003
 * @tc.desc: Verify the QueryClientSessionObject function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryClientSessionObjectTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryClientSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: QueryServerSessionObjectTest001
 * @tc.desc: Verify the QueryServerSessionObject function when sessionOfPeer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryServerSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryServerSessionObjectTest002
 * @tc.desc: Verify the QueryServerSessionObject function valid
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryServerSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);
    bool ret = current->ProxyAttachDBinderSession(handle, remoteSession);
    EXPECT_TRUE(ret);

    std::shared_ptr<DBinderSessionObject> session = testInvoker.QueryServerSessionObject(handle);
    EXPECT_TRUE(session != nullptr);
}

/**
 * @tc.name: QueryServerSessionObjectTest003
 * @tc.desc: Verify the QueryServerSessionObject function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryServerSessionObjectTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryServerSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: OnReceiveNewConnectionTest001
 * @tc.desc: Verify the OnReceiveNewConnection function when GetCurrent return valid value
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnReceiveNewConnectionTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();
    
    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(current));

    EXPECT_CALL(*instance, QueryCommAuthInfo(testing::_))
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*instance, StubDetachDBinderSession(testing::_, testing::_))
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*instance, StubAttachDBinderSession(testing::_, testing::_))
        .WillRepeatedly(testing::Return(true));

    current->instance_ = instance;
    int32_t socketId = 1;
    int peerPid = 1;
    int peerUid = 1;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid,
        peerName, networkId);
    EXPECT_FALSE(ret);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: OnReceiveNewConnectionTest002
 * @tc.desc: Verify the OnReceiveNewConnection function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnReceiveNewConnectionTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    int32_t socketId = 1;
    int peerPid = 1;
    int peerUid = 1;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid,
        peerName, networkId);
    EXPECT_FALSE(ret);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: OnReceiveNewConnectionTest003
 * @tc.desc: Verify the OnReceiveNewConnection function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnReceiveNewConnectionTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, QueryCommAuthInfo(testing::_))
        .WillRepeatedly(testing::Return(false));

    current->instance_ = instance;
    int32_t socketId = 1;
    int peerPid = 1;
    int peerUid = 1;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid,
        peerName, networkId);
    EXPECT_FALSE(ret);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}
/**
 * @tc.name: OnReceiveNewConnectionTest004
 * @tc.desc: Verify the OnReceiveNewConnection function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnReceiveNewConnectionTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, StubAttachDBinderSession(testing::_, testing::_))
        .WillRepeatedly(testing::Return(false));

    current->instance_ = instance;
    int32_t socketId = 1;
    int peerPid = 1;
    int peerUid = 1;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid,
        peerName, networkId);
    EXPECT_FALSE(ret);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}
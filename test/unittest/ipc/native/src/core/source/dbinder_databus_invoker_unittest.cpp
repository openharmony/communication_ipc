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
namespace OHOS {

namespace {
const std::string DEVICE_ID_TEST = "deviceidTest";
const std::string SESSION_NAME_TEST = "sessionNameTest";
const std::string SERVICE_NAME_TEST = "serviceNameTest";
const int32_t TEST_HANDLE_INVALID = 0;
const int32_t TEST_UINT_HANDLE_INVALID = 0;
const uint32_t TEST_HANDLE_VALID = 1;
const int32_t SOCKET_ID_TEST = 1;
const int PEER_PID_TEST = 1;
const int PEER_UID_TEST = 1;
}

class DbinderDataBusInvokerInterface {
public:
    DbinderDataBusInvokerInterface() {};
    virtual ~DbinderDataBusInvokerInterface() {};

    virtual sptr<IRemoteObject> FindOrNewObject(int handle, const dbinder_negotiation_data *dbinderData = nullptr) = 0;
    virtual bool QueryCommAuthInfo(AppAuthInfo &appAuthInfo) = 0;
    virtual bool StubAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object) = 0;
    virtual bool StubDetachDBinderSession(uint32_t handle, uint32_t &tokenId) = 0;
    virtual std::shared_ptr<DBinderSessionObject> StubQueryDBinderSession(uint32_t handle) = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual uint64_t ReadUint64() = 0;
    virtual bool WriteUint64(uint64_t value) = 0;
};
class DbinderDataBusInvokerMock : public DbinderDataBusInvokerInterface {
public:
    DbinderDataBusInvokerMock();
    ~DbinderDataBusInvokerMock() override;

    MOCK_METHOD2(FindOrNewObject, sptr<IRemoteObject>(int handle, const dbinder_negotiation_data *data));
    MOCK_METHOD1(QueryCommAuthInfo, bool(AppAuthInfo &appAuthInfo));
    MOCK_METHOD2(StubAttachDBinderSession, bool(uint32_t handle, std::shared_ptr<DBinderSessionObject> object));
    MOCK_METHOD2(StubDetachDBinderSession, bool(uint32_t handle, uint32_t &tokenId));
    MOCK_METHOD1(StubQueryDBinderSession, std::shared_ptr<DBinderSessionObject>(uint32_t handle));
    MOCK_METHOD1(WriteUint32, bool(uint32_t value));
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD0(ReadUint64, uint64_t());
    MOCK_METHOD1(WriteUint64, bool(uint64_t value));
};

static void *g_interface = nullptr;

DbinderDataBusInvokerMock::DbinderDataBusInvokerMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DbinderDataBusInvokerMock::~DbinderDataBusInvokerMock()
{
    g_interface = nullptr;
}

static DbinderDataBusInvokerInterface *GetDbinderDataBusInvokerInterface()
{
    return reinterpret_cast<DbinderDataBusInvokerInterface *>(g_interface);
}

extern "C" {
    sptr<IRemoteObject> IPCProcessSkeleton::FindOrNewObject(int handle, const dbinder_negotiation_data *dbinderData)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return nullptr;
        }
        return GetDbinderDataBusInvokerInterface()->FindOrNewObject(handle, dbinderData);
    }
    bool IPCProcessSkeleton::QueryCommAuthInfo(AppAuthInfo &appAuthInfo)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->QueryCommAuthInfo(appAuthInfo);
    }
    bool IPCProcessSkeleton::StubAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->StubAttachDBinderSession(handle, object);
    }
    bool IPCProcessSkeleton::StubDetachDBinderSession(uint32_t handle, uint32_t &tokenId)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->StubDetachDBinderSession(handle, tokenId);
    }
    std::shared_ptr<DBinderSessionObject> IPCProcessSkeleton::StubQueryDBinderSession(uint32_t handle)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return nullptr;
        }
        return GetDbinderDataBusInvokerInterface()->StubQueryDBinderSession(handle);
    }
    bool Parcel::WriteUint32(uint32_t value)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->WriteUint32(value);
    }
    bool Parcel::WriteString(const std::string &value)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->WriteString(value);
    }
    uint64_t Parcel::ReadUint64()
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->ReadUint64();
    }
    bool Parcel::WriteUint64(uint64_t value)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->WriteUint64(value);
    }
}

class MockBufferObject : public BufferObject {
public:
    MOCK_METHOD1(GetSendBufferAndLock, char *(uint32_t size));
    MOCK_CONST_METHOD0(GetSendBufferWriteCursor, ssize_t());
    MOCK_CONST_METHOD0(GetSendBufferReadCursor, ssize_t());
};

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
    int32_t handle = TEST_HANDLE_INVALID;
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
    current->instance_ = nullptr;
    current->exitFlag_ = true;
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_EQ(ret, nullptr);
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

    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    
    EXPECT_CALL(mock, FindOrNewObject).WillRepeatedly(testing::Return(nullptr));

    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_EQ(ret, nullptr);
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

    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();

    EXPECT_CALL(mock, FindOrNewObject).WillRepeatedly(testing::Return(proxy));
    EXPECT_CALL(*proxy, GetProto()).WillRepeatedly(testing::Return(IRemoteObject::IF_PROT_ERROR));

    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_EQ(ret, nullptr);
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
    EXPECT_EQ(ret, nullptr);
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
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(*proxy, GetSessionName()).WillRepeatedly(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(false));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, DEVICE_ID_TEST);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetSessionForProxy003
 * @tc.desc: Verify the GetSessionForProxy function
 * when InvokeListenThread function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetSessionForProxy003, TestSize.Level1)
{
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(*proxy, GetSessionName()).WillRepeatedly(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*proxy, InvokeListenThread(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, DEVICE_ID_TEST);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetSessionForProxy004
 * @tc.desc: Verify the GetSessionForProxy function
 * when InvokeListenThread function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetSessionForProxy004, TestSize.Level1)
{
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(*proxy, GetSessionName()).WillRepeatedly(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*proxy, InvokeListenThread(testing::_, testing::_)).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, ReadUint64()).WillRepeatedly(Return(0));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, DEVICE_ID_TEST);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetSessionForProxy005
 * @tc.desc: Verify the GetSessionForProxy function
 * when InvokeListenThread function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetSessionForProxy005, TestSize.Level1)
{
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(*proxy, GetSessionName()).WillRepeatedly(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*proxy, InvokeListenThread(testing::_, testing::_)).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, ReadUint64()).WillRepeatedly(Return(1));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, DEVICE_ID_TEST);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: AuthSession2Proxy001
 * @tc.desc: Verify the AuthSession2Proxy function when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AuthSession2Proxy001, TestSize.Level1)
{
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    DBinderDatabusInvoker testInvoker;
    bool res = testInvoker.AuthSession2Proxy(handle, nullptr);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: AuthSession2Proxy002
 * @tc.desc: Verify the AuthSession2Proxy function when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AuthSession2Proxy002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(false));

    bool res = testInvoker.AuthSession2Proxy(handle, remoteSession);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: AuthSession2Proxy003
 * @tc.desc: Verify the AuthSession2Proxy function when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AuthSession2Proxy003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillRepeatedly(Return(true));

    bool res = testInvoker.AuthSession2Proxy(handle, remoteSession);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: QuerySessionOfBinderProxy001
 * @tc.desc: Verify the QuerySessionOfBinderProxy function when remoteSession is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QuerySessionOfBinderProxy001, TestSize.Level1)
{
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    std::string serverName = SERVICE_NAME_TEST;
    std::string deviceId = DEVICE_ID_TEST;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(serverName, deviceId, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    NiceMock<DbinderDataBusInvokerMock> mock;
    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(false));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.QuerySessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE(res == nullptr);
}

/**
 * @tc.name: QuerySessionOfBinderProxy002
 * @tc.desc: Verify the QuerySessionOfBinderProxy function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QuerySessionOfBinderProxy002, TestSize.Level1)
{
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
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
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, StubQueryDBinderSession(testing::_)).WillRepeatedly(testing::Return(nullptr));

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
    uint32_t handle = TEST_HANDLE_VALID;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, StubQueryDBinderSession(testing::_)).WillRepeatedly(testing::Return(remoteSession));

    std::shared_ptr<DBinderSessionObject> session = testInvoker.QueryClientSessionObject(handle);
    EXPECT_TRUE(session == remoteSession);
}

/**
 * @tc.name: QueryClientSessionObjectTest003
 * @tc.desc: Verify the QueryClientSessionObject function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryClientSessionObjectTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;
    
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryClientSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
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
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
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
    uint32_t handle = TEST_HANDLE_VALID;
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
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryServerSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
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
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, QueryCommAuthInfo(testing::_)).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StubDetachDBinderSession(testing::_, testing::_)).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StubAttachDBinderSession(testing::_, testing::_)).WillRepeatedly(testing::Return(true));

    int32_t socketId = SOCKET_ID_TEST;
    int peerPid = PEER_PID_TEST;
    int peerUid = PEER_UID_TEST;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, networkId);
    EXPECT_TRUE(ret);
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
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    int32_t socketId = SOCKET_ID_TEST;
    int peerPid = PEER_PID_TEST;
    int peerUid = PEER_UID_TEST;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, networkId);
    EXPECT_FALSE(ret);
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
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, QueryCommAuthInfo(testing::_)).WillRepeatedly(testing::Return(false));

    int32_t socketId = SOCKET_ID_TEST;
    int peerPid = PEER_PID_TEST;
    int peerUid = PEER_UID_TEST;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, networkId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnReceiveNewConnectionTest004
 * @tc.desc: Verify the OnReceiveNewConnection function when StubAttachDBinderSession function return false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnReceiveNewConnectionTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, QueryCommAuthInfo(testing::_)).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, StubAttachDBinderSession(testing::_, testing::_)).WillRepeatedly(testing::Return(false));

    int32_t socketId = SOCKET_ID_TEST;
    int peerPid = PEER_PID_TEST;
    int peerUid = PEER_UID_TEST;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, networkId);
    EXPECT_FALSE(ret);
}
} //namespace OHOS
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
#include <cstring>
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
const std::string PEER_PID_INVALID_TEST = "DBinder456_123456789011";
const std::string PEER_UID_INVALID_TEST = "DBinder123456789011_456";
const std::string IDENTITY_SHORT_TEST = "123456";
const std::string TOKEN_ID_STR = "1234567890";
const char DATA_TEST[] = "test data";
constexpr int32_t TEST_HANDLE_INVALID = 0;
constexpr int32_t TEST_UINT_HANDLE_INVALID = 0;
constexpr uint32_t TEST_HANDLE_VALID = 1;
constexpr int32_t SOCKET_ID_TEST = 1;
constexpr int PEER_PID_TEST = 1;
constexpr int PEER_UID_TEST = 1;
constexpr uint64_t STUB_INDEX = 1;
constexpr uint32_t TOKEN_ID = 1;
constexpr int32_t SOCKET_ID_INVALID_TEST = 0;
constexpr int ACCESS_TOKEN_MAX_LEN = 10;
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
    virtual int GetSocketIdleThreadNum() = 0;
    virtual char *GetSendBufferAndLock(uint32_t size) = 0;
    virtual std::shared_ptr<BufferObject> GetSessionBuff() = 0;
    virtual int32_t SendBytes(int32_t socket, const void *data, uint32_t len) = 0;
    virtual ssize_t GetSendBufferWriteCursor() = 0;
    virtual ssize_t GetSendBufferReadCursor() = 0;
    virtual std::string GetDeviceId() = 0;
    virtual std::string GetServiceName() = 0;
    virtual bool QueryProxyBySocketId(int32_t socketId, std::vector<uint32_t> &proxyHandle) = 0;
    virtual std::list<uint64_t> DetachAppAuthInfoBySocketId(int32_t socketId) = 0;
    virtual IRemoteObject *QueryStubByIndex(uint64_t stubIndex) = 0;
    virtual bool QueryAppInfoToStubIndex(const AppAuthInfo &appAuthInfo) = 0;
    virtual bool IsContainsObject(IRemoteObject *object) = 0;
    virtual uint64_t AddStubByIndex(IRemoteObject *stubObject) = 0;
    virtual std::string GetDatabusName() = 0;
    virtual int32_t CreateClientSocket(
        const std::string &ownName, const std::string &peerName, const std::string &networkId) = 0;
    virtual bool IsNumStr(const std::string &str) = 0;
    virtual std::string GetLocalDeviceID() = 0;
    virtual bool AttachOrUpdateAppAuthInfo(const AppAuthInfo &appAuthInfo) = 0;
    virtual bool StrToUint64(const std::string &str, uint64_t &value) = 0;
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
    MOCK_METHOD0(GetSocketIdleThreadNum, int());
    MOCK_METHOD0(GetSessionBuff, std::shared_ptr<BufferObject>());
    MOCK_METHOD1(GetSendBufferAndLock, char *(uint32_t size));
    MOCK_METHOD3(SendBytes, int32_t(int32_t socket, const void *data, uint32_t len));
    MOCK_METHOD0(GetSendBufferWriteCursor, ssize_t());
    MOCK_METHOD0(GetSendBufferReadCursor, ssize_t());
    MOCK_METHOD0(GetDeviceId, std::string());
    MOCK_METHOD0(GetServiceName, std::string());
    MOCK_METHOD2(QueryProxyBySocketId, bool(int32_t socketId, std::vector<uint32_t> &proxyHandle));
    MOCK_METHOD1(DetachAppAuthInfoBySocketId, std::list<uint64_t>(int32_t socketId));
    MOCK_METHOD1(QueryStubByIndex, IRemoteObject *(uint64_t stubIndex));
    MOCK_METHOD1(QueryAppInfoToStubIndex, bool(const AppAuthInfo &appAuthInfo));
    MOCK_METHOD1(IsContainsObject, bool(IRemoteObject *object));
    MOCK_METHOD1(AddStubByIndex, uint64_t(IRemoteObject *stubObject));
    MOCK_METHOD0(GetDatabusName, std::string());
    MOCK_METHOD1(IsNumStr, bool(const std::string &str));
    MOCK_METHOD3(CreateClientSocket, int32_t(
        const std::string &ownName, const std::string &peerName, const std::string &networkId));
    MOCK_METHOD0(GetLocalDeviceID, std::string());
    MOCK_METHOD1(AttachOrUpdateAppAuthInfo, bool(const AppAuthInfo &appAuthInfo));
    MOCK_METHOD2(StrToUint64, bool(const std::string &str, uint64_t &value));
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
    int IPCProcessSkeleton::GetSocketIdleThreadNum() const
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return 0;
        }
        return GetDbinderDataBusInvokerInterface()->GetSocketIdleThreadNum();
    }
    std::shared_ptr<BufferObject> DBinderSessionObject::GetSessionBuff()
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return nullptr;
        }
        return GetDbinderDataBusInvokerInterface()->GetSessionBuff();
    }
    char *BufferObject::GetSendBufferAndLock(uint32_t size)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return nullptr;
        }
        return GetDbinderDataBusInvokerInterface()->GetSendBufferAndLock(size);
    }
    int32_t DBinderSoftbusClient::SendBytes(int32_t socket, const void *data, uint32_t len)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return 0;
        }
        return GetDbinderDataBusInvokerInterface()->SendBytes(socket, data, len);
    }
    ssize_t BufferObject::GetSendBufferReadCursor() const
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return 0;
        }
        return GetDbinderDataBusInvokerInterface()->GetSendBufferReadCursor();
    }
    ssize_t BufferObject::GetSendBufferWriteCursor() const
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return 0;
        }
        return GetDbinderDataBusInvokerInterface()->GetSendBufferWriteCursor();
    }
    std::string DBinderSessionObject::GetDeviceId() const
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return "";
        }
        return GetDbinderDataBusInvokerInterface()->GetDeviceId();
    }
    std::string DBinderSessionObject::GetServiceName() const
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return "";
        }
        return GetDbinderDataBusInvokerInterface()->GetServiceName();
    }
    bool IPCProcessSkeleton::QueryAppInfoToStubIndex(const AppAuthInfo &appAuthInfo)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->QueryAppInfoToStubIndex(appAuthInfo);
    }
    bool IPCProcessSkeleton::IsContainsObject(IRemoteObject *object)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->IsContainsObject(object);
    }
    uint64_t IPCProcessSkeleton::AddStubByIndex(IRemoteObject *stubObject)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return 0;
        }
        return GetDbinderDataBusInvokerInterface()->AddStubByIndex(stubObject);
    }
    IRemoteObject *IPCProcessSkeleton::QueryStubByIndex(uint64_t stubIndex)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return nullptr;
        }
        return GetDbinderDataBusInvokerInterface()->QueryStubByIndex(stubIndex);
    }
    bool IPCProcessSkeleton::QueryProxyBySocketId(int32_t socketId, std::vector<uint32_t> &proxyHandle)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->QueryProxyBySocketId(socketId, proxyHandle);
    }
    std::list<uint64_t> IPCProcessSkeleton::DetachAppAuthInfoBySocketId(int32_t socketId)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return std::list<uint64_t>();
        }
        return GetDbinderDataBusInvokerInterface()->DetachAppAuthInfoBySocketId(socketId);
    }
    std::string IPCProcessSkeleton::GetDatabusName()
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return "";
        }
        return GetDbinderDataBusInvokerInterface()->GetDatabusName();
    }
    int32_t DatabusSocketListener::CreateClientSocket(const std::string &ownName, const std::string &peerName,
        const std::string &networkId)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return 0;
        }
        return GetDbinderDataBusInvokerInterface()->CreateClientSocket(ownName, peerName, networkId);
    }
    bool ProcessSkeleton::IsNumStr(const std::string &str)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->IsNumStr(str);
    }
    std::string IPCProcessSkeleton::GetLocalDeviceID()
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return "";
        }
        return GetDbinderDataBusInvokerInterface()->GetLocalDeviceID();
    }
    bool IPCProcessSkeleton::AttachOrUpdateAppAuthInfo(const AppAuthInfo &appAuthInfo)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->AttachOrUpdateAppAuthInfo(appAuthInfo);
    }
    bool ProcessSkeleton::StrToUint64(const std::string &str, uint64_t &value)
    {
        if (GetDbinderDataBusInvokerInterface() == nullptr) {
            return false;
        }
        return GetDbinderDataBusInvokerInterface()->StrToUint64(str, value);
    }
}

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
 * @tc.desc: Verify the GetSessionForProxy function when WriteUint32 function return false
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
 * @tc.desc: Verify the GetSessionForProxy function when InvokeListenThread function return 1
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
    EXPECT_CALL(*proxy, InvokeListenThread(testing::_, testing::_)).WillRepeatedly(testing::Return(1));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, DEVICE_ID_TEST);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetSessionForProxy004
 * @tc.desc: Verify the GetSessionForProxy function when ReadUint64 function return 0
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
    EXPECT_CALL(*proxy, InvokeListenThread(testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(mock, ReadUint64()).WillRepeatedly(Return(0));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, DEVICE_ID_TEST);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetSessionForProxy005
 * @tc.desc: Verify the GetSessionForProxy function when ReadUint64 function return 1
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
    EXPECT_CALL(*proxy, InvokeListenThread(testing::_, testing::_)).WillRepeatedly(testing::Return(0));
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

/**
 * @tc.name: CreateProcessThreadTest001
 * @tc.desc: Verify the CreateProcessThread function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateProcessThreadTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    bool ret = testInvoker.CreateProcessThread();
    EXPECT_FALSE(ret);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: CreateProcessThreadTest002
 * @tc.desc: Verify the CreateProcessThread function when GetSocketIdleThreadNum function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateProcessThreadTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetSocketIdleThreadNum()).WillRepeatedly(testing::Return(0));

    bool ret = testInvoker.CreateProcessThread();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CreateProcessThreadTest003
 * @tc.desc: Verify the CreateProcessThread function when GetSocketIdleThreadNum function return 1
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateProcessThreadTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetSocketIdleThreadNum()).WillRepeatedly(testing::Return(1));

    bool ret = testInvoker.CreateProcessThread();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: OnRawDataAvailableTest001
 * @tc.desc: Verify the OnRawDataAvailable function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnRawDataAvailableTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;
    
    int32_t socketId = SOCKET_ID_TEST;
    uint32_t dataSize = sizeof(DATA_TEST);
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnRawDataAvailable(socketId, DATA_TEST, dataSize));
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: OnMessageAvailableTest001
 * @tc.desc: Verify the OnMessageAvailable function
 * when socketId is 0 or data is nullptr or len is greater than MAX_RAWDATA_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnMessageAvailableTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    ssize_t len = 0;
    int32_t socketId = SOCKET_ID_TEST;
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnMessageAvailable(-1, DATA_TEST, len));
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnMessageAvailable(socketId, nullptr, len));
    len = static_cast<ssize_t>(MAX_RAWDATA_SIZE) + 1;
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnMessageAvailable(socketId, DATA_TEST, len));
}

/**
 * @tc.name: OnMessageAvailableTest002
 * @tc.desc: Verify the OnMessageAvailable function when HasRawDataPackage function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnMessageAvailableTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t socketId = SOCKET_ID_TEST;
    char data[sizeof(dbinder_transaction_data)] = {0};
    ssize_t len = sizeof(data);
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnMessageAvailable(socketId, DATA_TEST, len));
}

/**
 * @tc.name: OnMessageAvailableTest003
 * @tc.desc: Verify the OnMessageAvailable function when HasRawDataPackage function return greater than 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnMessageAvailableTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t socketId = SOCKET_ID_TEST;
    dbinder_transaction_data tr = {0};
    tr.sizeOfSelf = sizeof(tr);
    tr.magic = DBINDER_MAGICWORD;
    tr.cmd = BC_SEND_RAWDATA;
    char data[sizeof(tr)];
    memcpy_s(data, sizeof(data), &tr, sizeof(tr));
    ssize_t len = sizeof(data);
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnMessageAvailable(socketId, DATA_TEST, len));
}

/**
 * @tc.name: HasRawDataPackageTest001
 * @tc.desc: Verify the HasRawDataPackage function when data is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, HasRawDataPackageTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    dbinder_transaction_data tr = {0};
    tr.sizeOfSelf = sizeof(tr);
    tr.magic = DBINDER_MAGICWORD;
    tr.cmd = BC_SEND_RAWDATA;
    char data[sizeof(tr)];
    memcpy_s(data, sizeof(data), &tr, sizeof(tr));
    ssize_t len = sizeof(data);
    uint32_t result = testInvoker.HasRawDataPackage(data, len);
    EXPECT_EQ(result, tr.sizeOfSelf);
}

/**
 * @tc.name: HasRawDataPackageTest002
 * @tc.desc: Verify the HasRawDataPackage function when tr.magic and tr.cmd are invalid value
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, HasRawDataPackageTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    dbinder_transaction_data tr = {0};
    tr.sizeOfSelf = sizeof(tr);
    tr.magic = 0xDEADBEEF;
    tr.cmd = 0x1234;
    char data[sizeof(tr)];
    memcpy_s(data, sizeof(data), &tr, sizeof(tr));
    ssize_t len = sizeof(data);
    uint32_t result = testInvoker.HasRawDataPackage(data, len);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: HasRawDataPackageTest003
 * @tc.desc: Verify the HasRawDataPackage function when tr.sizeOfSelf greater than MAX_RAWDATA_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, HasRawDataPackageTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    dbinder_transaction_data tr = {0};
    tr.sizeOfSelf = MAX_RAWDATA_SIZE + 1;
    tr.magic = DBINDER_MAGICWORD;
    tr.cmd = BC_SEND_RAWDATA;
    char data[sizeof(tr)];
    memcpy_s(data, sizeof(data), &tr, sizeof(tr));
    ssize_t len = sizeof(data);
    uint32_t result = testInvoker.HasRawDataPackage(data, len);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: OnSendMessageTest001
 * @tc.desc: Verify the OnSendMessage function when sessionOfPeer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnSendMessageTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = nullptr;
    int result = testInvoker.OnSendMessage(sessionOfPeer);
    EXPECT_EQ(result, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendMessageTest002
 * @tc.desc: Verify the OnSendMessage function when socketId is less than or equal to 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnSendMessageTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto sessionOfPeer = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    sessionOfPeer->SetSocketId(0);
    int result = testInvoker.OnSendMessage(sessionOfPeer);
    EXPECT_EQ(result, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendMessageTest003
 * @tc.desc: Verify the OnSendMessage function when sessionBuff is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnSendMessageTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto sessionOfPeer = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    sessionOfPeer->SetSocketId(1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetSessionBuff()).WillOnce(testing::Return(nullptr));
    int result = testInvoker.OnSendMessage(sessionOfPeer);
    EXPECT_EQ(result, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendMessageTest004
 * @tc.desc: Verify the OnSendMessage function when GetSendBufferAndLock function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnSendMessageTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto sessionOfPeer = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    sessionOfPeer->SetSocketId(1);
    auto sessionBuff = std::make_shared<BufferObject>();
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetSessionBuff()).WillOnce(testing::Return(sessionBuff));
    EXPECT_CALL(mock, GetSendBufferAndLock(testing::_)).WillRepeatedly(testing::Return(nullptr));

    int result = testInvoker.OnSendMessage(sessionOfPeer);
    EXPECT_EQ(result, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendDataTest001
 * @tc.desc: Verify the SendData function when GetSendBufferAndLock function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SendDataTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    auto sessionBuff = std::make_shared<BufferObject>();

    EXPECT_CALL(mock, GetSendBufferAndLock(testing::_)).WillRepeatedly(testing::Return(nullptr));

    int result = testInvoker.SendData(sessionBuff, SOCKET_ID_TEST);
    EXPECT_EQ(result, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendDataTest002
 * @tc.desc: Verify the SendData function when the return value of function GetSendBufferWriteCursor
 * is less than to the return value of function GetSendBufferReadCursor
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SendDataTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    auto sessionBuff = std::make_shared<BufferObject>();
    char sendBuffer[1024] = {0};

    EXPECT_CALL(mock, GetSendBufferAndLock(testing::_)).WillOnce(testing::Return(sendBuffer));
    EXPECT_CALL(mock, GetSendBufferWriteCursor()).WillOnce(testing::Return(0));
    EXPECT_CALL(mock, GetSendBufferReadCursor()).WillOnce(testing::Return(1024));

    int result = testInvoker.SendData(sessionBuff, SOCKET_ID_TEST);
    EXPECT_EQ(result, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendDataTest003
 * @tc.desc: Verify the SendData function when the return value of function GetSendBufferWriteCursor
 * is equal to the return value of function GetSendBufferReadCursor
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SendDataTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    auto sessionBuff = std::make_shared<BufferObject>();
    char sendBuffer[1024] = {0};

    EXPECT_CALL(mock, GetSendBufferAndLock(testing::_)).WillOnce(testing::Return(sendBuffer));
    EXPECT_CALL(mock, GetSendBufferWriteCursor()).WillOnce(testing::Return(1024));
    EXPECT_CALL(mock, GetSendBufferReadCursor()).WillOnce(testing::Return(1024));

    int result = testInvoker.SendData(sessionBuff, SOCKET_ID_TEST);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: SendDataTest004
 * @tc.desc: Verify the SendData function when the return value of function GetSendBufferWriteCursor
 * is equal to the return value of function GetSendBufferReadCursor and SendBytes function return 1
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SendDataTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    auto sessionBuff = std::make_shared<BufferObject>();
    char sendBuffer[1024] = {0};

    EXPECT_CALL(mock, GetSendBufferAndLock(testing::_)).WillOnce(testing::Return(sendBuffer));
    EXPECT_CALL(mock, GetSendBufferWriteCursor()).WillOnce(testing::Return(1024));
    EXPECT_CALL(mock, GetSendBufferReadCursor()).WillOnce(testing::Return(0));
    EXPECT_CALL(mock, SendBytes).WillRepeatedly(testing::Return(1));

    int result = testInvoker.SendData(sessionBuff, SOCKET_ID_TEST);
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: SendDataTest005
 * @tc.desc: Verify the SendData function when SendBytes function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SendDataTest005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    auto sessionBuff = std::make_shared<BufferObject>();
    char sendBuffer[1024] = {0};

    EXPECT_CALL(mock, GetSendBufferAndLock(testing::_)).WillOnce(testing::Return(sendBuffer));
    EXPECT_CALL(mock, GetSendBufferWriteCursor()).WillOnce(testing::Return(1024));
    EXPECT_CALL(mock, GetSendBufferReadCursor()).WillOnce(testing::Return(0));
    EXPECT_CALL(mock, SendBytes).WillRepeatedly(testing::Return(0));

    int result = testInvoker.SendData(sessionBuff, SOCKET_ID_TEST);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: OnSendRawDataTest001
 * @tc.desc: Verify the OnSendRawData function when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnSendRawDataTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    size_t size = 0;

    int result = testInvoker.OnSendRawData(nullptr, nullptr, size);
    EXPECT_EQ(result, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendRawDataTest002
 * @tc.desc: Verify the OnSendRawData function when socketId is less or equal than 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnSendRawDataTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto sessionObject = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    sessionObject->SetSocketId(SOCKET_ID_INVALID_TEST);
    size_t size = 0;

    int result = testInvoker.OnSendRawData(sessionObject, nullptr, size);
    EXPECT_EQ(result, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendRawDataTest003
 * @tc.desc: Verify the OnSendRawData function when SendBytes function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnSendRawDataTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    auto sessionObject = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    sessionObject->SetSocketId(SOCKET_ID_TEST);
    size_t size = 0;

    EXPECT_CALL(mock, SendBytes).WillRepeatedly(testing::Return(0));

    int result = testInvoker.OnSendRawData(sessionObject, nullptr, size);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: OnSendRawDataTest004
 * @tc.desc: Verify the OnSendRawData function when SendBytes function return 1
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnSendRawDataTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    auto sessionObject = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    sessionObject->SetSocketId(SOCKET_ID_TEST);
    size_t size = 0;

    EXPECT_CALL(mock, SendBytes).WillRepeatedly(testing::Return(1));

    int result = testInvoker.OnSendRawData(sessionObject, nullptr, size);
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: JoinProcessThreadTest001
 * @tc.desc: Verify the JoinProcessThread function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, JoinProcessThreadTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    ASSERT_NO_FATAL_FAILURE(testInvoker.JoinProcessThread(true));
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: FlattenSessionTest001
 * @tc.desc: Verify the FlattenSession function when GetDeviceId function return ""
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlattenSessionTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, "", STUB_INDEX, nullptr, TOKEN_ID);
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    uint32_t binderVersion = TEST_HANDLE_VALID;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDeviceId()).WillOnce(testing::Return(""));

    auto result = testInvoker.FlattenSession(sessionOffset, connectSession, binderVersion);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: FlattenSessionTest002
 * @tc.desc: Verify the FlattenSession function when GetServiceName function return ""
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlattenSessionTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    uint32_t binderVersion = TEST_HANDLE_VALID;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDeviceId()).WillRepeatedly(testing::Return(DEVICE_ID_TEST));
    EXPECT_CALL(mock, GetServiceName()).WillOnce(testing::Return(""));

    auto result = testInvoker.FlattenSession(sessionOffset, connectSession, binderVersion);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: FlattenSessionTest003
 * @tc.desc: Verify the FlattenSession function when GetDeviceId function return length greater than DEVICEID_LENGTH
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlattenSessionTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    uint32_t binderVersion = TEST_HANDLE_VALID;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDeviceId()).WillOnce(testing::Return(DEVICE_ID_TEST))
    .WillOnce(testing::Return(std::string(DEVICEID_LENGTH + 1, 'a')));

    auto result = testInvoker.FlattenSession(sessionOffset, connectSession, binderVersion);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: FlattenSessionTest004
 * @tc.desc: Verify the FlattenSession function when GetDeviceId and GetServiceName function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlattenSessionTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    uint32_t binderVersion = TEST_HANDLE_VALID;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDeviceId()).WillRepeatedly(testing::Return(DEVICE_ID_TEST));
    EXPECT_CALL(mock, GetServiceName()).WillRepeatedly(testing::Return(SERVICE_NAME_TEST));

    auto result = testInvoker.FlattenSession(sessionOffset, connectSession, binderVersion);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: OnDatabusSessionClientSideClosedTest001
 * @tc.desc: Verify the OnDatabusSessionClientSideClosed function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnDatabusSessionClientSideClosedTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    ASSERT_NO_FATAL_FAILURE(testInvoker.OnDatabusSessionClientSideClosed(SOCKET_ID_TEST));
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: OnDatabusSessionClientSideClosedTest002
 * @tc.desc: Verify the OnDatabusSessionClientSideClosed function when QueryProxyBySocketId function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnDatabusSessionClientSideClosedTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, QueryProxyBySocketId(testing::_, testing::_)).WillOnce(testing::Return(false));

    ASSERT_NO_FATAL_FAILURE(testInvoker.OnDatabusSessionClientSideClosed(SOCKET_ID_TEST));
}

/**
 * @tc.name: OnDatabusSessionClientSideClosedTest003
 * @tc.desc: Verify the OnDatabusSessionClientSideClosed function when proxyHandle is empty
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnDatabusSessionClientSideClosedTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->proxyToSession_.clear();

    EXPECT_CALL(mock, QueryProxyBySocketId(testing::_, testing::_)).WillOnce(testing::Return(true));

    ASSERT_NO_FATAL_FAILURE(testInvoker.OnDatabusSessionClientSideClosed(SOCKET_ID_TEST));
}

/**
 * @tc.name: OnDatabusSessionClientSideClosedTest004
 * @tc.desc: Verify the OnDatabusSessionClientSideClosed function when QueryProxyBySocketId return true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnDatabusSessionClientSideClosedTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    current->proxyToSession_[TEST_HANDLE_VALID] = remoteSession;

    EXPECT_CALL(mock, QueryProxyBySocketId(testing::_, testing::_)).WillOnce(testing::Return(true));

    ASSERT_NO_FATAL_FAILURE(testInvoker.OnDatabusSessionClientSideClosed(SOCKET_ID_TEST));
    current->proxyToSession_.clear();
}

/**
 * @tc.name: OnDatabusSessionServerSideClosedTest001
 * @tc.desc: Verify the OnDatabusSessionServerSideClosed function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnDatabusSessionServerSideClosedTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    ASSERT_NO_FATAL_FAILURE(testInvoker.OnDatabusSessionServerSideClosed(SOCKET_ID_TEST));
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: QueryHandleBySessionTest001
 * @tc.desc: Verify the QueryHandleBySession function when current->instance_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryHandleBySessionTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    auto result = testInvoker.QueryHandleBySession(nullptr);
    EXPECT_EQ(result, 0);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: QueryHandleBySessionTest002
 * @tc.desc: Verify the QueryHandleBySession function when TEST_HANDLE_VALID
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryHandleBySessionTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    current->proxyToSession_[TEST_HANDLE_VALID] = remoteSession;

    auto result = testInvoker.QueryHandleBySession(remoteSession);
    EXPECT_EQ(result, TEST_HANDLE_VALID);
}

/**
 * @tc.name: CheckAndSetCallerInfoTest001
 * @tc.desc: Verify the CheckAndSetCallerInfo function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CheckAndSetCallerInfoTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    auto result = testInvoker.CheckAndSetCallerInfo(SOCKET_ID_TEST, STUB_INDEX);
    EXPECT_EQ(result, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: CheckAndSetCallerInfoTest002
 * @tc.desc: Verify the CheckAndSetCallerInfo function when uid less than 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CheckAndSetCallerInfoTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;
    remoteSession->SetPeerPid(PEER_PID_TEST);
    remoteSession->SetPeerUid(-1);

        EXPECT_CALL(mock, StubQueryDBinderSession(testing::_))
            .WillRepeatedly(testing::Return(remoteSession));

    auto result = testInvoker.CheckAndSetCallerInfo(SOCKET_ID_TEST, STUB_INDEX);
    EXPECT_EQ(result, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: CheckAndSetCallerInfoTest003
 * @tc.desc: Verify the CheckAndSetCallerInfo function whenwhen QueryAppInfoToStubIndex function return false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CheckAndSetCallerInfoTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;
    remoteSession->SetPeerPid(PEER_PID_TEST);
    remoteSession->SetPeerUid(1);

    EXPECT_CALL(mock, StubQueryDBinderSession(testing::_)).WillRepeatedly(testing::Return(remoteSession));
    EXPECT_CALL(mock, QueryAppInfoToStubIndex(testing::_)).WillRepeatedly(testing::Return(false));

    auto result = testInvoker.CheckAndSetCallerInfo(SOCKET_ID_TEST, STUB_INDEX);
    EXPECT_EQ(result, RPC_DATABUS_INVOKER_INVALID_STUB_INDEX);
}

/**
 * @tc.name: CheckAndSetCallerInfoTest004
 * @tc.desc: Verify the CheckAndSetCallerInfo function ERR_NONE when QueryAppInfoToStubIndex function return true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CheckAndSetCallerInfoTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;
    remoteSession->SetPeerPid(PEER_PID_TEST);
    remoteSession->SetPeerUid(1);

    EXPECT_CALL(mock, StubQueryDBinderSession(testing::_)).WillRepeatedly(testing::Return(remoteSession));
    EXPECT_CALL(mock, QueryAppInfoToStubIndex(testing::_)).WillRepeatedly(testing::Return(true));

    auto result = testInvoker.CheckAndSetCallerInfo(SOCKET_ID_TEST, STUB_INDEX);
    EXPECT_EQ(result, ERR_NONE);
}


/**
 * @tc.name: MakeStubIndexByRemoteObjectTest001
 * @tc.desc: Verify the MakeStubIndexByRemoteObject function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeStubIndexByRemoteObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_HANDLE_VALID);

    auto result = testInvoker.MakeStubIndexByRemoteObject(object);
    EXPECT_EQ(result, 0);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: MakeStubIndexByRemoteObjectTest002
 * @tc.desc: Verify the MakeStubIndexByRemoteObject function when IsContainsObject is false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeStubIndexByRemoteObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_HANDLE_VALID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, IsContainsObject(testing::_)).WillOnce(testing::Return(false));

    auto result = testInvoker.MakeStubIndexByRemoteObject(object);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: MakeStubIndexByRemoteObjectTest003
 * @tc.desc: Verify the MakeStubIndexByRemoteObject function when AddStubByIndex is 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeStubIndexByRemoteObjectTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_HANDLE_VALID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, IsContainsObject(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, AddStubByIndex(testing::_)).WillOnce(testing::Return(0));

    auto result = testInvoker.MakeStubIndexByRemoteObject(object);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: MakeStubIndexByRemoteObjectTest004
 * @tc.desc: Verify the MakeStubIndexByRemoteObject function when AddStubByIndex is 1
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeStubIndexByRemoteObjectTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_HANDLE_VALID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, IsContainsObject(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, AddStubByIndex(testing::_)).WillOnce(testing::Return(1));

    auto result = testInvoker.MakeStubIndexByRemoteObject(object);
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: UnFlattenSessionTest001
 * @tc.desc: Verify the UnFlattenSession function when flatSession->stubIndex is 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UnFlattenSessionTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    flatSession->stubIndex = 0;
    uint32_t binderVersion = TEST_HANDLE_VALID;

    auto result = testInvoker.UnFlattenSession(sessionOffset, binderVersion);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: UnFlattenSessionTest002
 * @tc.desc: Verify the UnFlattenSession function when flatSession->stubIndex is not 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UnFlattenSessionTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    flatSession->stubIndex = STUB_INDEX;
    flatSession->version = SUPPORT_TOKENID_VERSION_NUM;
    flatSession->magic = TOKENID_MAGIC;
    uint32_t binderVersion = SUPPORT_TOKENID_VERSION_NUM;

    auto result = testInvoker.UnFlattenSession(sessionOffset, binderVersion);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: UnFlattenSessionTest003
 * @tc.desc: Verify the UnFlattenSession function when flatSession->version = SUPPORT_TOKENID_VERSION_NUM - 1
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UnFlattenSessionTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    flatSession->stubIndex = STUB_INDEX;
    flatSession->version = SUPPORT_TOKENID_VERSION_NUM - 1;
    flatSession->magic = TOKENID_MAGIC;
    uint32_t binderVersion = SUPPORT_TOKENID_VERSION_NUM;

    auto result = testInvoker.UnFlattenSession(sessionOffset, binderVersion);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: UnFlattenSessionTest004
 * @tc.desc: Verify the UnFlattenSession function when binderVersion = SUPPORT_TOKENID_VERSION_NUM - 1
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UnFlattenSessionTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    flatSession->stubIndex = STUB_INDEX;
    flatSession->version = SUPPORT_TOKENID_VERSION_NUM;
    flatSession->magic = TOKENID_MAGIC;
    uint32_t binderVersion = SUPPORT_TOKENID_VERSION_NUM - 1;

    auto result = testInvoker.UnFlattenSession(sessionOffset, binderVersion);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: UnFlattenSessionTest005
 * @tc.desc: Verify the UnFlattenSession function when flatSession->magic not equal TOKENID_MAGIC
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UnFlattenSessionTest005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    FlatDBinderSession *flatSession = reinterpret_cast<FlatDBinderSession *>(sessionOffset);
    flatSession->stubIndex = STUB_INDEX;
    flatSession->version = SUPPORT_TOKENID_VERSION_NUM;
    flatSession->magic = TOKENID_MAGIC - 1;
    uint32_t binderVersion = SUPPORT_TOKENID_VERSION_NUM;

    auto result = testInvoker.UnFlattenSession(sessionOffset, binderVersion);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: UpdateClientSessionTest001
 * @tc.desc: Verify the UpdateClientSession function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UpdateClientSessionTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    auto result = testInvoker.UpdateClientSession(connectSession);
    EXPECT_FALSE(result);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: UpdateClientSessionTest002
 * @tc.desc: Verify the UpdateClientSession function when GetDatabusName is ""
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UpdateClientSessionTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(""));

    auto result = testInvoker.UpdateClientSession(connectSession);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateClientSessionTest003
 * @tc.desc: Verify the UpdateClientSession function when peerUid.length() > INT_STRING_MAX_LEN
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UpdateClientSessionTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(DEVICE_ID_TEST));
    EXPECT_CALL(mock, GetServiceName()).WillOnce(testing::Return(PEER_UID_INVALID_TEST));

    auto result = testInvoker.UpdateClientSession(connectSession);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateClientSessionTest004
 * @tc.desc: Verify the UpdateClientSession function when peerPid.length() > INT_STRING_MAX_LEN
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UpdateClientSessionTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(DEVICE_ID_TEST));
    EXPECT_CALL(mock, GetServiceName()).WillOnce(testing::Return(PEER_PID_INVALID_TEST));

    auto result = testInvoker.UpdateClientSession(connectSession);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateClientSessionTest005
 * @tc.desc: Verify the UpdateClientSession function when IsNumStr function return false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UpdateClientSessionTest005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(DEVICE_ID_TEST));
    EXPECT_CALL(mock, GetServiceName()).WillOnce(testing::Return(DBINDER_SOCKET_NAME_PREFIX + "123_456"));
    EXPECT_CALL(mock, IsNumStr(testing::_)).WillRepeatedly(testing::Return(false));

    auto result = testInvoker.UpdateClientSession(connectSession);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateClientSessionTest006
 * @tc.desc: Verify the UpdateClientSession function when CreateClientSocket function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UpdateClientSessionTest006, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(DEVICE_ID_TEST));
    EXPECT_CALL(mock, GetServiceName()).WillOnce(testing::Return(DBINDER_SOCKET_NAME_PREFIX + "123_456"));
    EXPECT_CALL(mock, IsNumStr(testing::_)).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, CreateClientSocket).WillRepeatedly(testing::Return(0));

    auto result = testInvoker.UpdateClientSession(connectSession);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateClientSessionTest0087
 * @tc.desc: Verify the UpdateClientSession function when CreateClientSocket function return 1
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UpdateClientSessionTest007, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX, nullptr, TOKEN_ID);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(DEVICE_ID_TEST));
    EXPECT_CALL(mock, GetServiceName()).WillOnce(testing::Return(DBINDER_SOCKET_NAME_PREFIX + "123_456"));
    EXPECT_CALL(mock, IsNumStr(testing::_)).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, CreateClientSocket).WillRepeatedly(testing::Return(1));

    auto result = testInvoker.UpdateClientSession(connectSession);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MakeDefaultServerSessionObjectTest001
 * @tc.desc: Verify the MakeDefaultServerSessionObject function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeDefaultServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;
    uint64_t stubIndex = STUB_INDEX;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);

    auto result = testInvoker.MakeDefaultServerSessionObject(stubIndex, remoteSession);
    EXPECT_EQ(result, nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: MakeDefaultServerSessionObjectTest002
 * @tc.desc: Verify the MakeDefaultServerSessionObject function when GetDatabusName function return ""
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeDefaultServerSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint64_t stubIndex = STUB_INDEX;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(""));

    auto result = testInvoker.MakeDefaultServerSessionObject(stubIndex, remoteSession);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: MakeDefaultServerSessionObjectTest003
 * @tc.desc: Verify the MakeDefaultServerSessionObject function when GetLocalDeviceID function return ""
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeDefaultServerSessionObjectTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint64_t stubIndex = STUB_INDEX;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(SERVICE_NAME_TEST));
    EXPECT_CALL(mock, GetLocalDeviceID()).WillOnce(testing::Return(""));

    auto result = testInvoker.MakeDefaultServerSessionObject(stubIndex, remoteSession);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: MakeDefaultServerSessionObjectTest004
 * @tc.desc: Verify the MakeDefaultServerSessionObject function
 * when functions GetDatabusName and GetLocalDeviceID return non empty values
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeDefaultServerSessionObjectTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint64_t stubIndex = STUB_INDEX;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(SERVICE_NAME_TEST));
    EXPECT_CALL(mock, GetLocalDeviceID()).WillOnce(testing::Return(DEVICE_ID_TEST));

    auto result = testInvoker.MakeDefaultServerSessionObject(stubIndex, remoteSession);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: ConnectRemoteObject2SessionTest001
 * @tc.desc: Verify the ConnectRemoteObject2Session function sessionObject is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, ConnectRemoteObject2SessionTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    sptr<IRemoteObject> stubObject = new IPCObjectProxy(TEST_HANDLE_VALID);
    uint64_t stubIndex = STUB_INDEX;
    std::shared_ptr<DBinderSessionObject> sessionObject = nullptr;

    auto result = testInvoker.ConnectRemoteObject2Session(stubObject, stubIndex, sessionObject);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: ConnectRemoteObject2SessionTest002
 * @tc.desc: Verify the ConnectRemoteObject2Session function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, ConnectRemoteObject2SessionTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;
    sptr<IRemoteObject> stubObject = new IPCObjectProxy(TEST_HANDLE_VALID);
    uint64_t stubIndex = STUB_INDEX;
    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);

    auto result = testInvoker.ConnectRemoteObject2Session(stubObject, stubIndex, sessionObject);
    EXPECT_EQ(result, false);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: ConnectRemoteObject2SessionTest003
 * @tc.desc: Verify the ConnectRemoteObject2Session function when AttachOrUpdateAppAuthInfo function return true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, ConnectRemoteObject2SessionTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    sptr<IRemoteObject> stubObject = new IPCObjectProxy(TEST_HANDLE_VALID);
    uint64_t stubIndex = STUB_INDEX;
    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, AttachOrUpdateAppAuthInfo(testing::_)).WillOnce(testing::Return(true));

    auto result = testInvoker.ConnectRemoteObject2Session(stubObject, stubIndex, sessionObject);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: CreateServerSessionObjectTest001
 * @tc.desc: Verify the CreateServerSessionObject function ptrTest is 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);

    auto result = testInvoker.CreateServerSessionObject(0, sessionObject);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: CreateServerSessionObjectTest002
 * @tc.desc: Verify the CreateServerSessionObject function ptrTest is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateServerSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;
    binder_uintptr_t ptrTest = 1;
    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);

    auto result = testInvoker.CreateServerSessionObject(ptrTest, sessionObject);
    EXPECT_EQ(result, nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: CreateServerSessionObjectTest003
 * @tc.desc: Verify the CreateServerSessionObject function when MakeStubIndexByRemoteObject function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateServerSessionObjectTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    binder_uintptr_t ptrTest = 1;
    std::shared_ptr<DBinderSessionObject> sessionObject = nullptr;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, IsContainsObject(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, AddStubByIndex(testing::_)).WillOnce(testing::Return(0));

    auto result = testInvoker.CreateServerSessionObject(ptrTest, sessionObject);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: CreateServerSessionObjectTest004
 * @tc.desc: Verify the CreateServerSessionObject function
 * when MakeDefaultServerSessionObject function return not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateServerSessionObjectTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    binder_uintptr_t ptrTest = 1;
    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, IsContainsObject(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, AddStubByIndex(testing::_)).WillOnce(testing::Return(1));
    EXPECT_CALL(mock, GetDatabusName()).WillOnce(testing::Return(SERVICE_NAME_TEST));
    EXPECT_CALL(mock, GetLocalDeviceID()).WillOnce(testing::Return(DEVICE_ID_TEST));

    auto result = testInvoker.CreateServerSessionObject(ptrTest, sessionObject);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: FlushCommandsTest001
 * @tc.desc: Verify the FlushCommands function object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlushCommandsTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    sptr<IRemoteObject> object = nullptr;

    auto result = testInvoker.FlushCommands(object);
    EXPECT_EQ(result, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: FlushCommandsTest002
 * @tc.desc: Verify the FlushCommands function when QueryServerSessionObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlushCommandsTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_HANDLE_VALID);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    auto result = testInvoker.FlushCommands(object);
    EXPECT_EQ(result, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: FlushCommandsTest003
 * @tc.desc: Verify the FlushCommands function return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlushCommandsTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_HANDLE_VALID);
    ASSERT_TRUE(object->IsProxyObject());

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);
    bool ret = current->ProxyAttachDBinderSession(TEST_HANDLE_VALID, remoteSession);
    EXPECT_TRUE(ret);

    auto result = testInvoker.FlushCommands(object);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: SetCallingIdentityTest001
 * @tc.desc: Verify the SetCallingIdentity function identity is empty or identity.length() <= DEVICEID_LENGTH
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SetCallingIdentityTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string identity = "";
    auto result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(result, false);

    identity = IDENTITY_SHORT_TEST;
    result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetCallingIdentityTest002
 * @tc.desc: Verify the SetCallingIdentity function when StrToUint64 function return false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SetCallingIdentityTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string identity = "invalid_token_id" + std::string(DEVICEID_LENGTH, '0');
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, StrToUint64(testing::_, testing::_)).WillOnce(testing::Return(false));

    auto result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetCallingIdentityTest003
 * @tc.desc: Verify the SetCallingIdentity function when deviceId is invalid value
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SetCallingIdentityTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string identity = std::string(ACCESS_TOKEN_MAX_LEN, '1') + "invalid_device_id";
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, StrToUint64(testing::_, testing::_)).WillRepeatedly(testing::Return(true));

    auto result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetCallingIdentityTest004
 * @tc.desc: Verify the SetCallingIdentity function when identity.length() = ACCESS_TOKEN_MAX_LEN + DEVICEID_LENGTH
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SetCallingIdentityTest004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string tokenIdStr = TOKEN_ID_STR;
    std::string deviceId = std::string(DEVICEID_LENGTH, 'A');
    std::string identity = tokenIdStr + deviceId;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, StrToUint64(testing::_, testing::_)).WillOnce(testing::Return(true));

    auto result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetCallingIdentityTest005
 * @tc.desc: Verify the SetCallingIdentity function when StrToUint64 function second return false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SetCallingIdentityTest005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string tokenIdStr = TOKEN_ID_STR;
    std::string deviceId = std::string(DEVICEID_LENGTH, 'A');
    uint64_t token = (static_cast<uint64_t>(1000) << PID_LEN) | 2000;
    std::string tokenStr = std::to_string(token);
    std::string identity = tokenIdStr + deviceId + tokenStr;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, StrToUint64(testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(false));

    auto result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: SetCallingIdentityTest006
 * @tc.desc: Verify the SetCallingIdentity function when true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SetCallingIdentityTest006, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string tokenIdStr = TOKEN_ID_STR;
    std::string deviceId = std::string(DEVICEID_LENGTH, 'A');
    uint64_t token = (static_cast<uint64_t>(1000) << PID_LEN) | 2000;
    std::string tokenStr = std::to_string(token);
    std::string identity = tokenIdStr + deviceId + tokenStr;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, StrToUint64(testing::_, testing::_)).WillRepeatedly(testing::Return(true));

    auto result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(result, true);
}
} //namespace OHOS
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ipc_file_descriptor.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "mock_iremote_invoker.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace {
    constexpr int VALID_FD_TEST = 1;
}
class IPCFileDescriptorInterface {
public:
    IPCFileDescriptorInterface() {};
    virtual ~IPCFileDescriptorInterface() {};

    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
};
class IPCFileDescriptorInterfaceMock : public IPCFileDescriptorInterface {
public:
    IPCFileDescriptorInterfaceMock();
    ~IPCFileDescriptorInterfaceMock() override;
    
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
};
static void *g_interface = nullptr;

IPCFileDescriptorInterfaceMock::IPCFileDescriptorInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCFileDescriptorInterfaceMock::~IPCFileDescriptorInterfaceMock()
{
    g_interface = nullptr;
}

static IPCFileDescriptorInterface *GetIPCFileDescriptorInterface()
{
    return reinterpret_cast<IPCFileDescriptorInterface *>(g_interface);
}

extern "C" {
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (GetIPCFileDescriptorInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCFileDescriptorInterface()->GetRemoteInvoker(proto);
    }
}

class IPCFileDescriptorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void IPCFileDescriptorTest::SetUpTestCase()
{
}

void IPCFileDescriptorTest::TearDownTestCase()
{
}

void IPCFileDescriptorTest::SetUp()
{
}

void IPCFileDescriptorTest::TearDown()
{
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Verify the Marshalling function when ipcFileDescriptor.fd_ is -1
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest001, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    ipcFileDescriptor.fd_ = INVALID_FD;
    Parcel parcel;

    auto result = ipcFileDescriptor.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest002, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    ipcFileDescriptor.fd_ = VALID_FD_TEST;
    Parcel parcel;

    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));

    auto result = ipcFileDescriptor.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest003
 * @tc.desc: Verify the Marshalling function when WriteFileDescriptor function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest003, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    ipcFileDescriptor.fd_ = VALID_FD_TEST;
    Parcel parcel;

    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, WriteFileDescriptor(testing::_, testing::_, testing::_)).WillOnce(Return(false));

    auto result = ipcFileDescriptor.Marshalling(parcel);
    EXPECT_FALSE(result);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest004
 * @tc.desc: Verify the Marshalling function when WriteFileDescriptor function return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest004, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    ipcFileDescriptor.fd_ = VALID_FD_TEST;
    Parcel parcel;

    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, WriteFileDescriptor(testing::_, testing::_, testing::_)).WillOnce(Return(true));

    auto result = ipcFileDescriptor.Marshalling(parcel);
    EXPECT_TRUE(result);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest005
 * @tc.desc: Verify the Marshalling function when object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest005, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    sptr<IPCFileDescriptor> object;

    auto result = ipcFileDescriptor.Marshalling(parcel, object);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest006
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest006, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    sptr<IPCFileDescriptor> object = new IPCFileDescriptor();
    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));

    auto result = ipcFileDescriptor.Marshalling(parcel, object);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest007
 * @tc.desc: Verify the Marshalling function when WriteFileDescriptor function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest007, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    sptr<IPCFileDescriptor> object = new IPCFileDescriptor();
    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, WriteFileDescriptor(testing::_, testing::_, testing::_)).WillOnce(Return(false));

    auto result = ipcFileDescriptor.Marshalling(parcel, object);
    EXPECT_FALSE(result);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest008
 * @tc.desc: Verify the Marshalling function when WriteFileDescriptor function return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, MarshallingTest008, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    sptr<IPCFileDescriptor> object = new IPCFileDescriptor();
    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, WriteFileDescriptor(testing::_, testing::_, testing::_)).WillOnce(Return(true));

    auto result = ipcFileDescriptor.Marshalling(parcel, object);
    EXPECT_TRUE(result);
    delete invoker;
}

/**
 * @tc.name: UnmarshallingTest001
 * @tc.desc: Verify the Unmarshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, UnmarshallingTest001, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    NiceMock<IPCFileDescriptorInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));

    auto result = ipcFileDescriptor.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: UnmarshallingTest002
 * @tc.desc: Verify the Unmarshalling function when ReadFileDescriptor function return 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCFileDescriptorTest, UnmarshallingTest002, TestSize.Level1) {
    IPCFileDescriptor ipcFileDescriptor;
    Parcel parcel;
    NiceMock<IPCFileDescriptorInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(*invoker, ReadFileDescriptor(testing::_)).WillOnce(Return(1));

    auto result = ipcFileDescriptor.Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    delete invoker;
}

/**
 * @tc.name: AuthSession2Proxy004
 * @tc.desc: Verify the AuthSession2Proxy function when WriteString function return false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AuthSession2Proxy004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(false));

    bool res = testInvoker.AuthSession2Proxy(handle, remoteSession);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: AuthSession2Proxy005
 * @tc.desc: Verify the AuthSession2Proxy function when WriteUint64 function false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AuthSession2Proxy005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = TEST_UINT_HANDLE_INVALID;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillRepeatedly(Return(false));

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
    uint64_t seqNumber = SOCKET_ID_TEST;
    uint32_t dataSize = sizeof(DATA_TEST);
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnRawDataAvailable(socketId, seqNumber, DATA_TEST, dataSize));
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: OnRawDataAvailableTest002
 * @tc.desc: Verify the OnRawDataAvailable function when dataSize equal sizeof(dbinder_transaction_data)
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnRawDataAvailableTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t socketId = SOCKET_ID_TEST;
    uint64_t seqNumber = SOCKET_ID_TEST;
    uint32_t dataSize = sizeof(dbinder_transaction_data);
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnRawDataAvailable(socketId, seqNumber, DATA_TEST, dataSize));
}

/**
 * @tc.name: OnRawDataAvailableTest003
 * @tc.desc: Verify the OnRawDataAvailable function when AttachRawData function return false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnRawDataAvailableTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t socketId = SOCKET_ID_TEST;
    uint64_t seqNumber = SOCKET_ID_TEST;
    uint32_t dataSize = sizeof(dbinder_transaction_data) + 2;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, AttachRawData).WillOnce(testing::Return(false));

    ASSERT_NO_FATAL_FAILURE(testInvoker.OnRawDataAvailable(socketId, seqNumber, DATA_TEST, dataSize));
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
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnMessageAvailable(socketId, data, len));
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
    ASSERT_NO_FATAL_FAILURE(testInvoker.OnMessageAvailable(socketId, data, len));
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
    EXPECT_EQ(len, tr.sizeOfSelf);
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
    EXPECT_CALL(mock, GetSendBufferSize()).WillOnce(testing::Return(1024));
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
 * @tc.name: FlattenSessionTest005
 * @tc.desc: Verify the FlattenSession function when flatSession->deviceIdLength > DEVICEID_LENGTH
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlattenSessionTest005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    auto connectSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, "", STUB_INDEX, nullptr, TOKEN_ID);
    unsigned char sessionOffset[sizeof(FlatDBinderSession)] = {0};
    uint32_t binderVersion = TEST_HANDLE_VALID;
    NiceMock<DbinderDataBusInvokerMock> mock;

    EXPECT_CALL(mock, GetDeviceId()).WillOnce(testing::Return(std::string(DEVICEID_LENGTH + 1, 'a')));

    auto result = testInvoker.FlattenSession(sessionOffset, connectSession, binderVersion);
    EXPECT_EQ(result, 0);
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
 * @tc.name: OnDatabusSessionClientSideClosedTest005
 * @tc.desc: Verify the OnDatabusSessionClientSideClosed function when QueryObject return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnDatabusSessionClientSideClosedTest005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    current->proxyToSession_[TEST_HANDLE_VALID] = remoteSession;

    EXPECT_CALL(mock, QueryProxyBySocketId(testing::_, testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryObject).WillRepeatedly(testing::Return(nullptr));

    ASSERT_NO_FATAL_FAILURE(testInvoker.OnDatabusSessionClientSideClosed(SOCKET_ID_TEST));
    current->proxyToSession_.clear();
}

/**
 * @tc.name: OnDatabusSessionClientSideClosedTest006
 * @tc.desc: Verify the OnDatabusSessionClientSideClosed function when QueryObject return object
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnDatabusSessionClientSideClosedTest006, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    NiceMock<DbinderDataBusInvokerMock> mock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    current->proxyToSession_[TEST_HANDLE_VALID] = remoteSession;
    sptr<IRemoteObject> object = new IPCObjectStub(DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);

    EXPECT_CALL(mock, QueryProxyBySocketId(testing::_, testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryObject).WillRepeatedly(testing::Return(object));

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
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;
    remoteSession->SetPeerPid(PEER_PID_TEST);
    remoteSession->SetPeerUid(1);

    EXPECT_CALL(mock, StubQueryDBinderSession(testing::_)).WillRepeatedly(testing::Return(remoteSession));

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

    EXPECT_CALL(mock, StubQueryDBinderSession(testing::_)).WillRepeatedly(testing::Return(remoteSession));

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
 * @tc.name: CheckAndSetCallerInfoTest005
 * @tc.desc: Verify the CheckAndSetCallerInfo function when GetDeviceId function return DEVICEID_LENGTH + 1
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CheckAndSetCallerInfoTest005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    NiceMock<DbinderDataBusInvokerMock> mock;
    remoteSession->SetPeerPid(PEER_PID_TEST);
    remoteSession->SetPeerUid(1);

    EXPECT_CALL(mock, StubQueryDBinderSession(testing::_)).WillRepeatedly(testing::Return(remoteSession));
    EXPECT_CALL(mock, GetDeviceId()).WillRepeatedly(testing::Return(std::string(DEVICEID_LENGTH + 1, 'a')));

    auto result = testInvoker.CheckAndSetCallerInfo(SOCKET_ID_TEST, STUB_INDEX);
    EXPECT_EQ(result, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
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

} // namespace OHOS
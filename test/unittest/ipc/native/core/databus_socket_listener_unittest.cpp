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
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "databus_socket_listener.h"
#include "ipc_thread_skeleton.h"
#include "iremote_invoker.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class DatabusSocketListenerInterface {
public:
    DatabusSocketListenerInterface() {};
    virtual ~DatabusSocketListenerInterface() {};
    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener) = 0;
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
};

class DatabusSocketListenerInterfaceMock : public DatabusSocketListenerInterface {
public:
    DatabusSocketListenerInterfaceMock();
    ~DatabusSocketListenerInterfaceMock() override;
    MOCK_METHOD1(Socket, int32_t(SocketInfo));
    MOCK_METHOD4(Listen, int32_t(int32_t, const QosTV *, uint32_t, const ISocketListener *));
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
    MOCK_METHOD4(Bind, int32_t(int32_t, const QosTV *, uint32_t, const ISocketListener *));
};

class DatabusSocketListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void DatabusSocketListenerTest::SetUpTestCase()
{
}

void DatabusSocketListenerTest::TearDownTestCase()
{
}

void DatabusSocketListenerTest::SetUp()
{
}

void DatabusSocketListenerTest::TearDown()
{
}

static void *g_interface = nullptr;

DatabusSocketListenerInterfaceMock::DatabusSocketListenerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DatabusSocketListenerInterfaceMock::~DatabusSocketListenerInterfaceMock()
{
    g_interface = nullptr;
}

static DatabusSocketListenerInterfaceMock *GetDatabusSocketListenerInterface()
{
    return reinterpret_cast<DatabusSocketListenerInterfaceMock *>(g_interface);
}

extern "C" {
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (GetDatabusSocketListenerInterface() == nullptr) {
            return nullptr;
        }
        return GetDatabusSocketListenerInterface()->GetRemoteInvoker(proto);
    }

    int32_t DBinderSoftbusClient::Socket(SocketInfo info)
    {
        return GetDatabusSocketListenerInterface()->Socket(info);
    }

    int32_t DBinderSoftbusClient::Listen(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
    {
        return GetDatabusSocketListenerInterface()->Listen(socket, qos, qosCount, listener);
    }

    int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener)
    {
        return GetDatabusSocketListenerInterface()->Bind(socket, qos, qosCount, listener);
    }
}

/**
 * @tc.name: ServerOnBindTest001
 * @tc.desc: Verify the ServerOnBind function when peerUid.length() > INT_STRING_MAX_LEN
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest001, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    std::string infoName = DBINDER_SOCKET_NAME_PREFIX + "01234567890123456789" + "_" + "012345";
    std::string infoNetworkId = "1234567890abcdefg";
    std::string infoPkgName = "1234567asd";
    PeerSocketInfo info = {
        .dataType = DATA_TYPE_BYTES,
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str()),
    };
    ASSERT_NO_FATAL_FAILURE(listener.ServerOnBind(socket, info));
}

/**
 * @tc.name: ServerOnBindTest002
 * @tc.desc: Verify the ServerOnBind function when peerPid.length() > INT_STRING_MAX_LEN)
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest002, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    std::string infoName = DBINDER_SOCKET_NAME_PREFIX + "01234567890123456789" + "_" + "012345";
    std::string infoNetworkId = "1234567890abcdefg";
    std::string infoPkgName = "1234567asd";
    PeerSocketInfo info = {
        .dataType = DATA_TYPE_BYTES,
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str()),
    };
    ASSERT_NO_FATAL_FAILURE(listener.ServerOnBind(socket, info));
}

/**
 * @tc.name: ServerOnBindTest003
 * @tc.desc: Verify the ServerOnBind function when !ProcessSkeleton::IsNumStr(peerUid)
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest003, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    std::string infoName = DBINDER_SOCKET_NAME_PREFIX + "peerUid" + "_" + "012345";
    std::string infoNetworkId = "1234567890abcdefg";
    std::string infoPkgName = "1234567asd";
    PeerSocketInfo info = {
        .dataType = DATA_TYPE_BYTES,
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str()),
    };
    ASSERT_NO_FATAL_FAILURE(listener.ServerOnBind(socket, info));
}

/**
 * @tc.name: ServerOnBindTest004
 * @tc.desc: Verify the ServerOnBind function when !ProcessSkeleton::IsNumStr(peerPid)
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest004, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    std::string infoName = DBINDER_SOCKET_NAME_PREFIX + "012345" + "_" + "peerPid";
    std::string infoNetworkId = "1234567890abcdefg";
    std::string infoPkgName = "1234567asd";
    PeerSocketInfo info = {
        .dataType = DATA_TYPE_BYTES,
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str())
    };
    ASSERT_NO_FATAL_FAILURE(listener.ServerOnBind(socket, info));
}

/**
 * @tc.name: ClientOnShutdown001
 * @tc.desc: Verify the ClientOnShutdown function when invoker == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ClientOnShutdown001, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 1;
    ShutdownReason reason = SHUTDOWN_REASON_LINK_DOWN;
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));
    ASSERT_NO_FATAL_FAILURE(listener.ClientOnShutdown(socket, reason));
}

/**
 * @tc.name: ClientOnShutdown002
 * @tc.desc: Verify the ClientOnShutdown function when it->second == socket in iter socketInfoMap_
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ClientOnShutdown002, TestSize.Level1)
{
    DatabusSocketListener listener;
    int32_t socket = 100;
    ShutdownReason reason = SHUTDOWN_REASON_LINK_DOWN;
    std::string ownName = "ownName";
    std::string peerName = "peerName";
    std::string networkId = "networkId";
    DBinderSocketInfo info(ownName, peerName, networkId);
    listener.socketInfoMap_[info] = socket;
    ASSERT_NO_FATAL_FAILURE(listener.ClientOnShutdown(socket, reason));
    listener.socketInfoMap_.clear();
}

/**
 * @tc.name: StartServerListener001
 * @tc.desc: Verify the StartServerListener function when socketId <= 0
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListener001, TestSize.Level1)
{
    DatabusSocketListener listener;
    std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    int32_t socketId = -1;

    EXPECT_CALL(mock, Socket).WillOnce(Return(socketId));
    int32_t result = listener.StartServerListener(ownName);
    EXPECT_EQ(result, SOCKET_ID_INVALID);
}

/**
 * @tc.name: StartServerListener002
 * @tc.desc: Verify the StartServerListener function when ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_SOCKET_IN_USE
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListener002, TestSize.Level1)
{
    DatabusSocketListener listener;
    std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    int32_t socketId = 100;

    EXPECT_CALL(mock, Socket).WillOnce(Return(socketId));
    EXPECT_CALL(mock, Listen).WillOnce(Return(SOFTBUS_DISCOVER_ACTION_HAD_PRELINK));
    int32_t result = listener.StartServerListener(ownName);
    EXPECT_EQ(result, SOCKET_ID_INVALID);
}

/**
 * @tc.name: StartServerListener003
 * @tc.desc: Verify the StartServerListener function when ret == SOFTBUS_TRANS_SOCKET_IN_USE
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListener003, TestSize.Level1)
{
    DatabusSocketListener listener;
    std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    int32_t socketId = 1;

    EXPECT_CALL(mock, Socket).WillOnce(Return(socketId));
    EXPECT_CALL(mock, Listen).WillOnce(Return(SOFTBUS_TRANS_SOCKET_IN_USE));
    int32_t result = listener.StartServerListener(ownName);
    EXPECT_EQ(result, socketId);
}

/**
 * @tc.name: StartServerListener004
 * @tc.desc: Verify the StartServerListener function when ret == SOFTBUS_OK
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListener004, TestSize.Level1)
{
    DatabusSocketListener listener;
    std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    int32_t socketId = 1;

    EXPECT_CALL(mock, Socket).WillOnce(Return(socketId));
    EXPECT_CALL(mock, Listen).WillOnce(Return(SOFTBUS_OK));
    int32_t result = listener.StartServerListener(ownName);
    EXPECT_EQ(result, socketId);
}

/**
 * @tc.name:GetDeviceIDTest001
 * @tc.desc: Verify the GetDeviceID function devide equal DEVICE_TEST
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetDeviceIDTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);
    std::string ret = fakeStub->GetDeviceID();

    EXPECT_STREQ(ret.c_str(), DEVICE_TEST.c_str());
}

/**
 * @tc.name:GetStubIndexTest001
 * @tc.desc: Verify the GetStubIndex function stubIndex_ equal STUBINDEX_TEST
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetStubIndexTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);
    uint64_t ret = fakeStub->GetStubIndex();

    EXPECT_EQ(ret, STUBINDEX_TEST);
}

/**
 * @tc.name: OnRemoteRequestTest001
 * @tc.desc: Verify the OnRemoteRequest function when code GET_PROTO_INFO
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, OnRemoteRequestTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);
    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = fakeStub->OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(ret, DBINDER_CALLBACK_READ_OBJECT_ERR);
}

/**
 * @tc.name: OnRemoteRequestTest002
 * @tc.desc: Verify the OnRemoteRequest function when code is 0
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, OnRemoteRequestTest002, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);
    uint32_t code = CODE_TEST;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = fakeStub->OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(ret, DBINDER_CALLBACK_ERR);
}

/**
 * @tc.name: ProcessProtoTest001
 * @tc.desc: Verify the ProcessProto function when uid is 1 and pid is 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessProtoTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, GetCallingUid).WillRepeatedly(testing::Return(UID_VALID_TEST));
    EXPECT_CALL(mock, GetCallingPid).WillRepeatedly(testing::Return(PID_VALID_TEST));
    EXPECT_CALL(mock, GetSAMgrObject).WillRepeatedly(testing::Return(nullptr));

    int32_t ret = fakeStub->ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_CALLBACK_READ_OBJECT_ERR);
}

/**
 * @tc.name: ProcessProtoTest002
 * @tc.desc: Verify the ProcessProto function when uid is 1 and pid is -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessProtoTest002, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    uint32_t code = DBINDER_DECREFS_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, GetCallingUid).WillRepeatedly(testing::Return(UID_VALID_TEST));
    EXPECT_CALL(mock, GetCallingPid).WillRepeatedly(testing::Return(PID_INVALID_TEST));

    int32_t ret = fakeStub->ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest003
 * @tc.desc: Verify the ProcessProto function when uid is -1 and pid is 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessProtoTest003, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    uint32_t code = DBINDER_DECREFS_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, GetCallingUid).WillRepeatedly(testing::Return(UID_INVALID_TEST));
    EXPECT_CALL(mock, GetCallingPid).WillRepeatedly(testing::Return(PID_VALID_TEST));

    int32_t ret = fakeStub->ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest004
 * @tc.desc: Verify the ProcessProto function when GetSessionNameForPidUid function return empty
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessProtoTest004, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_OBJECT_HANDLE);

    EXPECT_CALL(mock, GetCallingUid).WillRepeatedly(testing::Return(UID_VALID_TEST));
    EXPECT_CALL(mock, GetCallingPid).WillRepeatedly(testing::Return(PID_VALID_TEST));
    EXPECT_CALL(mock, GetSAMgrObject).WillOnce(Return(object));
    EXPECT_CALL(mock, GetSessionNameForPidUid).WillRepeatedly(Return(""));

    int32_t ret = fakeStub->ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_WRONG_SESSION);
}

/**
 * @tc.name: ProcessProtoTest005
 * @tc.desc: Verify the ProcessProto function when GetSessionNameForPidUid function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessProtoTest005, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_OBJECT_HANDLE);

    EXPECT_CALL(mock, GetCallingUid).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, GetCallingPid).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, GetSAMgrObject).WillOnce(Return(object));
    EXPECT_CALL(mock, GetSessionNameForPidUid).WillRepeatedly(Return(SESSION_TEST));

    int32_t ret = fakeStub->ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
}

/**
 * @tc.name: ProcessDataTest001
 * @tc.desc: Verify the ProcessProto function when WriteUint32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessDataTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    MessageParcel data;
    MessageParcel reply;
    int uid = UID_VALID_TEST;
    int pid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, WriteUint32).WillRepeatedly(testing::Return(false));

    int32_t ret = fakeStub->ProcessData(uid, pid, sessionName, data, reply);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
}

/**
 * @tc.name: ProcessDataTest002
 * @tc.desc: Verify the ProcessProto function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessDataTest002, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    MessageParcel data;
    MessageParcel reply;
    int uid = UID_VALID_TEST;
    int pid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(nullptr));

    int32_t ret = fakeStub->ProcessData(uid, pid, sessionName, data, reply);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_ERR);
}

/**
 * @tc.name: ProcessDataTest003
 * @tc.desc: Verify the ProcessProto function when SendRequest function return 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessDataTest003, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    MessageParcel data;
    MessageParcel reply;
    int uid = UID_VALID_TEST;
    int pid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(1));

    int32_t ret = fakeStub->ProcessData(uid, pid, sessionName, data, reply);
    EXPECT_EQ(ret, BINDER_CALLBACK_AUTHCOMM_ERR);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: ProcessDataTest004
 * @tc.desc: Verify the ProcessProto function when WriteUint64 function second return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessDataTest004, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    MessageParcel data;
    MessageParcel reply;
    int uid = UID_VALID_TEST;
    int pid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillOnce(Return(true)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_NONE));

    int32_t ret = fakeStub->ProcessData(uid, pid, sessionName, data, reply);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: ProcessDataTest005
 * @tc.desc: Verify the ProcessProto function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, ProcessDataTest005, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    MessageParcel data;
    MessageParcel reply;
    int uid = UID_VALID_TEST;
    int pid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_NONE));

    int32_t ret = fakeStub->ProcessData(uid, pid, sessionName, data, reply);
    EXPECT_EQ(ret, 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: AddDBinderCommAuthTest001
 * @tc.desc: Verify the AddDBinderCommAuth function when WriteUint32 function false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, AddDBinderCommAuthTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    pid_t pid = UID_VALID_TEST;
    uid_t uid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, WriteUint32).WillRepeatedly(testing::Return(false));

    int ret = fakeStub->AddDBinderCommAuth(pid, uid, sessionName);
    EXPECT_EQ(ret, IPC_STUB_WRITE_PARCEL_ERR);
}

/**
 * @tc.name: AddDBinderCommAuthTest002
 * @tc.desc: Verify the AddDBinderCommAuth function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, AddDBinderCommAuthTest002, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    pid_t pid = UID_VALID_TEST;
    uid_t uid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(nullptr));

    int ret = fakeStub->AddDBinderCommAuth(pid, uid, sessionName);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_ERR);
}

/**
 * @tc.name: AddDBinderCommAuthTest003
 * @tc.desc: Verify the AddDBinderCommAuth function when SendRequest function return 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, AddDBinderCommAuthTest003, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    pid_t pid = UID_VALID_TEST;
    uid_t uid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(1));

    int ret = fakeStub->AddDBinderCommAuth(pid, uid, sessionName);
    EXPECT_EQ(ret, BINDER_CALLBACK_AUTHCOMM_ERR);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: AddDBinderCommAuthTest004
 * @tc.desc: Verify the AddDBinderCommAuth function when SendRequest function return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, AddDBinderCommAuthTest004, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    pid_t pid = UID_VALID_TEST;
    uid_t uid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, WriteUint32(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint64(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteString(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_NONE));

    int ret = fakeStub->AddDBinderCommAuth(pid, uid, sessionName);
    EXPECT_EQ(ret, ERR_NONE);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: SaveDBinderDataTest001
 * @tc.desc: Verify the SaveDBinderData function when dbinderData_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, SaveDBinderDataTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    fakeStub->dbinderData_  = nullptr;
    std::string sessionName = SESSION_TEST;

    int32_t ret = fakeStub->SaveDBinderData(sessionName);
    EXPECT_EQ(ret, DBINDER_CALLBACK_MALLOC_ERR);
}

/**
 * @tc.name: SaveDBinderDataTest002
 * @tc.desc: Verify the SaveDBinderData function when dbinderData_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, SaveDBinderDataTest002, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    fakeStub->dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    std::string sessionName = SESSION_TEST;

    int32_t ret = fakeStub->SaveDBinderData(sessionName);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest001
 * @tc.desc: Verify the GetAndSaveDBinderData function when pid is 1 and uid is -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetAndSaveDBinderDataTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    int32_t ret = fakeStub->GetAndSaveDBinderData(PID_INVALID_TEST, UID_VALID_TEST);
    EXPECT_EQ(ret, DBINDER_CALLBACK_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest002
 * @tc.desc: Verify the GetAndSaveDBinderData function when pid is -1 and uid is 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetAndSaveDBinderDataTest002, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    int32_t ret = fakeStub->GetAndSaveDBinderData(PID_VALID_TEST, UID_VALID_TEST);
    EXPECT_EQ(ret, DBINDER_CALLBACK_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest003
 * @tc.desc: Verify the GetAndSaveDBinderData function when GetSAMgrObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetAndSaveDBinderDataTest003, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, GetSAMgrObject).WillOnce(Return(nullptr));
    int32_t ret = fakeStub->GetAndSaveDBinderData(PID_VALID_TEST, UID_VALID_TEST);
    EXPECT_EQ(ret, DBINDER_CALLBACK_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest004
 * @tc.desc: Verify the GetAndSaveDBinderData function when GetSessionNameForPidUid function return empty
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetAndSaveDBinderDataTest004, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_OBJECT_HANDLE);

    EXPECT_CALL(mock, GetSAMgrObject).WillOnce(Return(object));
    EXPECT_CALL(mock, GetSessionNameForPidUid).WillRepeatedly(Return(""));
    int32_t ret = fakeStub->GetAndSaveDBinderData(1, 1);
    EXPECT_EQ(ret, DBINDER_CALLBACK_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest005
 * @tc.desc: Verify the GetAndSaveDBinderData function
 * when AddDBinderCommAuth function return IPC_STUB_WRITE_PARCEL_ERR
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, GetAndSaveDBinderDataTest005, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    pid_t pid = UID_VALID_TEST;
    uid_t uid = PID_VALID_TEST;
    std::string sessionName = SESSION_TEST;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    sptr<IRemoteObject> object = new IPCObjectProxy(TEST_OBJECT_HANDLE);
    EXPECT_CALL(mock, GetSAMgrObject).WillOnce(Return(object));
    EXPECT_CALL(mock, GetSessionNameForPidUid).WillOnce(Return(SESSION_TEST));
    EXPECT_CALL(mock, WriteUint32).WillRepeatedly(testing::Return(false));
    fakeStub->AddDBinderCommAuth(pid, uid, sessionName);

    int32_t ret = fakeStub->GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, IPC_STUB_WRITE_PARCEL_ERR);
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Verify the Marshalling function when parcel is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, MarshallingTest001, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    Parcel parcel;
    sptr<IRemoteObject> object(nullptr);
    bool ret = fakeStub->Marshalling(parcel, object);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Verify the Marshalling function when dbinderData_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, MarshallingTest002, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    Parcel parcel;
    sptr<IRemoteObject> object(nullptr);
    fakeStub->dbinderData_  = nullptr;
    bool ret = fakeStub->Marshalling(parcel, object);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest003
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, MarshallingTest003, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    Parcel parcel;
    fakeStub->dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    NiceMock<DBinderCallbackStubInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(nullptr));

    bool ret = fakeStub->Marshalling(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest004
 * @tc.desc: Verify the Marshalling function when FlattenDBinderData function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, MarshallingTest004, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    Parcel parcel;
    fakeStub->dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(Return(invoker));
    EXPECT_CALL(mock, FlattenDBinderData).WillRepeatedly(Return(false));

    bool ret = fakeStub->Marshalling(parcel);
    EXPECT_FALSE(ret);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest005
 * @tc.desc: Verify the Marshalling function when FlattenObject function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, MarshallingTest005, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    Parcel parcel;
    fakeStub->dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(Return(invoker));
    EXPECT_CALL(mock, FlattenDBinderData).WillRepeatedly(Return(true));
    EXPECT_CALL(*invoker, FlattenObject).WillRepeatedly(Return(false));

    bool ret = fakeStub->Marshalling(parcel);
    EXPECT_FALSE(ret);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest006
 * @tc.desc: Verify the Marshalling function return true
 * @tc.type: FUNC
 */
HWTEST_F(DBinderCallbackStubTest, MarshallingTest006, TestSize.Level1)
{
    sptr<DBinderCallbackStub> fakeStub = new (std::nothrow) DBinderCallbackStub(
        SERVICE_TEST, DEVICE_TEST, LOCALDEVICE_TEST, STUBINDEX_TEST, HANDLE_TEST, TOKENID_TEST);
    ASSERT_TRUE(fakeStub != nullptr);

    Parcel parcel;
    fakeStub->dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(Return(invoker));
    EXPECT_CALL(mock, FlattenDBinderData).WillRepeatedly(Return(true));
    EXPECT_CALL(*invoker, FlattenObject).WillRepeatedly(Return(true));

    bool ret = fakeStub->Marshalling(parcel);
    EXPECT_TRUE(ret);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}
}  // namespace OHOS
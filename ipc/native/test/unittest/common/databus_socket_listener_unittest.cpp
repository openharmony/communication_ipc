/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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

#define private public
#include "databus_socket_listener.h"
#include "iremote_invoker.h"
#include "ipc_thread_skeleton.h"
#include "dsoftbus_interface.h"
#include "dbinder_databus_invoker.h"

#undef protected
#undef private
#include "ipc_process_skeleton.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

class DatabusSocketListenerInterface {
public:
    DatabusSocketListenerInterface() {};
    virtual ~DatabusSocketListenerInterface() {};

    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener) = 0;
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener) = 0;

    virtual bool OnReceiveNewConnection(int32_t socketId, int peerPid, int peerUid,
        std::string peerName, std::string networkId) = 0;
    virtual void OnDatabusSessionServerSideClosed(int32_t socketId) = 0;
    virtual void OnDatabusSessionClientSideClosed(int32_t socketId) = 0;
    virtual void OnMessageAvailable(int32_t socketId, const char *data, uint32_t len) = 0;
    virtual IPCProcessSkeleton *GetCurrent() = 0;
    virtual sptr<IRemoteObject> GetSAMgrObject() = 0;
    virtual std::string GetDatabusName() = 0;
};
class DatabusSocketListenerInterfaceMock : public DatabusSocketListenerInterface {
public:
    DatabusSocketListenerInterfaceMock();
    ~DatabusSocketListenerInterfaceMock() override;

    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
    MOCK_METHOD1(Socket, int32_t(SocketInfo));
    MOCK_METHOD4(Listen, int32_t(int32_t, const QosTV*, uint32_t, const ISocketListener *));
    MOCK_METHOD4(Bind, int32_t(int32_t, const QosTV*, uint32_t, const ISocketListener *));
    MOCK_METHOD5(OnReceiveNewConnection, bool(int32_t, int, int, std::string, std::string));
    MOCK_METHOD1(OnDatabusSessionServerSideClosed, void(int32_t));
    MOCK_METHOD1(OnDatabusSessionClientSideClosed, void(int32_t));
    MOCK_METHOD3(OnMessageAvailable, void(int32_t, const char *, uint32_t));
    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton *());
    MOCK_METHOD0(GetSAMgrObject, sptr<IRemoteObject>());
    MOCK_METHOD0(GetDatabusName, std::string());
};
static void *g_interface = nullptr;

DatabusSocketListenerInterfaceMock::DatabusSocketListenerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DatabusSocketListenerInterfaceMock::~DatabusSocketListenerInterfaceMock()
{
    g_interface = nullptr;
}

static DatabusSocketListenerInterface *GetDatabusSocketListenerInterface()
{
    return reinterpret_cast<DatabusSocketListenerInterface *>(g_interface);
}

extern "C" {
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
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

    int32_t DBinderSoftbusClient::Bind(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
    {
        return GetDatabusSocketListenerInterface()->Bind(socket, qos, qosCount, listener);
    }

    bool DBinderDatabusInvoker::OnReceiveNewConnection(int32_t socketId, int peerPid, int peerUid,
        std::string peerName, std::string networkId)
    {
        return GetDatabusSocketListenerInterface()->OnReceiveNewConnection(
            socketId, peerPid, peerUid, peerName, networkId);
    }
    void DBinderDatabusInvoker::OnDatabusSessionServerSideClosed(int32_t socketId)
    {
        return GetDatabusSocketListenerInterface()->OnDatabusSessionServerSideClosed(socketId);
    }
    void DBinderDatabusInvoker::OnDatabusSessionClientSideClosed(int32_t socketId)
    {
        return GetDatabusSocketListenerInterface()->OnDatabusSessionClientSideClosed(socketId);
    }
    void DBinderDatabusInvoker::OnMessageAvailable(int32_t socketId, const char *data, uint32_t len)
    {
        return GetDatabusSocketListenerInterface()->OnMessageAvailable(socketId, data, len);
    }

    IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
    {
        return GetDatabusSocketListenerInterface()->GetCurrent();
    }
    sptr<IRemoteObject> IPCProcessSkeleton::GetSAMgrObject()
    {
        return GetDatabusSocketListenerInterface()->GetSAMgrObject();
    }
    std::string IPCProcessSkeleton::GetDatabusName()
    {
        return GetDatabusSocketListenerInterface()->GetDatabusName();
    }
}

class DatabusSocketListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void DatabusSocketListenerTest::SetUpTestCase()
{
}

void DatabusSocketListenerTest::TearDownTestCase()
{
}

void DatabusSocketListenerTest::SetUp() const
{
}

void DatabusSocketListenerTest::TearDown() const
{
}

/**
 * @tc.name: ServerOnBindTest001
 * @tc.desc: Verify the ServerOnBind function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest001, TestSize.Level1)  // line 87
{
    PeerSocketInfo info;
    std::string name = "abcdefg123456_654321";
    info.name = const_cast<char *>(name.c_str());
    char networkId[] = "255255255211";
    info.networkId = networkId;
    int32_t socket = 1001;
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new DBinderDatabusInvoker();

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(invoker));
    EXPECT_CALL(mock, OnReceiveNewConnection).WillOnce(Return(true));
    DatabusSocketListener::ServerOnBind(socket, info);
    
    EXPECT_EQ(socket, 1001);
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: ServerOnBindTest003
 * @tc.desc: Verify the ServerOnBind function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnBindTest003, TestSize.Level1)  // line 82
{
    PeerSocketInfo info;
    std::string name = "abcdefg123456_654321";
    info.name = const_cast<char *>(name.c_str());
    char networkId[] = "255255255211";
    info.networkId = networkId;
    int32_t socket = 1001;
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));
    DatabusSocketListener::ServerOnBind(socket, info);
    EXPECT_EQ(socket, 1001);
}

/**
 * @tc.name: ServerOnShutdownTest001
 * @tc.desc: Verify the ServerOnShutdown function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnShutdownTest001, TestSize.Level1)  // line 99
{
    ShutdownReason shutdownReason = ShutdownReason(0);
    int32_t socket = 1001;
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new DBinderDatabusInvoker();
        
    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(invoker));
    EXPECT_CALL(mock, OnDatabusSessionServerSideClosed).WillOnce(Return());
    DatabusSocketListener::ServerOnShutdown(socket, shutdownReason);
    EXPECT_EQ(socket, 1001);
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: ServerOnShutdownTest002
 * @tc.desc: Verify the ServerOnShutdown function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ServerOnShutdownTest002, TestSize.Level1)  // line 95
{
    ShutdownReason shutdownReason = ShutdownReason(0);
    int32_t socket = 1001;
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));
    DatabusSocketListener::ServerOnShutdown(socket, shutdownReason);
    EXPECT_EQ(socket, 1001);
}

/**
 * @tc.name: ClientOnBindTest001
 * @tc.desc: Verify the ClientOnBind function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ClientOnBindTest001, TestSize.Level1)  // line 104
{
    PeerSocketInfo info;
    int32_t socket = 1001;

    DatabusSocketListener::ClientOnBind(socket, info);
    EXPECT_EQ(socket, 1001);
}

/**
 * @tc.name: ClientOnShutdownTest001
 * @tc.desc: Verify the ClientOnShutdown function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ClientOnShutdownTest001, TestSize.Level1)  // line 112
{
    ShutdownReason shutdownReason = ShutdownReason(0);
    int32_t socket = 1001;
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));
    DatabusSocketListener::ClientOnShutdown(socket, shutdownReason);
    EXPECT_EQ(socket, 1001);
}

/**
 * @tc.name: ClientOnShutdownTest002
 * @tc.desc: Verify the ClientOnShutdown function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ClientOnShutdownTest002, TestSize.Level1)  // line 130
{
    ShutdownReason shutdownReason = ShutdownReason(0);
    int32_t socket = 1001;

    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new DBinderDatabusInvoker();
        
    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(invoker));
    EXPECT_CALL(mock, OnDatabusSessionClientSideClosed).WillOnce(Return());
    DatabusSocketListener::ClientOnShutdown(socket, shutdownReason);
    EXPECT_EQ(socket, 1001);
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: OnBytesReceivedTest001
 * @tc.desc: Verify the OnBytesReceived function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, OnBytesReceivedTest001, TestSize.Level1)  // line 138
{
    int32_t socket = 1001;
    char data[] = "just for test";
    uint32_t dataLen = sizeof(data);
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));
    DatabusSocketListener::OnBytesReceived(socket, data, dataLen);
    EXPECT_EQ(socket, 1001);
}

/**
 * @tc.name: OnBytesReceivedTest002
 * @tc.desc: Verify the OnBytesReceived function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, OnBytesReceivedTest002, TestSize.Level1)  // line 143
{
    int32_t socket = 1001;
    char data[] = "just for test";
    uint32_t dataLen = sizeof(data);
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new DBinderDatabusInvoker();

    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(invoker));
    EXPECT_CALL(mock, OnMessageAvailable).WillOnce(Return());
    DatabusSocketListener::OnBytesReceived(socket, data, dataLen);
    EXPECT_EQ(socket, 1001);
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: StartServerListenerTest001
 * @tc.desc: Verify the StartServerListener function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListenerTest001, TestSize.Level1)  // line 158
{
    DatabusSocketListener listener;
    const std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, Socket).WillOnce(Return(-1));

    int32_t ret = listener.StartServerListener(ownName);
    EXPECT_EQ(ret, SOCKET_ID_INVALID);
}

/**
 * @tc.name: StartServerListenerTest002
 * @tc.desc: Verify the StartServerListener function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListenerTest002, TestSize.Level1)  // line 161
{
    DatabusSocketListener listener;
    const std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, Socket).WillOnce(Return(1001));
    EXPECT_CALL(mock, Listen).WillOnce(Return(SOFTBUS_TRANS_CREATE_SOCKET_SERVER_FAILED));

    int32_t ret = listener.StartServerListener(ownName);
    EXPECT_EQ(ret, SOCKET_ID_INVALID);
}

/**
 * @tc.name: StartServerListenerTest003
 * @tc.desc: Verify the StartServerListener function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, StartServerListenerTest003, TestSize.Level1)  // line 167
{
    DatabusSocketListener listener;
    const std::string ownName = "ownName";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, Socket).WillOnce(Return(1001));
    EXPECT_CALL(mock, Listen).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = listener.StartServerListener(ownName);
    EXPECT_EQ(ret, 1001);
}

/**
 * @tc.name: CreateClientSocketTest001
 * @tc.desc: Verify the CreateClientSocket function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, CreateClientSocketTest001, TestSize.Level1)  // line 215
{
    DatabusSocketListener listener;
    const std::string ownName = "ownName";
    const std::string peerName = "peerName";
    const std::string &networkId = "255255255251";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, Socket).WillOnce(Return(-1));

    int32_t ret = listener.CreateClientSocket(ownName, peerName, networkId);
    EXPECT_EQ(ret, SOCKET_ID_INVALID);
}

/**
 * @tc.name: CreateClientSocketTest002
 * @tc.desc: Verify the CreateClientSocket function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, CreateClientSocketTest002, TestSize.Level1)  // line 220
{
    DatabusSocketListener listener;
    const std::string ownName = "ownName";
    const std::string peerName = "peerName";
    const std::string &networkId = "255255255251";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, Socket).WillOnce(Return(1001));
    EXPECT_CALL(mock, Bind).WillOnce(Return(SOFTBUS_TRANS_CREATE_SOCKET_SERVER_FAILED));

    int32_t ret = listener.CreateClientSocket(ownName, peerName, networkId);
    EXPECT_EQ(ret, SOCKET_ID_INVALID);
}

/**
 * @tc.name: CreateClientSocketTest003
 * @tc.desc: Verify the CreateClientSocket function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, CreateClientSocketTest003, TestSize.Level1)  // line 235
{
    DatabusSocketListener listener;
    const std::string ownName = "ownName";
    const std::string peerName = "peerName";
    const std::string &networkId = "255255255251";
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, Socket).WillOnce(Return(1001));
    EXPECT_CALL(mock, Bind).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = listener.CreateClientSocket(ownName, peerName, networkId);
    EXPECT_EQ(ret, 1001);
}

/**
 * @tc.name: CreateClientSocketTest004
 * @tc.desc: Verify the CreateClientSocket function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, CreateClientSocketTest004, TestSize.Level1)  // line 202
{
    DatabusSocketListener listener;
    const std::string ownName = "ownName";
    const std::string peerName = "peerName";
    const std::string &networkId = "255255255251";

    int32_t ret = listener.CreateClientSocket(ownName, peerName, networkId);
    EXPECT_EQ(ret, 1001);
}

/**
 * @tc.name: ShutdownSocketTest001
 * @tc.desc: Verify the ShutdownSocket function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, ShutdownSocket001, TestSize.Level1)  // line 243
{
    DatabusSocketListener listener;
    int32_t socket = 1001;

    listener.ShutdownSocket(socket);
    EXPECT_EQ(socket, 1001);
}

/**
 * @tc.name: RemoveSessionNameTest001
 * @tc.desc: Verify the RemoveSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, RemoveSessionNameTest001, TestSize.Level1)  // line 268
{
    DatabusSocketListener listener;
    NiceMock<DatabusSocketListenerInterfaceMock> mock;
    IPCProcessSkeleton *current = nullptr;

    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(current));

    listener.RemoveSessionName();
    EXPECT_EQ(current, nullptr);
}

/**
 * @tc.name: RemoveSessionNameTest002
 * @tc.desc: Verify the RemoveSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, RemoveSessionNameTest002, TestSize.Level1)  // line 273
{
    DatabusSocketListener listener;
    IPCProcessSkeleton *current = new IPCProcessSkeleton();
    NiceMock<DatabusSocketListenerInterfaceMock> mock;

    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(current));

    listener.RemoveSessionName();
    EXPECT_NE(current, nullptr);
    if (current != nullptr) {
        delete current;
    }
}

/**
 * @tc.name: GetPidAndUidBySessionName001
 * @tc.desc: Verify the GetPidAndUidFromServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, GetPidAndUidBySessionName001, TestSize.Level1)
{
    int32_t pid = -1;
    int32_t uid = -1;
    bool ret = DatabusSocketListener::GetPidAndUidFromServiceName("DBinder1_1", pid, uid);
    ASSERT_TRUE(ret);
    ASSERT_EQ(pid, 1);
    ASSERT_EQ(pid, 1);

    pid = 0;
    uid = 0;
    ret = DatabusSocketListener::GetPidAndUidFromServiceName("DBinder-1_-1", pid, uid);
    ASSERT_TRUE(ret);
    ASSERT_EQ(pid, -1);
    ASSERT_EQ(pid, -1);
}

/**
 * @tc.name: GetPidAndUidBySessionName002
 * @tc.desc: Verify the GetPidAndUidFromServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, GetPidAndUidBySessionName002, TestSize.Level1)
{
    int32_t pid = -1;
    int32_t uid = -1;
    bool ret = DatabusSocketListener::GetPidAndUidFromServiceName("", pid, uid);
    ASSERT_FALSE(ret);

    ret = DatabusSocketListener::GetPidAndUidFromServiceName("abc", pid, uid);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetPidAndUidBySessionName003
 * @tc.desc: Verify the GetPidAndUidFromServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, GetPidAndUidBySessionName003, TestSize.Level1)
{
    int32_t pid = -1;
    int32_t uid = -1;
    bool ret = DatabusSocketListener::GetPidAndUidFromServiceName("DBinder", pid, uid);
    ASSERT_FALSE(ret);

    ret = DatabusSocketListener::GetPidAndUidFromServiceName("DBinder1_", pid, uid);
    ASSERT_FALSE(ret);

    ret = DatabusSocketListener::GetPidAndUidFromServiceName("DBinder_1", pid, uid);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetPidAndUidBySessionName004
 * @tc.desc: Verify the GetPidAndUidFromServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DatabusSocketListenerTest, GetPidAndUidBySessionName004, TestSize.Level1)
{
    std::string invalidIntegerStr = std::to_string(UINT64_MAX);

    int32_t pid = -1;
    int32_t uid = -1;
    std::string sessionName = "DBinder" + invalidIntegerStr + "_1";
    bool ret = DatabusSocketListener::GetPidAndUidFromServiceName(sessionName, pid, uid);
    ASSERT_FALSE(ret);

    sessionName = "DBinder1_" + invalidIntegerStr;
    ret = DatabusSocketListener::GetPidAndUidFromServiceName(sessionName, pid, uid);
    ASSERT_FALSE(ret);

    sessionName = "DBinder" + invalidIntegerStr + "_" + invalidIntegerStr;
    ret = DatabusSocketListener::GetPidAndUidFromServiceName(sessionName, pid, uid);
    ASSERT_FALSE(ret);
}
} // end of OHOS
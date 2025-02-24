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

#include "dbinder_remote_listener.h"
#include "dbinder_service.h"
#include "dbinder_softbus_client.h"
#include "ipc_types.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace {
    const std::string PEER_NETWORK_ID_TEST = "test_network_id";
    const std::string OWN_SESSION_NAME = "own_session";
    const std::string DEVICE_ID_TEST = "123";
    const int32_t EXPRCTED_SOCKET_ID_TEST = 123;
}

namespace OHOS {
class DBinderRemoteListenerInterface {
public:
    DBinderRemoteListenerInterface() {};
    virtual ~DBinderRemoteListenerInterface() {};

    virtual int32_t DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName) = 0;
    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener) = 0;
    virtual void Shutdown(int32_t socket) = 0;
    virtual int32_t SendBytes(int32_t socket, const void *data, uint32_t len) = 0;
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener) = 0;
};
class DBinderRemoteListenerInterfaceMock : public DBinderRemoteListenerInterface {
public:
    DBinderRemoteListenerInterfaceMock();
    ~DBinderRemoteListenerInterfaceMock() override;

    MOCK_METHOD3(DBinderGrantPermission, int32_t(int32_t uid, int32_t pid, const std::string &socketName));
    MOCK_METHOD1(Socket, int32_t(SocketInfo));
    MOCK_METHOD4(Listen, int32_t(int32_t, const QosTV*, uint32_t, const ISocketListener *));
    MOCK_METHOD1(Shutdown, void(int32_t));
    MOCK_METHOD3(SendBytes, int32_t(int32_t socket, const void *data, uint32_t len));
    MOCK_METHOD4(Bind, int32_t(int32_t, const QosTV*, uint32_t, const ISocketListener *));
};
static void *g_interface = nullptr;

DBinderRemoteListenerInterfaceMock::DBinderRemoteListenerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DBinderRemoteListenerInterfaceMock::~DBinderRemoteListenerInterfaceMock()
{
    g_interface = nullptr;
}

static DBinderRemoteListenerInterface *GetDBinderRemoteListenerInterface()
{
    return reinterpret_cast<DBinderRemoteListenerInterfaceMock *>(g_interface);
}

extern "C" {
    int32_t DBinderSoftbusClient::DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName)
    {
        if (g_interface == nullptr) {
            return 0;
        }
        return GetDBinderRemoteListenerInterface()->DBinderGrantPermission(uid, pid, socketName);
    }

    int32_t DBinderSoftbusClient::Socket(SocketInfo info)
    {
        if (g_interface == nullptr) {
            return 0;
        }
        return GetDBinderRemoteListenerInterface()->Socket(info);
    }

    int32_t DBinderSoftbusClient::Listen(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
    {
        if (g_interface == nullptr) {
            return 0;
        }
        return GetDBinderRemoteListenerInterface()->Listen(socket, qos, qosCount, listener);
    }

    void DBinderSoftbusClient::Shutdown(int32_t socket)
    {
        if (g_interface == nullptr) {
            return ;
        }
        return GetDBinderRemoteListenerInterface()->Shutdown(socket);
    }

    int32_t DBinderSoftbusClient::SendBytes(int32_t socket, const void *data, uint32_t len)
    {
        if (g_interface == nullptr) {
            return 0;
        }
        return GetDBinderRemoteListenerInterface()->SendBytes(socket, data, len);
    }

    int32_t DBinderSoftbusClient::Bind(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
    {
        if (g_interface == nullptr) {
            return 0;
        }
        return GetDBinderRemoteListenerInterface()->Bind(socket, qos, qosCount, listener);
    }
}
}

class DBinderRemoteListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DBinderRemoteListenerTest::SetUpTestCase()
{
}

void DBinderRemoteListenerTest::TearDownTestCase()
{
}

void DBinderRemoteListenerTest::SetUp()
{
}

void DBinderRemoteListenerTest::TearDown()
{
}

/**
 * @tc.name: GetPeerSocketIdTest001
 * @tc.desc: Verify the GetPeerSocketId function
 * when the corresponding socketID can be found based on the peerNetworkId
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, GetPeerSocketIdTest001, TestSize.Level1) {
    DBinderRemoteListener listener;
    std::string peerNetworkId = PEER_NETWORK_ID_TEST;
    int32_t expectedSocketId = EXPRCTED_SOCKET_ID_TEST;
    DBinderRemoteListener::serverSocketInfos_[peerNetworkId] = expectedSocketId;

    int32_t result = listener.GetPeerSocketId(peerNetworkId);
    EXPECT_EQ(result, expectedSocketId);
    DBinderRemoteListener::serverSocketInfos_.erase(peerNetworkId);
}

/**
 * @tc.name: GetPeerSocketIdTest002
 * @tc.desc: Verify the GetPeerSocketId function
 * when the corresponding socketID can not be found based on the peerNetworkId
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, GetPeerSocketIdTest002, TestSize.Level1) {
    DBinderRemoteListener listener;
    std::string peerNetworkId = PEER_NETWORK_ID_TEST;

    int32_t result = listener.GetPeerSocketId(peerNetworkId);
    EXPECT_EQ(result, SOCKET_ID_INVALID);
}

/**
 * @tc.name: StartListenerTest001
 * @tc.desc: Verify the StartListener function return true
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, StartListenerTest001, TestSize.Level1) {
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    int32_t mockSocketId = EXPRCTED_SOCKET_ID_TEST;

    EXPECT_CALL(mockClient, DBinderGrantPermission).WillOnce(testing::Return(ERR_NONE));
    EXPECT_CALL(mockClient, Socket).WillOnce(testing::Return(mockSocketId));
    EXPECT_CALL(mockClient, Listen).WillOnce(testing::Return(SOFTBUS_OK));

    bool result = listener.StartListener();
    EXPECT_TRUE(result);
    result = listener.StopListener();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: StartListenerTest002
 * @tc.desc: Verify the StartListener function when DBinderGrantPermission function execution return failed
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, StartListenerTest002, TestSize.Level1) {
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;

    EXPECT_CALL(mockClient, DBinderGrantPermission).WillOnce(testing::Return(1));

    bool result = listener.StartListener();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: StartListenerTest003
 * @tc.desc: Verify the StartListener function when Socket function execution return failed
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, StartListenerTest003, TestSize.Level1) {
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;

    EXPECT_CALL(mockClient, DBinderGrantPermission).WillOnce(testing::Return(ERR_NONE));
    EXPECT_CALL(mockClient, Socket).WillOnce(testing::Return(-1));

    bool result = listener.StartListener();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: StartListenerTest004
 * @tc.desc: Verify the StartListener function when Listen function execution return failed
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, StartListenerTest004, TestSize.Level1) {
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    int32_t mockSocketId = EXPRCTED_SOCKET_ID_TEST;

    EXPECT_CALL(mockClient, DBinderGrantPermission).WillOnce(testing::Return(ERR_NONE));
    EXPECT_CALL(mockClient, Socket).WillOnce(testing::Return(mockSocketId));
    EXPECT_CALL(mockClient, Listen).WillOnce(testing::Return(2));

    bool result = listener.StartListener();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SendDataToRemoteTest001
 * @tc.desc: Verify SendDataToRemote function when message is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, SendDataToRemoteTest001, TestSize.Level1)
{
    DBinderRemoteListener listener;
    const std::string networkId = PEER_NETWORK_ID_TEST;
    EXPECT_EQ(listener.SendDataToRemote(networkId, nullptr), false);
}

/**
 * @tc.name: SendDataToRemoteTest002
 * @tc.desc: Verify SendDataToRemote function when networkId not exist in the map
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, SendDataToRemoteTest002, TestSize.Level1)
{
    DBinderRemoteListener listener;
    const std::string networkId = PEER_NETWORK_ID_TEST;
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    EXPECT_EQ(listener.SendDataToRemote(networkId, &message), false);
}

/**
 * @tc.name: SendDataToRemoteTest003
 * @tc.desc: Verify SendDataToRemote function when SendBytes function execution return 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, SendDataToRemoteTest003, TestSize.Level1)
{
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    const std::string networkId = PEER_NETWORK_ID_TEST;
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);

    EXPECT_CALL(mockClient, SendBytes).WillRepeatedly(testing::Return(1));
    EXPECT_EQ(listener.SendDataToRemote(networkId, &message), false);
    DBinderRemoteListener::clientSocketInfos_.clear();
}

/**
 * @tc.name: SendDataToRemoteTest004
 * @tc.desc: Verify SendDataToRemote function when SendBytes function execution return 0
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, SendDataToRemoteTest004, TestSize.Level1)
{
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    const std::string networkId = PEER_NETWORK_ID_TEST;
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);

    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(EXPRCTED_SOCKET_ID_TEST));
    EXPECT_CALL(mockClient, Bind).WillRepeatedly(testing::Return(SOFTBUS_OK));
    listener.CreateClientSocket(networkId);
    
    EXPECT_CALL(mockClient, SendBytes).WillRepeatedly(testing::Return(0));
    EXPECT_EQ(listener.SendDataToRemote(networkId, &message), true);
    DBinderRemoteListener::clientSocketInfos_.clear();
}

/**
 * @tc.name: SendDataReplyTest001
 * @tc.desc: Verify SendDataReply function when message is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, SendDataReplyTest001, TestSize.Level1)
{
    DBinderRemoteListener listener;
    const std::string networkId = PEER_NETWORK_ID_TEST;
    EXPECT_EQ(listener.SendDataReply(networkId, nullptr), false);
}

/**
 * @tc.name: SendDataReplyTest002
 * @tc.desc: Verify SendDataReply function when networkId not exist in the map
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, SendDataReplyTest002, TestSize.Level1)
{
    DBinderRemoteListener listener;
    const std::string networkId = PEER_NETWORK_ID_TEST;
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    EXPECT_EQ(listener.SendDataReply(networkId, &message), false);
}

/**
 * @tc.name: SendDataReplyTest003
 * @tc.desc: Verify SendDataReply function when SendBytes function return 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, SendDataReplyTest003, TestSize.Level1)
{
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    const std::string networkId = PEER_NETWORK_ID_TEST;
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    int32_t expectedSocketId = EXPRCTED_SOCKET_ID_TEST;
    DBinderRemoteListener::serverSocketInfos_[networkId] = expectedSocketId;

    EXPECT_CALL(mockClient, SendBytes(testing::_, testing::_, testing::_)).WillRepeatedly(testing::Return(1));

    EXPECT_EQ(listener.SendDataReply(networkId, &message), false);
    DBinderRemoteListener::serverSocketInfos_.erase(networkId);
}

/**
 * @tc.name: SendDataReplyTest004
 * @tc.desc: Verify SendDataReply function when SendBytes function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, SendDataReplyTest004, TestSize.Level1)
{
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    const std::string networkId = PEER_NETWORK_ID_TEST;
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    int32_t expectedSocketId = EXPRCTED_SOCKET_ID_TEST;
    DBinderRemoteListener::serverSocketInfos_[networkId] = expectedSocketId;

    EXPECT_CALL(mockClient, SendBytes(testing::_, testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    EXPECT_EQ(listener.SendDataReply(networkId, &message), true);
    DBinderRemoteListener::serverSocketInfos_.erase(networkId);
}

/**
 * @tc.name: CreateClientSocketTest001
 * @tc.desc: Verify CreateClientSocket function when peerNetworkId is ""
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, CreateClientSocketTest001, TestSize.Level1)
{
    DBinderRemoteListener listener;
    const std::string peerNetworkId = "";
    int32_t ret = listener.CreateClientSocket(peerNetworkId);
    EXPECT_EQ(ret, SOCKET_ID_INVALID);
}

/**
 * @tc.name: CreateClientSocketTest002
 * @tc.desc: Verify CreateClientSocket function when Socket function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, CreateClientSocketTest002, TestSize.Level1)
{
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    const std::string peerNetworkId = PEER_NETWORK_ID_TEST;

    EXPECT_CALL(mockClient, Socket(testing::_)).WillRepeatedly(testing::Return(0));

    int32_t ret = listener.CreateClientSocket(peerNetworkId);
    EXPECT_EQ(ret, SOCKET_ID_INVALID);
}

/**
 * @tc.name: CreateClientSocketTest003
 * @tc.desc: Verify CreateClientSocket function when Bind function return SOFTBUS_TRANS_CREATE_SOCKET_SERVER_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, CreateClientSocketTest003, TestSize.Level1)
{
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    const std::string peerNetworkId = PEER_NETWORK_ID_TEST;

    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(EXPRCTED_SOCKET_ID_TEST));
    EXPECT_CALL(mockClient, Bind).WillRepeatedly(testing::Return(SOFTBUS_TRANS_CREATE_SOCKET_SERVER_FAILED));

    int32_t ret = listener.CreateClientSocket(peerNetworkId);
    EXPECT_EQ(ret, SOCKET_ID_INVALID);
}

/**
 * @tc.name: CreateClientSocketTest004
 * @tc.desc: Verify CreateClientSocket function when bind function return SOFTBUS_OK
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerTest, CreateClientSocketTest004, TestSize.Level1)
{
    DBinderRemoteListener listener;
    NiceMock<DBinderRemoteListenerInterfaceMock> mockClient;
    const std::string peerNetworkId = PEER_NETWORK_ID_TEST;

    EXPECT_CALL(mockClient, Socket).WillRepeatedly(testing::Return(EXPRCTED_SOCKET_ID_TEST));
    EXPECT_CALL(mockClient, Bind).WillRepeatedly(testing::Return(SOFTBUS_OK));

    int32_t ret = listener.CreateClientSocket(peerNetworkId);
    EXPECT_EQ(ret, EXPRCTED_SOCKET_ID_TEST);
    DBinderRemoteListener::clientSocketInfos_.clear();
}
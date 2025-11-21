/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dbinder_service.h"
#include "gtest/gtest.h"
#include "rpc_log.h"
#include "log_tags.h"
#define private public
#include "dbinder_remote_listener.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

class DBinderRemoteListenerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    const std::string NETWORKID_TEST = "123456789";
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "DBinderRemoteListenerUnitTest" };
};

void DBinderRemoteListenerUnitTest::SetUp() {}

void DBinderRemoteListenerUnitTest::TearDown() {}

void DBinderRemoteListenerUnitTest::SetUpTestCase() {}

void DBinderRemoteListenerUnitTest::TearDownTestCase() {}

/**
 * @tc.name: CreateClientSocket_001
 * @tc.desc: Verify CreateClientSocket function when networkId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, CreateClientSocket_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "";
    EXPECT_EQ(dBinderRemoteListener.CreateClientSocket(networkId), SOCKET_ID_INVALID);
}

/**
 * @tc.name: CreateClientSocket_002
 * @tc.desc: Verify CreateClientSocket function when networkId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, CreateClientSocket_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "networkIdTest";
    EXPECT_EQ(dBinderRemoteListener.CreateClientSocket(networkId), SOCKET_ID_INVALID);
}


/**
 * @tc.name: ServerOnBind_001
 * @tc.desc: Verify ServerOnBind function when binding a valid socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnBind_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = 1;
    PeerSocketInfo info = {
        .networkId = const_cast<char *>(NETWORKID_TEST.c_str()),
    };

    dBinderRemoteListener.ServerOnBind(socketId, info);
    EXPECT_EQ(dBinderRemoteListener.serverSocketInfos_.size(), 1);
    dBinderRemoteListener.serverSocketInfos_.clear();
}

/**
 * @tc.name: ServerOnBind_002
 * @tc.desc: Verify ServerOnBind function when binding a valid socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnBind_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = -1;
    PeerSocketInfo info = {
        .networkId = const_cast<char *>(NETWORKID_TEST.c_str()),
    };

    dBinderRemoteListener.ServerOnBind(socketId, info);
    EXPECT_EQ(dBinderRemoteListener.serverSocketInfos_.size(), 1);
    dBinderRemoteListener.serverSocketInfos_.clear();
}

/**
 * @tc.name: ServerOnBind_003
 * @tc.desc: Verify ServerOnBind function when binding a valid socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnBind_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = INT_MAX;
    PeerSocketInfo info = {
        .networkId = const_cast<char *>(NETWORKID_TEST.c_str()),
    };

    dBinderRemoteListener.ServerOnBind(socketId, info);
    EXPECT_EQ(dBinderRemoteListener.serverSocketInfos_.size(), 1);
    dBinderRemoteListener.serverSocketInfos_.clear();
}

/**
 * @tc.name: ServerOnShutdown_001
 * @tc.desc: Verify ServerOnShutdown function when shutdown occurs for an existing socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnShutdown_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = NETWORKID_TEST;
    int32_t socketId = 1;
    dBinderRemoteListener.serverSocketInfos_[networkId] = socketId;
    dBinderRemoteListener.ServerOnShutdown(socketId, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(dBinderRemoteListener.serverSocketInfos_.size(), 0);
}

/**
 * @tc.name: ServerOnShutdown_002
 * @tc.desc: Verify ServerOnShutdown function when shutdown occurs for a non-existing socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnShutdown_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = 1;
    dBinderRemoteListener.ServerOnShutdown(socketId, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(dBinderRemoteListener.serverSocketInfos_.size(), 0);
}

/**
 * @tc.name: ServerOnShutdown_003
 * @tc.desc: Verify ServerOnShutdown function when shutdown occurs for an existing socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnShutdown_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = NETWORKID_TEST;
    int32_t socketId = -1;
    dBinderRemoteListener.serverSocketInfos_[networkId] = socketId;
    dBinderRemoteListener.ServerOnShutdown(socketId, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(dBinderRemoteListener.serverSocketInfos_.size(), 0);
}

/**
 * @tc.name: ServerOnShutdown_004
 * @tc.desc: Verify ServerOnShutdown function when shutdown occurs for a non-existing socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnShutdown_004, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = -1;
    dBinderRemoteListener.ServerOnShutdown(socketId, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(dBinderRemoteListener.serverSocketInfos_.size(), 0);
}

/**
 * @tc.name: OnBytesReceived_001
 * @tc.desc: Verify OnBytesReceived function when data is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OnBytesReceived_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const char* data = nullptr;
    auto len = sizeof(struct DHandleEntryTxRx);
    int32_t socketId = 1;
    dBinderRemoteListener.OnBytesReceived(socketId, data, len);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: OnBytesReceived_002
 * @tc.desc: Verify OnBytesReceived function when data length is zero.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OnBytesReceived_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const char *data = "testdatas";
    ssize_t len = 0;
    int32_t socketId = 1;
    dBinderRemoteListener.OnBytesReceived(socketId, data, len);
    EXPECT_EQ(len < static_cast<ssize_t>(sizeof(struct DHandleEntryTxRx)), true);
}

/**
 * @tc.name: OnBytesReceived_003
 * @tc.desc: Verify OnBytesReceived function when data is nullptr and length is valid.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OnBytesReceived_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    auto len = sizeof(struct DHandleEntryTxRx);
    dBinderRemoteListener.OnBytesReceived(1, nullptr, len);
    EXPECT_EQ(dBinderRemoteListener.listenSocketId_, SOCKET_ID_INVALID);
}

/**
 * @tc.name: OnBytesReceived_004
 * @tc.desc: Verify OnBytesReceived function when data length is less than required size.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OnBytesReceived_004, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const char *data = "testdata";
    uint32_t len = sizeof(struct DHandleEntryTxRx) - 1;
    int32_t socketId = 1;
    dBinderRemoteListener.OnBytesReceived(socketId, data, len);
    EXPECT_EQ(len != sizeof(struct DHandleEntryTxRx), true);
}

/**
 * @tc.name: OnBytesReceived_005
 * @tc.desc: Verify OnBytesReceived function when data length and content are valid.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OnBytesReceived_005, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    DHandleEntryTxRx data;
    data.head.len = sizeof(DHandleEntryTxRx);
    uint32_t len = sizeof(DHandleEntryTxRx);
    int32_t socketId = 1;
    dBinderRemoteListener.OnBytesReceived(socketId, &data, len);
    EXPECT_EQ(dBinderRemoteListener.listenSocketId_, SOCKET_ID_INVALID);
}

/**
 * @tc.name: OnBytesReceived_006
 * @tc.desc: Verify OnBytesReceived function when data is nullptr and length is Invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OnBytesReceived_006, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    auto len = 0;
    dBinderRemoteListener.OnBytesReceived(1, nullptr, len);
    EXPECT_EQ(dBinderRemoteListener.listenSocketId_, SOCKET_ID_INVALID);
}

/**
 * @tc.name: OnBytesReceived_007
 * @tc.desc: Verify OnBytesReceived function when socketid is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OnBytesReceived_007, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const char *data = "testdatas";
    ssize_t len = 10;
    int32_t socketId = -1;
    dBinderRemoteListener.OnBytesReceived(socketId, data, len);
    EXPECT_EQ(len < static_cast<ssize_t>(sizeof(struct DHandleEntryTxRx)), true);
}

/**
 * @tc.name: SendDataToRemote_001
 * @tc.desc: Verify SendDataToRemote function when message is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, SendDataToRemote_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "testdeviceid";
    EXPECT_EQ(dBinderRemoteListener.SendDataToRemote(deviceId, nullptr), false);
}

/**
 * @tc.name: SendDataToRemote_002
 * @tc.desc: Verify SendDataToRemote function when deviceId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, SendDataToRemote_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    EXPECT_EQ(dBinderRemoteListener.SendDataToRemote(deviceId, &message), false);
}

/**
 * @tc.name: SendDataToRemote_003
 * @tc.desc: Verify SendDataToRemote function when deviceId is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, SendDataToRemote_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "123";
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    EXPECT_EQ(dBinderRemoteListener.SendDataToRemote(deviceId, &message), false);
}

/**
 * @tc.name: StartListener_001
 * @tc.desc: Verify StartListener function.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, StartListener_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    EXPECT_EQ(dBinderRemoteListener.StartListener(), false);
}

/**
 * @tc.name: StopListener_001
 * @tc.desc: Verify StopListener function.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, StopListener_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    EXPECT_EQ(dBinderRemoteListener.StopListener(), true);
}

/**
 * @tc.name: ShutdownSocket_001
 * @tc.desc: Verify ShutdownSocket function when deviceId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ShutdownSocket_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    EXPECT_EQ(dBinderRemoteListener.ShutdownSocket(deviceId), false);
}

/**
 * @tc.name: ShutdownSocket_002
 * @tc.desc: Verify ShutdownSocket function.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ShutdownSocket_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = NETWORKID_TEST;
    int32_t socketId = 123;
    dBinderRemoteListener.clientSocketInfos_[networkId] = socketId;
    EXPECT_TRUE(dBinderRemoteListener.ShutdownSocket(networkId));
}

/**
 * @tc.name: ShutdownSocket_003
 * @tc.desc: Verify ShutdownSocket function when clientSocketInfo is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ShutdownSocket_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string networkId = NETWORKID_TEST;
    EXPECT_EQ(dBinderRemoteListener.ShutdownSocket(networkId), false);
}

/**
 * @tc.name: QueryOrNewDeviceLock_001
 * @tc.desc: Verify QueryOrNewDeviceLock function.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, QueryOrNewDeviceLock_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    dBinderRemoteListener.QueryOrNewDeviceLock(deviceId);
    const std::string deviceId1 = "123456";
    std::shared_ptr<DeviceLock> lockInfo = nullptr;
    lockInfo = dBinderRemoteListener.QueryOrNewDeviceLock(deviceId1);
    EXPECT_TRUE(lockInfo != nullptr);
}

/**
 * @tc.name: QueryOrNewDeviceLock_002
 * @tc.desc: Verify QueryOrNewDeviceLock function.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, QueryOrNewDeviceLock_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string networkId = NETWORKID_TEST;
    std::shared_ptr<DeviceLock> lockInfo = std::make_shared<struct DeviceLock>();
    EXPECT_TRUE(lockInfo != nullptr);
    dBinderRemoteListener.deviceLockMap_[networkId] = lockInfo;
    EXPECT_EQ(dBinderRemoteListener.QueryOrNewDeviceLock(networkId), lockInfo);
}

/**
 * @tc.name: SendDataReply_001
 * @tc.desc: Verify SendDataReply function when message is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, SendDataReply_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    EXPECT_EQ(dBinderRemoteListener.SendDataReply(deviceId, nullptr), false);
}

/**
 * @tc.name: SendDataReply_002
 * @tc.desc: Verify SendDataReply function when message has valid data.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, SendDataReply_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    DHandleEntryTxRx message;
    message.deviceIdInfo.fromDeviceId[0] = 't';
    EXPECT_EQ(dBinderRemoteListener.SendDataReply(deviceId, &message), false);
}

/**
 * @tc.name: SendDataReply_003
 * @tc.desc: Verify SendDataReply function when deviceId is valid and message has data.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, SendDataReply_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "12345";
    DHandleEntryTxRx message;
    message.deviceIdInfo.fromDeviceId[0] = 't';
    EXPECT_EQ(dBinderRemoteListener.SendDataReply(deviceId, &message), false);
}

/**
 * @tc.name: OpenSoftbusSession_001
 * @tc.desc: Verify CreateClientSocket function with valid peerDeviceId.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OpenSoftbusSession_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string peerDeviceId = "12345";
    EXPECT_EQ(dBinderRemoteListener.CreateClientSocket(peerDeviceId), SOCKET_ID_INVALID);
}

/**
 * @tc.name: OpenSoftbusSession_002
 * @tc.desc: Verify CreateClientSocket function with null peerDeviceId.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, OpenSoftbusSession_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string peerDeviceId = "";
    EXPECT_EQ(dBinderRemoteListener.CreateClientSocket(peerDeviceId), SOCKET_ID_INVALID);
}

/**
 * @tc.name: GetPeerSocketId_001
 * @tc.desc: Verify GetPeerSocketId function when networkId is valid.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, GetPeerSocketId_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = NETWORKID_TEST;
    int32_t socketId = 123;
    dBinderRemoteListener.serverSocketInfos_[networkId] = socketId;
    EXPECT_EQ(dBinderRemoteListener.GetPeerSocketId(networkId), socketId);
}

/**
 * @tc.name: GetPeerSocketId_002
 * @tc.desc: Verify GetPeerSocketId function when networkId is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, GetPeerSocketId_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "nonexistentNetworkId";
    EXPECT_EQ(dBinderRemoteListener.GetPeerSocketId(networkId), SOCKET_ID_INVALID);
}

/**
 * @tc.name: GetPeerSocketId_003
 * @tc.desc: Verify GetPeerSocketId function when networkId is null.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, GetPeerSocketId_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "";
    EXPECT_EQ(dBinderRemoteListener.GetPeerSocketId(networkId), SOCKET_ID_INVALID);
}

/**
 * @tc.name: ClientOnBind_001
 * @tc.desc: Verify ClientOnBind function.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ClientOnBind_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = 1;
    PeerSocketInfo info = {
        .networkId = const_cast<char *>(NETWORKID_TEST.c_str()),
    };

    dBinderRemoteListener.ClientOnBind(socketId, info);
    EXPECT_EQ(dBinderRemoteListener.listenSocketId_, SOCKET_ID_INVALID);
}

/**
 * @tc.name: ClientOnBind_002
 * @tc.desc: Verify ClientOnBind function.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ClientOnBind_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = -1;
    PeerSocketInfo info = {
        .networkId = const_cast<char *>(NETWORKID_TEST.c_str()),
    };

    dBinderRemoteListener.ClientOnBind(socketId, info);
    EXPECT_EQ(dBinderRemoteListener.listenSocketId_, SOCKET_ID_INVALID);
}

/**
 * @tc.name: ClientOnBind_003
 * @tc.desc: Verify ClientOnBind function.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ClientOnBind_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = INT_MAX;
    PeerSocketInfo info = {
        .networkId = const_cast<char *>(NETWORKID_TEST.c_str()),
    };

    dBinderRemoteListener.ClientOnBind(socketId, info);
    EXPECT_EQ(dBinderRemoteListener.listenSocketId_, SOCKET_ID_INVALID);
}

/**
 * @tc.name: ClientOnShutdown_001
 * @tc.desc: Verify ClientOnShutdown function when shutdown occurs for an existing socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ClientOnShutdown_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "networkId";
    int32_t socketId = 1;
    dBinderRemoteListener.clientSocketInfos_[networkId] = socketId;
    dBinderRemoteListener.ClientOnShutdown(socketId, SHUTDOWN_REASON_PEER);

    EXPECT_EQ(dBinderRemoteListener.clientSocketInfos_.size(), 0);
}

/**
 * @tc.name: ClientOnShutdown_002
 * @tc.desc: Verify ClientOnShutdown function when shutdown occurs for a non-existing socket.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ClientOnShutdown_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "networkId";
    int32_t socketId = 1;
    dBinderRemoteListener.clientSocketInfos_[networkId] = socketId;
    dBinderRemoteListener.ClientOnShutdown(2, SHUTDOWN_REASON_PEER);

    EXPECT_EQ(dBinderRemoteListener.clientSocketInfos_.size(), 1);
}

/**
 * @tc.name: ClientOnShutdown_003
 * @tc.desc: Verify ClientOnShutdown function with multiple entries.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderRemoteListenerUnitTest, ClientOnShutdown_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "networkId";
    std::string networkId1 = "networkId1";
    int32_t socketId = 1;
    int32_t socketId1 = 2;
    dBinderRemoteListener.clientSocketInfos_[networkId] = socketId;
    EXPECT_EQ(dBinderRemoteListener.clientSocketInfos_.size(), 1);

    dBinderRemoteListener.clientSocketInfos_[networkId1] = socketId1;
    EXPECT_EQ(dBinderRemoteListener.clientSocketInfos_.size(), 2);

    dBinderRemoteListener.ClientOnShutdown(socketId, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(dBinderRemoteListener.clientSocketInfos_.size(), 1);
    dBinderRemoteListener.ClientOnShutdown(socketId1, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(dBinderRemoteListener.clientSocketInfos_.size(), 0);
}

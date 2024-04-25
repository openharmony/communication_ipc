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

HWTEST_F(DBinderRemoteListenerUnitTest, CreateClientSocket_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "";
    EXPECT_EQ(dBinderRemoteListener.CreateClientSocket(networkId), SOCKET_ID_INVALID);
}

HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnBind_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    int32_t socketId = 1;
    PeerSocketInfo info = {
        .networkId = const_cast<char *>(NETWORKID_TEST.c_str()),
    };

    dBinderRemoteListener.ServerOnBind(socketId, info);
    EXPECT_NE(dBinderRemoteListener.serverSocketInfos_.size(), 0);
}

HWTEST_F(DBinderRemoteListenerUnitTest, ServerOnShutdown_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    std::string networkId = "networkId";
    int32_t socketId = 1;
    dBinderRemoteListener.clientSocketInfos_[networkId] = socketId;
    dBinderRemoteListener.ServerOnShutdown(socketId, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(dBinderRemoteListener.serverSocketInfos_.size(), 0);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onbytesreceived_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const char* data = nullptr;
    auto len = sizeof(struct DHandleEntryTxRx);
    int32_t socketId = 1;
    dBinderRemoteListener.OnBytesReceived(socketId, data, len);
    EXPECT_EQ(data, nullptr);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onbytesreceived_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const char *data = "testdatas";
    ssize_t len = 0;
    int32_t socketId = 1;
    dBinderRemoteListener.OnBytesReceived(socketId, data, len);
    EXPECT_EQ(len < static_cast<ssize_t>(sizeof(struct DHandleEntryTxRx)), true);
}

HWTEST_F(DBinderRemoteListenerUnitTest, onbytesreceived_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    auto len = sizeof(struct DHandleEntryTxRx);
    dBinderRemoteListener.OnBytesReceived(1, nullptr, len);
    EXPECT_EQ(dBinderRemoteListener.listenSocketId_, SOCKET_ID_INVALID);
}

HWTEST_F(DBinderRemoteListenerUnitTest, senddatatoremote_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "testdeviceid";
    EXPECT_EQ(dBinderRemoteListener.SendDataToRemote(deviceId, nullptr), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, senddatatoremote_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    EXPECT_EQ(dBinderRemoteListener.SendDataToRemote(deviceId, &message), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, senddatatoremote_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "123";
    DHandleEntryTxRx message;
    message.head.len = sizeof(DHandleEntryTxRx);
    EXPECT_EQ(dBinderRemoteListener.SendDataToRemote(deviceId, &message), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, startlistener_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    EXPECT_EQ(dBinderRemoteListener.StartListener(), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, StopListener_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    EXPECT_EQ(dBinderRemoteListener.StopListener(), true);
}

HWTEST_F(DBinderRemoteListenerUnitTest, closedatabussession_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    EXPECT_EQ(dBinderRemoteListener.ShutdownSocket(deviceId), false);
}

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

HWTEST_F(DBinderRemoteListenerUnitTest, SendDataReply_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    EXPECT_EQ(dBinderRemoteListener.SendDataReply(deviceId, nullptr), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, SendDataReply_002, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "";
    DHandleEntryTxRx message;
    message.deviceIdInfo.fromDeviceId[0] = 't';
    EXPECT_EQ(dBinderRemoteListener.SendDataReply(deviceId, &message), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, SendDataReply_003, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string deviceId = "12345";
    DHandleEntryTxRx message;
    message.deviceIdInfo.fromDeviceId[0] = 't';
    EXPECT_EQ(dBinderRemoteListener.SendDataReply(deviceId, &message), false);
}

HWTEST_F(DBinderRemoteListenerUnitTest, OpenSoftbusSession_001, TestSize.Level1)
{
    DBinderRemoteListener dBinderRemoteListener;
    const std::string peerDeviceId = "12345";
    EXPECT_EQ(dBinderRemoteListener.CreateClientSocket(peerDeviceId), SOCKET_ID_INVALID);
}

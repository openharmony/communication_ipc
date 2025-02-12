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
#include <dlfcn.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>

#include "dbinder_softbus_client.h"

static constexpr const char *SOFTBUS_PATH_NAME = "/system/lib/platformsdk/libsoftbus_client.z.so";

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace {
constexpr int32_t TEST_PID = 2000;
constexpr int32_t TEST_UID = 1000;
constexpr int32_t TEST_SOCKET_ID = 1;
constexpr uint32_t TEST_LEN = 10;
constexpr uint32_t TEST_QOS_COUNT = 1;
constexpr std::string TEST_SOCKET_NAME = "test_socket";
constexpr std::string TEST_PKG_NAME = "test_package";
constexpr std::string TEST_DEVICE_ID = "test_deviceID";
}

class DBinderSoftbusClientTest : public ::testing::Test
{
    public:
        DBinderSoftbusClient* client = nullptr;
        static void SetUpTestCase(void);
        static void TearDownTestCase(void);
        void SetUp();
        void TearDown();
};

void DBinderSoftbusClientTest::SetUpTestCase()
{
}

void DBinderSoftbusClientTest::TearDownTestCase()
{
}

void DBinderSoftbusClientTest::SetUp()
{
}

void DBinderSoftbusClientTest::TearDown()
{
}

/**
 * @tc.name: OpenSoftbusClientSoTest001
 * @tc.desc: Verify the OpenSoftbusClientSo function when isLoaded_ is true
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, OpenSoftbusClientSoTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.soHandle_ = dlopen(SOFTBUS_PATH_NAME, RTLD_NOW | RTLD_NODELETE);
    client.isLoaded_ = true;

    EXPECT_TRUE(client.OpenSoftbusClientSo());
}

/**
 * @tc.name: OpenSoftbusClientSoTest002
 * @tc.desc: Verify the OpenSoftbusClientSo function when isLoaded_ is false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, OpenSoftbusClientSoTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;

    EXPECT_FALSE(client.OpenSoftbusClientSo());
}

/**
 * @tc.name: DBinderGrantPermissionTest001
 * @tc.desc: Verify the DBinderGrantPermission function
 * when grantPermissionFunc_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, DBinderGrantPermissionTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    int32_t uid = TEST_UID;
    int32_t pid = TEST_PID;
    std::string socketName = TEST_SOCKET_NAME;
    int32_t result = client.DBinderGrantPermission(uid, pid, socketName);
    EXPECT_EQ(result, SOFTBUS_CLIENT_INSTANCE_EXIT);
}

/**
 * @tc.name: DBinderGrantPermissionTest002
 * @tc.desc: Verify the DBinderGrantPermission function
 * when grantPermissionFunc_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, DBinderGrantPermissionTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    int32_t uid = TEST_UID;
    int32_t pid = TEST_PID;
    std::string socketName = TEST_SOCKET_NAME;
    client.grantPermissionFunc_ = [](int32_t, int32_t, const char*) { return 0; };
    int32_t result = client.DBinderGrantPermission(uid, pid, socketName);
    EXPECT_TRUE(result == SOFTBUS_CLIENT_SUCCESS);
}

/**
 * @tc.name: DBinderRemovePermissionTest001
 * @tc.desc: Verify the DBinderRemovePermission function
 * when removePermissionFunc_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, DBinderRemovePermissionTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    std::string socketName = TEST_SOCKET_NAME;
    int32_t result = client.DBinderRemovePermission(socketName);
    EXPECT_EQ(result, SOFTBUS_CLIENT_INSTANCE_EXIT);
}

/**
 * @tc.name: DBinderRemovePermissionTest002
 * @tc.desc: Verify the DBinderRemovePermission function
 * when removePermissionFunc_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, DBinderRemovePermissionTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    std::string socketName = TEST_SOCKET_NAME;
    client.removePermissionFunc_ = [](const char*) { return 0; };
    int32_t result = client.DBinderRemovePermission(socketName);
    EXPECT_EQ(result, SOFTBUS_CLIENT_SUCCESS);
}

/**
 * @tc.name: GetLocalNodeDeviceIdTest001
 * @tc.desc: Verify the GetLocalNodeDeviceId function
 * when getLocalNodeDeviceInfoFunc_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, GetLocalNodeDeviceIdTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    std::string pkgName = TEST_PKG_NAME;
    std::string devId = TEST_DEVICE_ID;
    int32_t result = client.GetLocalNodeDeviceId(pkgName, devId);
    EXPECT_EQ(result, SOFTBUS_CLIENT_INSTANCE_EXIT);
}

/**
 * @tc.name: GetLocalNodeDeviceIdTest002
 * @tc.desc: Verify the GetLocalNodeDeviceId function
 * when getLocalNodeDeviceInfoFunc_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, GetLocalNodeDeviceIdTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    std::string pkgName = TEST_PKG_NAME;
    std::string devId = TEST_DEVICE_ID;
    client.getLocalNodeDeviceInfoFunc_ = [](const char*, NodeBasicInfo*) { return 0; };
    int32_t result = client.GetLocalNodeDeviceId(pkgName, devId);
    EXPECT_TRUE(result == SOFTBUS_CLIENT_SUCCESS);
}

/**
 * @tc.name: SocketTest001
 * @tc.desc: Verify the Socket function
 * when SocketFunc is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, SocketTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    SocketInfo info;
    int32_t result = client.Socket(info);
    EXPECT_EQ(result, SOFTBUS_CLIENT_INSTANCE_EXIT);
}

/**
 * @tc.name: SocketTest002
 * @tc.desc: Verify the Socket function
 * when SocketFunc is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, SocketTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    SocketInfo info;
    client.socketFunc_ = [](SocketInfo) { return 0; };
    int32_t result = client.Socket(info);
    EXPECT_TRUE(result == SOFTBUS_CLIENT_SUCCESS);
}

/**
 * @tc.name: ListenTest001
 * @tc.desc: Verify the Listen function
 * when listenFunc_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, ListenTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    int32_t socket = TEST_SOCKET_ID;
    QosTV qos[1];
    uint32_t qosCount = TEST_QOS_COUNT;
    ISocketListener listener;
    int32_t result = client.Listen(socket, qos, qosCount, &listener);
    EXPECT_EQ(result, SOFTBUS_CLIENT_INSTANCE_EXIT);
}

/**
 * @tc.name: ListenTest002
 * @tc.desc: Verify the Listen function
 * when listenFunc_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, ListenTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    int32_t socket = TEST_SOCKET_ID;
    QosTV qos[1];
    uint32_t qosCount = TEST_QOS_COUNT;
    ISocketListener listener;
    client.listenFunc_ = [](int32_t, const QosTV[], uint32_t, const ISocketListener*) { return 0; };
    int32_t result = client.Listen(socket, qos, qosCount, &listener);
    EXPECT_EQ(result, SOFTBUS_CLIENT_SUCCESS);
}

/**
 * @tc.name: BindTest001
 * @tc.desc: Verify the Bind function
 * when bindFunc_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, BindTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    int32_t socket = TEST_SOCKET_ID;
    QosTV qos[1];
    uint32_t qosCount = TEST_QOS_COUNT;
    ISocketListener listener;
    int32_t result = client.Bind(socket, qos, qosCount, &listener);
    EXPECT_EQ(result, SOFTBUS_CLIENT_INSTANCE_EXIT);
}

/**
 * @tc.name: BindTest002
 * @tc.desc: Verify the Bind function
 * when bindFunc_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, BindTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    int32_t socket = TEST_SOCKET_ID;
    QosTV qos[1];
    uint32_t qosCount = TEST_QOS_COUNT;
    ISocketListener listener;
    client.bindFunc_ = [](int32_t, const QosTV[], uint32_t, const ISocketListener*) { return 0; };
    int32_t result = client.Bind(socket, qos, qosCount, &listener);
    EXPECT_EQ(result, SOFTBUS_CLIENT_SUCCESS);
}

/**
 * @tc.name: SendBytesTest001
 * @tc.desc: Verify the SendBytes function
 * when sendBytesFunc_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, SendBytesTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    int32_t socket = TEST_SOCKET_ID;
    void *data = nullptr;
    uint32_t len = TEST_LEN;
    int32_t result = client.SendBytes(socket, data, len);
    EXPECT_EQ(result, SOFTBUS_CLIENT_INSTANCE_EXIT);
}

/**
 * @tc.name: SendBytesTest002
 * @tc.desc: Verify the SendBytes function
 * when sendBytesFunc_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, SendBytesTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    int32_t socket = TEST_SOCKET_ID;
    void *data = nullptr;
    uint32_t len = TEST_LEN;
    client.sendBytesFunc_ = [](int32_t, const void*, uint32_t) { return 0; };
    int32_t result = client.SendBytes(socket, data, len);
    EXPECT_EQ(result, SOFTBUS_CLIENT_SUCCESS);
}

/**
 * @tc.name: SendMessageTest001
 * @tc.desc: Verify the SendMessage function
 * when sendMessageFunc_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, SendMessageTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    int32_t socket = TEST_SOCKET_ID;
    void *data = nullptr;
    uint32_t len = TEST_LEN;
    int32_t result = client.SendMessage(socket, data, len);
    EXPECT_EQ(result, SOFTBUS_CLIENT_INSTANCE_EXIT);
}

/**
 * @tc.name: SendMessageTest002
 * @tc.desc: Verify the SendMessage function
 * when sendMessageFunc_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, SendMessageTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    int32_t socket = TEST_SOCKET_ID;
    void *data = nullptr;
    uint32_t len = TEST_LEN;
    client.sendMessageFunc_ = [](int32_t, const void*, uint32_t) { return 0; };
    int32_t result = client.SendMessage(socket, data, len);
    EXPECT_EQ(result, SOFTBUS_CLIENT_SUCCESS);
}

/**
 * @tc.name: ShutdownTest001
 * @tc.desc: Verify the Shutdown function
 * when shutdownFunc_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, ShutdownTest001, TestSize.Level1) {
    DBinderSoftbusClient client;
    client.exitFlag_ = true;
    int32_t socket = TEST_SOCKET_ID;
    client.Shutdown(socket);
    SUCCEED();
}

/**
 * @tc.name: ShutdownTest002
 * @tc.desc: Verify the Shutdown function
 * when shutdownFunc_ is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientTest, ShutdownTest002, TestSize.Level1) {
    DBinderSoftbusClient client;
    int32_t socket = TEST_SOCKET_ID;
    client.soHandle_ = dlopen(SOFTBUS_PATH_NAME, RTLD_NOW | RTLD_NODELETE);
    client.shutdownFunc_ = (DBinderSoftbusClient::ShutdownFunc)dlsym(client.soHandle_, "Shutdown");
    client.Shutdown(socket);
    SUCCEED();
}
/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <securec.h>
#include <string>
#include <vector>

#include "dbinder_softbus_client.h"
#include "dbinder_softbus_client_death_recipient.h"

using namespace testing::ext;

namespace OHOS {
namespace {
constexpr int32_t TEST_UID = 1000;
constexpr int32_t TEST_PID = 2000;
constexpr char TEST_SOCKET_NAME[] = "test_socket";
constexpr char TEST_PKG_NAME[] = "test_package";
constexpr char TEST_DEVICE_ID_1[] = "device_1";
constexpr char TEST_DEVICE_ID_2[] = "device_2";

int32_t g_grantPermissionCallCount = 0;
int32_t g_removePermissionCallCount = 0;
bool g_freeNodeInfoCalled = false;

int32_t GrantPermissionMock(int32_t uid, int32_t pid, const char *socketName)
{
    ++g_grantPermissionCallCount;
    return (uid == TEST_UID && pid == TEST_PID && socketName != nullptr) ? SOFTBUS_CLIENT_SUCCESS : SOFTBUS_IPC_ERR;
}

int32_t RemovePermissionMock(const char *socketName)
{
    ++g_removePermissionCallCount;
    return (socketName != nullptr) ? SOFTBUS_CLIENT_SUCCESS : SOFTBUS_IPC_ERR;
}

int32_t GetAllNodeDeviceInfoMock(const char *, NodeBasicInfo **info, int32_t *infoNum)
{
    auto *nodeInfo = new (std::nothrow) NodeBasicInfo[2] {};
    if (nodeInfo == nullptr) {
        return SOFTBUS_IPC_ERR;
    }
    if (memcpy_s(nodeInfo[0].networkId, sizeof(nodeInfo[0].networkId), TEST_DEVICE_ID_1, sizeof(TEST_DEVICE_ID_1)) !=
        EOK) {
        delete[] nodeInfo;
        return SOFTBUS_IPC_ERR;
    }
    if (memcpy_s(nodeInfo[1].networkId, sizeof(nodeInfo[1].networkId), TEST_DEVICE_ID_2, sizeof(TEST_DEVICE_ID_2)) !=
        EOK) {
        delete[] nodeInfo;
        return SOFTBUS_IPC_ERR;
    }
    *info = nodeInfo;
    *infoNum = 2;
    return SOFTBUS_CLIENT_SUCCESS;
}

int32_t GetAllNodeDeviceInfoWithNullInfoMock(const char *, NodeBasicInfo **info, int32_t *infoNum)
{
    *info = nullptr;
    *infoNum = 0;
    return SOFTBUS_CLIENT_SUCCESS;
}

int32_t GetAllNodeDeviceInfoFailedMock(const char *, NodeBasicInfo **info, int32_t *infoNum)
{
    *info = nullptr;
    *infoNum = 0;
    return SOFTBUS_IPC_ERR;
}

void FreeNodeInfoMock(NodeBasicInfo *info)
{
    g_freeNodeInfoCalled = true;
    delete[] info;
}

class DBinderSoftbusClientStateGuard {
public:
    DBinderSoftbusClientStateGuard()
    {
        auto &client = DBinderSoftbusClient::GetInstance();
        savedExitFlag_ = client.exitFlag_.load();
        savedSessionRefCount_ = client.mapSessionRefCount_;
    }

    ~DBinderSoftbusClientStateGuard()
    {
        auto &client = DBinderSoftbusClient::GetInstance();
        client.exitFlag_ = savedExitFlag_;
        client.mapSessionRefCount_ = savedSessionRefCount_;
    }

private:
    bool savedExitFlag_ = false;
    std::map<std::string, int32_t> savedSessionRefCount_;
};
} // namespace

class DBinderSoftbusClientAdditionalTest : public testing::Test {
public:
    void SetUp() override
    {
        g_grantPermissionCallCount = 0;
        g_removePermissionCallCount = 0;
        g_freeNodeInfoCalled = false;
    }
};

/**
 * @tc.name: DBinderGrantPermissionRefCountTest001
 * @tc.desc: Verify repeated grant requests reuse the same permission entry and increase its reference count.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientAdditionalTest, DBinderGrantPermissionRefCountTest001, TestSize.Level1)
{
    DBinderSoftbusClient client;
    client.grantPermissionFunc_ = GrantPermissionMock;

    EXPECT_EQ(client.DBinderGrantPermission(TEST_UID, TEST_PID, TEST_SOCKET_NAME), SOFTBUS_CLIENT_SUCCESS);
    EXPECT_EQ(client.DBinderGrantPermission(TEST_UID, TEST_PID, TEST_SOCKET_NAME), SOFTBUS_CLIENT_SUCCESS);
    ASSERT_TRUE(client.mapSessionRefCount_.find(TEST_SOCKET_NAME) != client.mapSessionRefCount_.end());
    EXPECT_EQ(client.mapSessionRefCount_[TEST_SOCKET_NAME], 2);
    EXPECT_EQ(g_grantPermissionCallCount, 2);
}

/**
 * @tc.name: DBinderRemovePermissionRefCountTest001
 * @tc.desc: Verify remove permission only reaches the softbus callback when the last reference is released.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientAdditionalTest, DBinderRemovePermissionRefCountTest001, TestSize.Level1)
{
    DBinderSoftbusClient client;
    client.removePermissionFunc_ = RemovePermissionMock;
    client.mapSessionRefCount_[TEST_SOCKET_NAME] = 2;

    EXPECT_EQ(client.DBinderRemovePermission(TEST_SOCKET_NAME), SOFTBUS_CLIENT_SUCCESS);
    ASSERT_TRUE(client.mapSessionRefCount_.find(TEST_SOCKET_NAME) != client.mapSessionRefCount_.end());
    EXPECT_EQ(client.mapSessionRefCount_[TEST_SOCKET_NAME], 1);
    EXPECT_EQ(g_removePermissionCallCount, 0);

    EXPECT_EQ(client.DBinderRemovePermission(TEST_SOCKET_NAME), SOFTBUS_CLIENT_SUCCESS);
    EXPECT_TRUE(client.mapSessionRefCount_.find(TEST_SOCKET_NAME) == client.mapSessionRefCount_.end());
    EXPECT_EQ(g_removePermissionCallCount, 1);
}

/**
 * @tc.name: DBinderRemovePermissionRefCountTest002
 * @tc.desc: Verify remove permission still reaches the softbus callback when there is no cached reference entry.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientAdditionalTest, DBinderRemovePermissionRefCountTest002, TestSize.Level1)
{
    DBinderSoftbusClient client;
    client.removePermissionFunc_ = RemovePermissionMock;

    EXPECT_EQ(client.DBinderRemovePermission(TEST_SOCKET_NAME), SOFTBUS_CLIENT_SUCCESS);
    EXPECT_TRUE(client.mapSessionRefCount_.empty());
    EXPECT_EQ(g_removePermissionCallCount, 1);
}

/**
 * @tc.name: GetAllNodeDeviceIdTest003
 * @tc.desc: Verify GetAllNodeDeviceId collects all device IDs and releases node info when available.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientAdditionalTest, GetAllNodeDeviceIdTest003, TestSize.Level1)
{
    DBinderSoftbusClient client;
    client.getAllNodeDeviceInfoFunc_ = GetAllNodeDeviceInfoMock;
    client.freeNodeInfoFunc_ = FreeNodeInfoMock;
    std::vector<std::string> deviceIds;

    EXPECT_EQ(client.GetAllNodeDeviceId(TEST_PKG_NAME, deviceIds), SOFTBUS_CLIENT_SUCCESS);
    ASSERT_EQ(deviceIds.size(), 2);
    EXPECT_EQ(deviceIds[0], TEST_DEVICE_ID_1);
    EXPECT_EQ(deviceIds[1], TEST_DEVICE_ID_2);
    EXPECT_TRUE(g_freeNodeInfoCalled);
}

/**
 * @tc.name: GetAllNodeDeviceIdTest004
 * @tc.desc: Verify GetAllNodeDeviceId returns success when the softbus query succeeds but there is no node info.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientAdditionalTest, GetAllNodeDeviceIdTest004, TestSize.Level1)
{
    DBinderSoftbusClient client;
    client.getAllNodeDeviceInfoFunc_ = GetAllNodeDeviceInfoWithNullInfoMock;
    client.freeNodeInfoFunc_ = FreeNodeInfoMock;
    std::vector<std::string> deviceIds;

    EXPECT_EQ(client.GetAllNodeDeviceId(TEST_PKG_NAME, deviceIds), SOFTBUS_CLIENT_SUCCESS);
    EXPECT_TRUE(deviceIds.empty());
    EXPECT_FALSE(g_freeNodeInfoCalled);
}

/**
 * @tc.name: GetAllNodeDeviceIdTest005
 * @tc.desc: Verify GetAllNodeDeviceId reports query failure when softbus returns an error.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientAdditionalTest, GetAllNodeDeviceIdTest005, TestSize.Level1)
{
    DBinderSoftbusClient client;
    client.getAllNodeDeviceInfoFunc_ = GetAllNodeDeviceInfoFailedMock;
    client.freeNodeInfoFunc_ = FreeNodeInfoMock;
    std::vector<std::string> deviceIds;

    EXPECT_EQ(client.GetAllNodeDeviceId(TEST_PKG_NAME, deviceIds), SOFTBUS_CLIENT_GET_DEVICE_INFO_FAILED);
    EXPECT_TRUE(deviceIds.empty());
    EXPECT_FALSE(g_freeNodeInfoCalled);
}

/**
 * @tc.name: OnRemoteDiedTest001
 * @tc.desc: Verify the death recipient clears cached session permissions through the singleton recovery flow.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderSoftbusClientAdditionalTest, OnRemoteDiedTest001, TestSize.Level1)
{
    DBinderSoftbusClientStateGuard stateGuard;
    auto &client = DBinderSoftbusClient::GetInstance();
    client.exitFlag_ = false;
    client.mapSessionRefCount_.clear();
    client.mapSessionRefCount_[TEST_SOCKET_NAME] = 1;

    DbinderSoftbusClientDeathRecipient recipient;
    wptr<IRemoteObject> remote;
    recipient.OnRemoteDied(remote);

    EXPECT_TRUE(client.mapSessionRefCount_.empty());
}
} // namespace OHOS

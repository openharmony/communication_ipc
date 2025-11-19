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

#include "ipc_remote_object_internal.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {

bool g_deathRecipientIsCalled = false;

class IPCRemoteObjectInternalTest : public ::testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCRemoteObjectInternalTest::SetUpTestCase()
{
}

void IPCRemoteObjectInternalTest::TearDownTestCase()
{
}

void IPCRemoteObjectInternalTest::SetUp()
{
}

void IPCRemoteObjectInternalTest::TearDown()
{
}

/**
 * @tc.name: OnRemoteDied001
 * @tc.desc: Verify the OnRemoteDied function when deathRecipientCallback_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCRemoteObjectInternalTest, OnRemoteDied001, TestSize.Level1)
{
    OH_OnDeathRecipientCallback deathRecipientCallback = nullptr;
    OH_OnDeathRecipientDestroyCallback destroyCallback = nullptr;
    void *userData = nullptr;
    IPCDeathRecipient remoteObject(deathRecipientCallback, destroyCallback, userData);
    EXPECT_EQ(remoteObject.deathRecipientCallback_, nullptr);
    remoteObject.OnRemoteDied(nullptr);
}

/**
 * @tc.name: OnRemoteDied002
 * @tc.desc: Verify the OnRemoteDied function when deathRecipientCallback_ not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCRemoteObjectInternalTest, OnRemoteDied002, TestSize.Level1)
{
    OH_OnDeathRecipientCallback deathRecipientCallback = [](void *userData) { g_deathRecipientIsCalled = true; };
    OH_OnDeathRecipientDestroyCallback destroyCallback = nullptr;
    void *userData = nullptr;
    IPCDeathRecipient remoteObject(deathRecipientCallback, destroyCallback, userData);
    EXPECT_NE(remoteObject.deathRecipientCallback_, nullptr);
    g_deathRecipientIsCalled = false;
    remoteObject.OnRemoteDied(nullptr);
    EXPECT_TRUE(g_deathRecipientIsCalled);
    g_deathRecipientIsCalled = false;
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Verify the OnRemoteRequest function return OH_IPC_INNER_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(IPCRemoteObjectInternalTest, OnRemoteRequest001, TestSize.Level1)
{
    std::u16string desc = u"desc";
    OH_OnRemoteRequestCallback requestCallback = nullptr;
    OH_OnRemoteDestroyCallback destroyCallback = nullptr;
    void *userData = nullptr;
    OHIPCRemoteServiceStub stub(desc, requestCallback, destroyCallback, userData);
    EXPECT_EQ(stub.requestCallback_, nullptr);
    uint32_t code = 0;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OH_IPC_INNER_ERROR);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Verify the OnRemoteRequest function return OH_IPC_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(IPCRemoteObjectInternalTest, OnRemoteRequest002, TestSize.Level1)
{
    std::u16string desc = u"desc";
    OH_OnRemoteRequestCallback requestCallback = [](uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply,
        void *userData) -> int { return OH_IPC_SUCCESS; };
    OH_OnRemoteDestroyCallback destroyCallback = nullptr;
    void *userData = nullptr;
    OHIPCRemoteServiceStub stub(desc, requestCallback, destroyCallback, userData);
    EXPECT_NE(stub.requestCallback_, nullptr);
    uint32_t code = 0;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OH_IPC_SUCCESS);
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: Verify the OnRemoteRequest function return OH_IPC_INVALID_USER_ERROR_CODE
 * @tc.type: FUNC
 */
HWTEST_F(IPCRemoteObjectInternalTest, OnRemoteRequest003, TestSize.Level1)
{
    std::u16string desc = u"desc";
    OH_OnRemoteRequestCallback requestCallback = [](uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply,
        void *userData) -> int { return OH_IPC_ERROR_CODE_BASE - 1; };
    OH_OnRemoteDestroyCallback destroyCallback = nullptr;
    void *userData = nullptr;
    OHIPCRemoteServiceStub stub(desc, requestCallback, destroyCallback, userData);
    EXPECT_NE(stub.requestCallback_, nullptr);
    uint32_t code = 0;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OH_IPC_INVALID_USER_ERROR_CODE);
}
} // namespace OHOS
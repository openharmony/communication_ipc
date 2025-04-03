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

#include <gtest/gtest.h>

#include <cstring>
#include <securec.h>
#include <mutex>
#include <condition_variable>

#include "if_system_ability_manager.h"
#include "ipc_inner_object.h"
#include "ipc_kit.h"
#include "ipc_test_helper.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "test_capi_skeleton.h"
#include "test_service_command.h"
#include "test_service_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

static constexpr uint32_t ON_CALLBACK_REPLIED_INT = 1598311760;

namespace OHOS {
class IpcCApiRemoteObjectModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IpcCApiModuleTest" };

    void ResetCallbackReply();
    [[nodiscard]] int GetCallbackReply() const;

    static void OnDeathRecipientCallback(void *userData);
    static void OnDeathRecipientDestroyCallback(void *userData);
    static OHIPCRemoteProxy* IpcCreateIPCRemoteProxy(IPCTestHelper &helper);
    static void* MemAllocator(int32_t len);

private:
    int callBackReply_{ 0 };
    static inline IPCTestHelper *globalHelper_ = { nullptr };
};

void IpcCApiRemoteObjectModuleTest::SetUpTestCase()
{
    if (globalHelper_ == nullptr) {
        globalHelper_ = new IPCTestHelper();
        bool res = globalHelper_->PrepareTestSuite();
        ASSERT_TRUE(res);
    }
}

void IpcCApiRemoteObjectModuleTest::TearDownTestCase()
{
    if (globalHelper_ != nullptr) {
        bool res = globalHelper_->TearDownTestSuite();
        ASSERT_TRUE(res);
        delete globalHelper_;
        globalHelper_ = nullptr;
    }
}

void IpcCApiRemoteObjectModuleTest::SetUp()
{
    callBackReply_ = 0;
}

void IpcCApiRemoteObjectModuleTest::TearDown()
{}

void IpcCApiRemoteObjectModuleTest::ResetCallbackReply()
{
    callBackReply_ = 0;
}

int IpcCApiRemoteObjectModuleTest::GetCallbackReply() const
{
    return callBackReply_;
}


void IpcCApiRemoteObjectModuleTest::OnDeathRecipientCallback(void *userData)
{
    ZLOGI(LABEL, "OnDeathRecipientCallback modify callBackReply_");
    if (userData != nullptr) {
        auto *test = static_cast<IpcCApiRemoteObjectModuleTest *>(userData);
        test->callBackReply_ = ON_CALLBACK_REPLIED_INT;
    }
}

void IpcCApiRemoteObjectModuleTest::OnDeathRecipientDestroyCallback(void *userData)
{
    if (userData != nullptr) {
        auto *test = static_cast<IpcCApiRemoteObjectModuleTest *>(userData);
        test->callBackReply_ = ON_CALLBACK_REPLIED_INT;
    }
}


void* IpcCApiRemoteObjectModuleTest::MemAllocator(int32_t len)
{
    if (len <= 0) {
        ZLOGE(LABEL, "Invalid length passed to MemAllocator: %d", len);
        return nullptr;
    }
    void *buffer = malloc(len);
    if (buffer == nullptr) {
        ZLOGE(LABEL, "Failed to allocate memory of size: %d", len);
        return nullptr;
    }
    (void)memset_s(buffer, len, 0, len);
    return buffer;
}

OHIPCRemoteProxy* IpcCApiRemoteObjectModuleTest::IpcCreateIPCRemoteProxy(IPCTestHelper &helper)
{
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    if (!res) {
        ZLOGE(LABEL, "Failed to start test app");
        return nullptr;
    }

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        ZLOGE(LABEL, "Failed to get system ability manager");
        return nullptr;
    }

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    if (object == nullptr) {
        ZLOGE(LABEL, "Failed to get system ability object");
        return nullptr;
    }

    OHIPCRemoteProxy *remoteProxy = CreateIPCRemoteProxy(object);
    return remoteProxy;
}

/**
 * @tc.name: RemoteProxy_Destroy_001
 * @tc.desc: Test destory the remote proxy.
 * @tc.type: FUNC
 */
HWTEST_F(IpcCApiRemoteObjectModuleTest, RemoteProxy_Destroy_001, TestSize.Level1)
{
    IPCTestHelper helper;
    OHIPCRemoteProxy *remoteProxy = IpcCreateIPCRemoteProxy(helper);
    ASSERT_NE(remoteProxy, nullptr);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

/**
 * @tc.name: SendRequestSync_001
 * @tc.desc: Test use proxy to send sync request message.
 * @tc.type: FUNC
 */
HWTEST_F(IpcCApiRemoteObjectModuleTest, SendRequestSync_001, TestSize.Level1)
{
    IPCTestHelper helper;
    auto *remoteProxy = IpcCreateIPCRemoteProxy(helper);
    ASSERT_NE(remoteProxy, nullptr);

    OHIPCParcel *dataParcel = OH_IPCParcel_Create();
    OHIPCParcel *replyParcel = OH_IPCParcel_Create();
    OH_IPC_MessageOption option = {OH_IPC_REQUEST_MODE_SYNC, 0};

    int ret = OH_IPCRemoteProxy_SendRequest(nullptr, TestCommand::TEST_CMD_GET_FOO_SERVICE,
        dataParcel, replyParcel, &option);
    EXPECT_EQ(ret, OH_IPC_CHECK_PARAM_ERROR);

    ret = OH_IPCRemoteProxy_SendRequest(remoteProxy, TestCommand::TEST_CMD_GET_FOO_SERVICE,
        nullptr, replyParcel, &option);
    EXPECT_EQ(ret, OH_IPC_CHECK_PARAM_ERROR);

    ret = OH_IPCRemoteProxy_SendRequest(remoteProxy, TestCommand::TEST_CMD_GET_FOO_SERVICE,
        dataParcel, nullptr, &option);
    EXPECT_EQ(ret, OH_IPC_CHECK_PARAM_ERROR);

    ret = OH_IPCRemoteProxy_SendRequest(remoteProxy, TestCommand::TEST_CMD_GET_FOO_SERVICE,
        dataParcel, replyParcel, &option);
    EXPECT_EQ(ret, OH_IPC_SUCCESS);
    auto *fooProxy = OH_IPCParcel_ReadRemoteProxy(replyParcel);
    EXPECT_NE(fooProxy, nullptr);
    OH_IPCParcel_Destroy(dataParcel);
    OH_IPCParcel_Destroy(replyParcel);
    OH_IPCRemoteProxy_Destroy(fooProxy);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

/**
 * @tc.name: SendRequestAsync_001
 * @tc.desc: Test use proxy to send async request message.
 * @tc.type: FUNC
 */
HWTEST_F(IpcCApiRemoteObjectModuleTest, SendRequestAsync_001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    std::unique_ptr<TestServiceClient> testClient = std::make_unique<TestServiceClient>();
    ASSERT_NE(testClient, nullptr);
    res = testClient->ConnectService();
    ASSERT_TRUE(res);

    res = testClient->TestRegisterRemoteStub();
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_NE(object, nullptr);
    auto testService = iface_cast<ITestService>(object);
    ASSERT_NE(testService, nullptr);
    auto remoteProxyTest = std::make_shared<NativeRemoteProxyTest>(testService);
    ASSERT_NE(remoteProxyTest, nullptr);
    EXPECT_EQ(remoteProxyTest->ASyncAdd(), 0);

    res = testClient->TestUnRegisterRemoteStub();
    ASSERT_TRUE(res);
}

/**
 * @tc.name: RemoteProxy_AddDeathRecipient_001
 * @tc.desc: Test add death recipient.
 * @tc.type: FUNC
 */
HWTEST_F(IpcCApiRemoteObjectModuleTest, RemoteProxy_AddDeathRecipient_001, TestSize.Level1)
{
    IPCTestHelper helper;
    auto *remoteProxy = IpcCreateIPCRemoteProxy(helper);
    ASSERT_NE(remoteProxy, nullptr);

    auto deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, OnDeathRecipientDestroyCallback, this);
    ASSERT_NE(deathRecipient, nullptr);
    int ret = OH_IPCRemoteProxy_AddDeathRecipient(remoteProxy, deathRecipient);
    EXPECT_EQ(ret, 0);

    ResetCallbackReply();
    bool res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    EXPECT_EQ(GetCallbackReply(), ON_CALLBACK_REPLIED_INT);
    OH_IPCDeathRecipient_Destroy(deathRecipient);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

/**
 * @tc.name: RemoteProxy_RemoveDeathRecipient_001
 * @tc.desc: Test add death recipient.
 * @tc.type: FUNC
 */
HWTEST_F(IpcCApiRemoteObjectModuleTest, RemoteProxy_RemoveDeathRecipient_001, TestSize.Level1)
{
    IPCTestHelper helper;
    auto *remoteProxy = IpcCreateIPCRemoteProxy(helper);
    ASSERT_NE(remoteProxy, nullptr);

    auto deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, OnDeathRecipientDestroyCallback,
                                                      this);
    ASSERT_NE(deathRecipient, nullptr);

    int ret = OH_IPCRemoteProxy_AddDeathRecipient(remoteProxy, deathRecipient);
    ASSERT_EQ(ret, 0);

    ret = OH_IPCRemoteProxy_RemoveDeathRecipient(remoteProxy, deathRecipient);
    EXPECT_EQ(ret, 0);

    ResetCallbackReply();
    bool res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    EXPECT_NE(GetCallbackReply(), ON_CALLBACK_REPLIED_INT);
    OH_IPCDeathRecipient_Destroy(deathRecipient);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

/**
 * @tc.name: IsRemoteDead_001
 * @tc.desc: Test the IsRemoteDead function.
 * @tc.type: FUNC
 */
HWTEST_F(IpcCApiRemoteObjectModuleTest, IsRemoteDead_001, TestSize.Level1)
{
    IPCTestHelper helper;
    auto *remoteProxy = IpcCreateIPCRemoteProxy(helper);
    ASSERT_NE(remoteProxy, nullptr);

    int ret = OH_IPCRemoteProxy_IsRemoteDead(remoteProxy);
    EXPECT_FALSE(ret);
    bool res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    ret = OH_IPCRemoteProxy_IsRemoteDead(remoteProxy);
    EXPECT_TRUE(ret);

    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

/**
 * @tc.name: GetInterfaceDescriptor_001
 * @tc.desc: Test the GetInterfaceDescriptor function.
 * @tc.type: FUNC
 */
HWTEST_F(IpcCApiRemoteObjectModuleTest, GetInterfaceDescriptor_001, TestSize.Level1)
{
    IPCTestHelper helper;
    auto *remoteProxy = IpcCreateIPCRemoteProxy(helper);
    ASSERT_NE(remoteProxy, nullptr);

    char *descriptor = nullptr;
    int32_t len = 0;

    int ret = OH_IPCRemoteProxy_GetInterfaceDescriptor(remoteProxy, &descriptor, &len, MemAllocator);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(strlen(descriptor) + 1, len);
    EXPECT_GE(len, 0);

    if (descriptor != nullptr) {
        free(descriptor);
    }
    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

/**
 * @tc.name: OH_IPCParcel_TestReadWriteRemoteProxy_001
 * @tc.desc: Test the Write and Read RemoteProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(IpcCApiRemoteObjectModuleTest, OH_IPCParcel_TestReadWriteRemoteProxy_001, TestSize.Level1)
{
    OHIPCParcel *parcel = OH_IPCParcel_Create();
    EXPECT_NE(parcel, nullptr);
    OHIPCRemoteProxy *remoteProxy = OH_IPCParcel_ReadRemoteProxy(nullptr);
    EXPECT_EQ(remoteProxy, nullptr);

    IPCTestHelper helper;
    auto *proxy = IpcCreateIPCRemoteProxy(helper);
    ASSERT_NE(proxy, nullptr);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteProxy(nullptr, proxy), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteProxy(parcel, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCParcel_WriteRemoteProxy(parcel, proxy), OH_IPC_SUCCESS);
    remoteProxy = OH_IPCParcel_ReadRemoteProxy(parcel);
    EXPECT_NE(remoteProxy, nullptr);
    // destroy the objects
    OH_IPCParcel_Destroy(parcel);
    OH_IPCRemoteProxy_Destroy(proxy);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
    bool res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
}
} // namespace OHOS
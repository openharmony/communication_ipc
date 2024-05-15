/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

static constexpr uint32_t ON_CALLBACK_REPLIED_INT = 1598311760;

class IpcCApiRemoteObjectUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IpcCApiUnitTest" };

    void ResetCallbackReply();
    [[nodiscard]] int GetCallbackReply() const;

public:
    static void OnRemoteObjectDestroy(void *userData);
    static void OnDeathRecipientCallback(void *userData);
    static void OnDeathRecipientDestroyCallback(void *userData);
    static int OnRemoteRequestStub(uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply, void *userData);

private:
    int callBackReply_{ 0 };
    static inline IPCTestHelper *globalHelper_ = { nullptr };
};

void IpcCApiRemoteObjectUnitTest::SetUpTestCase()
{
    if (globalHelper_ == nullptr) {
        globalHelper_ = new IPCTestHelper();
        bool res = globalHelper_->PrepareTestSuite();
        ASSERT_TRUE(res);
    }
}

void IpcCApiRemoteObjectUnitTest::TearDownTestCase()
{
    if (globalHelper_ != nullptr) {
        bool res = globalHelper_->TearDownTestSuite();
        ASSERT_TRUE(res);
        delete globalHelper_;
        globalHelper_ = nullptr;
    }
}

void IpcCApiRemoteObjectUnitTest::SetUp()
{
    callBackReply_ = 0;
}

void IpcCApiRemoteObjectUnitTest::TearDown()
{}

void IpcCApiRemoteObjectUnitTest::ResetCallbackReply()
{
    callBackReply_ = 0;
}

int IpcCApiRemoteObjectUnitTest::GetCallbackReply() const
{
    return callBackReply_;
}

void IpcCApiRemoteObjectUnitTest::OnRemoteObjectDestroy(void *userData)
{
    if (userData != nullptr) {
        auto *test = static_cast<IpcCApiRemoteObjectUnitTest *>(userData);
        test->callBackReply_ = ON_CALLBACK_REPLIED_INT;
    }
}

void IpcCApiRemoteObjectUnitTest::OnDeathRecipientCallback(void *userData)
{
    ZLOGD(LABEL, "OnDeathRecipientCallback modify callBackReply_");
    if (userData != nullptr) {
        auto *test = static_cast<IpcCApiRemoteObjectUnitTest *>(userData);
        test->callBackReply_ = ON_CALLBACK_REPLIED_INT;
    }
}

void IpcCApiRemoteObjectUnitTest::OnDeathRecipientDestroyCallback(void *userData)
{
    if (userData != nullptr) {
        auto *test = static_cast<IpcCApiRemoteObjectUnitTest *>(userData);
        test->callBackReply_ = ON_CALLBACK_REPLIED_INT;
    }
}

int IpcCApiRemoteObjectUnitTest::OnRemoteRequestStub(uint32_t code, const OHIPCParcel *data, OHIPCParcel *reply,
    void *userData)
{
    (void)userData;
    (void)code;
    (void)data;
    (void)reply;
    return 0;
}

static void* MemAllocator(int32_t len)
{
    if (len <= 0) {
        return nullptr;
    }
    void *buffer = malloc(len);
    if (buffer == nullptr) {
        return nullptr;
    }
    (void)memset_s(buffer, len, 0, len);
    return buffer;
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, RemoteStub_Create_001, TestSize.Level1)
{
    OHIPCRemoteStub *remote = OH_IPCRemoteStub_Create(nullptr, OnRemoteRequestStub, OnRemoteObjectDestroy, this);
    EXPECT_EQ(remote, nullptr);

    remote = OH_IPCRemoteStub_Create("RemoteStub_Create_001", nullptr, OnRemoteObjectDestroy, this);
    EXPECT_EQ(remote, nullptr);

    remote = OH_IPCRemoteStub_Create("RemoteStub_Create_001", OnRemoteRequestStub, nullptr, this);
    EXPECT_NE(remote, nullptr);
    OH_IPCRemoteStub_Destroy(remote);

    remote = OH_IPCRemoteStub_Create("RemoteStub_Create_001", OnRemoteRequestStub, OnRemoteObjectDestroy, nullptr);
    EXPECT_NE(remote, nullptr);
    OH_IPCRemoteStub_Destroy(remote);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, RemoteStub_Destroy_001, TestSize.Level1)
{
    OHIPCRemoteStub *remote = OH_IPCRemoteStub_Create("RemoteStub_Destroy_001", OnRemoteRequestStub,
                                                      OnRemoteObjectDestroy, this);
    EXPECT_NE(remote, nullptr);

    ResetCallbackReply();
    OH_IPCRemoteStub_Destroy(remote);
    EXPECT_EQ(GetCallbackReply(), ON_CALLBACK_REPLIED_INT);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, RemoteProxy_Destroy_001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_NE(object, nullptr);
    OHIPCRemoteProxy *remoteProxy = CreateIPCRemoteProxy(object);
    ASSERT_NE(remoteProxy, nullptr);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, SendRequestSync_001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);

    sptr<IRemoteObject> objectServer = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_NE(objectServer, nullptr);
    auto *remoteProxy = CreateIPCRemoteProxy(objectServer);
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

HWTEST_F(IpcCApiRemoteObjectUnitTest, SendRequestAsync_001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    int cmdId = TestCommand::TEST_CMD_NATIVE_IPC_REGISTER_REMOTE_STUB_OBJECT;
    res = helper.StartTestApp(IPCTestHelper::IPC_TEST_CLIENT, cmdId);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_NE(object, nullptr);
    auto testService = iface_cast<ITestService>(object);
    auto remoteProxyTest = std::make_shared<NativeRemoteProxyTest>(testService);
    EXPECT_EQ(remoteProxyTest->ASyncAdd(), 0);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, DeathRecipient_Create_001, TestSize.Level1)
{
    auto deathRecipient = OH_IPCDeathRecipient_Create(nullptr, OnDeathRecipientDestroyCallback, this);
    EXPECT_EQ(deathRecipient, nullptr);
    deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, nullptr, nullptr);
    EXPECT_NE(deathRecipient, nullptr);
    OH_IPCDeathRecipient_Destroy(deathRecipient);
    deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, OnDeathRecipientDestroyCallback, this);
    EXPECT_NE(deathRecipient, nullptr);
    OH_IPCDeathRecipient_Destroy(deathRecipient);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, DeathRecipient_Destroy_001, TestSize.Level1)
{
    auto deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, OnDeathRecipientDestroyCallback, this);
    ASSERT_NE(deathRecipient, nullptr);
    ResetCallbackReply();
    OH_IPCDeathRecipient_Destroy(deathRecipient);
    EXPECT_EQ(GetCallbackReply(), ON_CALLBACK_REPLIED_INT);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, RemoteProxy_AddDeathRecipient_001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);

    sptr<IRemoteObject> objectServer = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_NE(objectServer, nullptr);
    auto *remoteProxy = CreateIPCRemoteProxy(objectServer);
    ASSERT_NE(remoteProxy, nullptr);

    auto deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, OnDeathRecipientDestroyCallback,
                                                      this);
    ASSERT_NE(deathRecipient, nullptr);
    int ret = OH_IPCRemoteProxy_AddDeathRecipient(remoteProxy, deathRecipient);
    EXPECT_EQ(ret, 0);

    ResetCallbackReply();
    res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    EXPECT_EQ(GetCallbackReply(), ON_CALLBACK_REPLIED_INT);
    OH_IPCDeathRecipient_Destroy(deathRecipient);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, RemoteProxy_RemoveDeathRecipient_001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);

    sptr<IRemoteObject> objectServer = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_NE(objectServer, nullptr);
    auto *remoteProxy = CreateIPCRemoteProxy(objectServer);
    ASSERT_NE(remoteProxy, nullptr);

    auto deathRecipient = OH_IPCDeathRecipient_Create(OnDeathRecipientCallback, OnDeathRecipientDestroyCallback,
                                                      this);
    ASSERT_NE(deathRecipient, nullptr);

    int ret = OH_IPCRemoteProxy_AddDeathRecipient(remoteProxy, deathRecipient);
    ASSERT_EQ(ret, 0);

    ret = OH_IPCRemoteProxy_RemoveDeathRecipient(remoteProxy, deathRecipient);
    EXPECT_EQ(ret, 0);

    ResetCallbackReply();
    res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    EXPECT_NE(GetCallbackReply(), ON_CALLBACK_REPLIED_INT);
    OH_IPCDeathRecipient_Destroy(deathRecipient);
    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, IsRemoteDead_001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);

    sptr<IRemoteObject> objectServer = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_NE(objectServer, nullptr);
    auto *remoteProxy = CreateIPCRemoteProxy(objectServer);
    ASSERT_NE(remoteProxy, nullptr);

    int ret = OH_IPCRemoteProxy_IsRemoteDead(remoteProxy);
    EXPECT_FALSE(ret);
    res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    ret = OH_IPCRemoteProxy_IsRemoteDead(remoteProxy);
    EXPECT_TRUE(ret);

    OH_IPCRemoteProxy_Destroy(remoteProxy);
}

HWTEST_F(IpcCApiRemoteObjectUnitTest, GetInterfaceDescriptor_001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saMgr, nullptr);

    sptr<IRemoteObject> objectServer = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_NE(objectServer, nullptr);
    auto *remoteProxy = CreateIPCRemoteProxy(objectServer);
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
/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"
#include "test_service_skeleton.h"
#include "test_service.h"
#include "test_service_command.h"
#include "test_service_client.h"
#include "ipc_test_helper.h"
#include "iservice_registry.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "log_tags.h"
#ifndef CONFIG_STANDARD_SYSTEM
#include "jni_help.h"
#endif

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

static constexpr int MAX_TEST_COUNT = 1000;
static constexpr bool SUPPORT_ZBINDER = false;

class IPCNativeUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCUnitTest" };

private:
    static inline IPCTestHelper *g_globalHelper = { nullptr };
};

void IPCNativeUnitTest::SetUpTestCase()
{
    if (g_globalHelper == nullptr) {
        g_globalHelper = new IPCTestHelper();
        bool res = g_globalHelper->PrepareTestSuite();
        ASSERT_TRUE(res);
    }
}

void IPCNativeUnitTest::TearDownTestCase()
{
    if (g_globalHelper != nullptr) {
        bool res = g_globalHelper->TearDownTestSuite();
        ASSERT_TRUE(res);
        delete g_globalHelper;
        g_globalHelper = nullptr;
    }
}

/**
 * @tc.name: DeathRecipient001
 * @tc.desc: The Stub should not support AddDeathRecipient
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, DeathRecipient001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    bool res = testStub->AddDeathRecipient(nullptr);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: DeathRecipient002
 * @tc.desc: The Stub should not support RemoveDeathRecipient
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, DeathRecipient002, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    bool res = testStub->RemoveDeathRecipient(nullptr);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: DumpTest001
 * @tc.desc: The Stub should not support Dump
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, DumpTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    std::vector<std::u16string> args;
    args.push_back(u"test");
    int res = testStub->Dump(0, args);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: ProxyJudgment001
 * @tc.desc: act as stub role, should return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, ProxyJudgment001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    bool res = testStub->IsProxyObject();
    EXPECT_FALSE(res);
}

#ifndef CONFIG_STANDARD_SYSTEM
/**
 * @tc.name: ProxyJudgment002
 * @tc.desc: act as proxy role, should return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, ProxyJudgment002, TestSize.Level1)
{
    sptr<IRemoteObject> remote = SystemAbilityManagerClient::GetInstance().GetRegistryRemoteObject();
    ASSERT_TRUE(remote != nullptr);
    EXPECT_TRUE(remote->IsProxyObject());
}

/**
 * @tc.name: RemoteId001.
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, RemoteId001, TestSize.Level1)
{
    sptr<IRemoteObject> remote = SystemAbilityManagerClient::GetInstance().GetRegistryRemoteObject();
    ASSERT_TRUE(remote != nullptr);

    IPCObjectProxy *proxy = reinterpret_cast<IPCObjectProxy *>(remote.GetRefPtr());
    ASSERT_TRUE(proxy != nullptr);

    int remoteId = proxy->GetHandle();
    EXPECT_GE(remoteId, 0);
}
#endif

/**
 * @tc.name: ProxyJudgment003
 * @tc.desc: transform interface instance to object.
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, ProxyJudgment003, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> asObject = saMgr->AsObject();
    ASSERT_TRUE(asObject != nullptr);
}

/**
 * @tc.name: ProxyJudgment004
 * @tc.desc: Press test to validate Get Register instance..
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, ProxyJudgment004, TestSize.Level1)
{
    std::vector<sptr<ISystemAbilityManager>> registryObjs;
    registryObjs.resize(100);

    for (int i = 0; i < 100; i++) {
        registryObjs[i] = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        ASSERT_TRUE(registryObjs[i] != nullptr);
    }
}

/**
 * @tc.name: MaxWorkThread001
 * @tc.desc: when multi-transaction called,
 * the driver will spawn new thread.but it should not exceed the max num.
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, MaxWorkThread001, TestSize.Level1)
{
    IPCTestHelper helper;
    IPCSkeleton::SetMaxWorkThreadNum(8);
    std::vector<pid_t> childPids;
    helper.GetChildPids(childPids);
    ASSERT_GE(childPids.size(), (const unsigned long)1);
}

/**
 * @tc.name: SyncTransaction001
 * @tc.desc: Test IPC data transaction.
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);
    ASSERT_TRUE(testService != nullptr);

    if (service->IsProxyObject()) {
        int reply = 0;
        ZLOGI(LABEL, "Got Proxy node");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int ret = proxy->TestSyncTransaction(2019, reply);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(reply, 9102);
    } else {
        ZLOGI(LABEL, "Got Stub node");
    }
}

/**
 * @tc.name: AsyncTransaction001
 * @tc.desc: Test IPC data transaction.
 * @tc.type: FUNC
 * @tc.require: AR000DPV5F
 */
HWTEST_F(IPCNativeUnitTest, AsyncTransaction001, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);
    ASSERT_TRUE(testService != nullptr);

    ZLOGI(LABEL, "Get test.service OK\n");
    if (service->IsProxyObject()) {
        ZLOGI(LABEL,  "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int reply = 0;
        int ret = proxy->TestAsyncTransaction(2019, reply);
        EXPECT_EQ(ret, ERR_NONE);
    } else {
        ZLOGI(LABEL, "Got Stub node\n");
    }
}

/**
 * @tc.name: SyncTransaction002
 * @tc.desc: Test IPC data transaction.
 * @tc.type: FUNC
 * @tc.require: AR000DPV5E
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction002, TestSize.Level1)
{
    int refCount = 0;
    IPCTestHelper helper;
    sptr<TestService> stub = new TestService();
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    refCount = stub->GetObjectRefCount();
    EXPECT_EQ(refCount, 1);

    int result = saMgr->AddSystemAbility(IPC_TEST_SERVICE, new TestService());
    EXPECT_EQ(result, ERR_NONE);

    refCount = stub->GetObjectRefCount();

    if (SUPPORT_ZBINDER) {
        EXPECT_GE(refCount, 2);
    } else {
        EXPECT_GE(refCount, 1);
    }

    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_CLIENT);
    ASSERT_TRUE(res);

    refCount = stub->GetObjectRefCount();
    if (SUPPORT_ZBINDER) {
        EXPECT_GE(refCount, 3);
    } else {
        EXPECT_GE(refCount, 1);
    }

    helper.StopTestApp(IPCTestHelper::IPC_TEST_CLIENT);
    refCount = stub->GetObjectRefCount();
    if (SUPPORT_ZBINDER) {
        EXPECT_GE(refCount, 2);
    } else {
        EXPECT_GE(refCount, 1);
    }
}

/**
 * @tc.name: SyncTransaction003
 * @tc.desc: Test IPC data transaction.
 * @tc.type: FUNC
 * @tc.require: AR000DPV5F
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction003, TestSize.Level1)
{
    int refCount = 0;
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> proxy = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(proxy != nullptr);

    refCount = proxy->GetObjectRefCount();
    if (SUPPORT_ZBINDER) {
        EXPECT_GE(refCount, 2);
    } else {
        EXPECT_GE(refCount, 1);
    }

    res = helper.StartTestApp(IPCTestHelper::IPC_TEST_CLIENT);
    ASSERT_TRUE(res);

    refCount = proxy->GetObjectRefCount();
    if (SUPPORT_ZBINDER) {
        EXPECT_GE(refCount, 3);
    } else {
        EXPECT_GE(refCount, 1);
    }

    helper.StopTestApp(IPCTestHelper::IPC_TEST_CLIENT);
    refCount = proxy->GetObjectRefCount();

    if (SUPPORT_ZBINDER) {
        EXPECT_GE(refCount, 2);
    } else {
        EXPECT_GE(refCount, 1);
    }
}

/**
 * @tc.name: SyncTransaction004
 * @tc.desc: Test IPC data transaction.
 * @tc.type: FUNC
 * @tc.require: AR000DPV5E
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction004, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    res = helper.StartTestApp(IPCTestHelper::IPC_TEST_CLIENT, static_cast<int>(TestCommand::TEST_CMD_LOOP_TRANSACTION));
    ASSERT_TRUE(res);

    std::unique_ptr<TestServiceClient> testClient = std::make_unique<TestServiceClient>();
    int result = testClient->ConnectService();
    ASSERT_EQ(result, 0);

    int count = testClient->StartLoopTest(MAX_TEST_COUNT);
    EXPECT_EQ(count, MAX_TEST_COUNT);
}

/**
 * @tc.name: SyncTransaction005
 * @tc.desc: Test get context object.
 * @tc.type: FUNC
 * @tc.require: SR000DFJQF AR000DFJQG
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction005, TestSize.Level1)
{
    sptr<IRemoteObject> remote = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remote != nullptr);
}

/**
 * @tc.name: SyncTransaction006
 * @tc.desc: Test set context object.
 * @tc.type: FUNC
 * @tc.require: SR000DFJQF AR000DFJQG

 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction006, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObj = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remoteObj != nullptr);
    bool ret = IPCSkeleton::SetContextObject(remoteObj);
    ASSERT_FALSE(ret);
}

#ifndef CONFIG_STANDARD_SYSTEM
/**
 * @tc.name: SyncTransaction007
 * @tc.desc: Test get context object through jni.
 * @tc.type: FUNC
 * @tc.require: SR000DFJQF AR000DFJQG
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction007, TestSize.Level1)
{
    JNIEnv *env = nullptr;
    sptr<IRemoteObject> remoteObj = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remoteObj != nullptr);
    jobject testObj = JNIHelperGetJavaRemoteObject(env, remoteObj);
    ASSERT_TRUE(testObj == nullptr);
}
#endif

/**
 * @tc.name: SyncTransaction008
 * @tc.desc: Test write and read interface token in MessageParcel.
 * @tc.type: FUNC
 * @tc.require: SR000DFJQF AR000DFJQG
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction008, TestSize.Level1)
{
    MessageParcel parcel;
    std::u16string descriptor = u"TokenDescriptor";
    parcel.WriteInterfaceToken(descriptor);
    std::u16string readDescriptor = parcel.ReadInterfaceToken();
    ASSERT_EQ(readDescriptor, descriptor);
}


/**
 * @tc.name: SyncTransaction009
 * @tc.desc: Test IPC stub data Normal release.
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction009, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> service = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    sptr<ITestService> testService = iface_cast<ITestService>(service);
    ASSERT_TRUE(testService != nullptr);

    ZLOGI(LABEL, "Get test.service OK\n");
    if (service->IsProxyObject()) {
        ZLOGI(LABEL,  "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int reply = 0;
        int ret = proxy->TestAsyncTransaction(2019, reply);
        EXPECT_EQ(ret, ERR_NONE);
    } else {
        ZLOGI(LABEL, "Got Stub node\n");
    }
}

/**
 * @tc.name: SyncTransaction010
 * @tc.desc: Test write and read exception.
 * @tc.type: FUNC
 * @tc.require: AR000E1QEG
 */
HWTEST_F(IPCNativeUnitTest, SyncTransaction010, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteNoException();
    ASSERT_EQ(parcel.ReadException(), 0);
}

/**
 * @tc.name: MessageOptionTest001
 * @tc.desc: Test set waiting time.
 * @tc.type: FUNC
 * @tc.require: AR000ER7PF
 */
HWTEST_F(IPCNativeUnitTest, MessageOptionTest001, TestSize.Level1)
{
    MessageOption messageOption;
    ASSERT_EQ(messageOption.GetWaitTime(), MessageOption::TF_WAIT_TIME);
    messageOption.SetWaitTime(-1);
    ASSERT_EQ(messageOption.GetWaitTime(), MessageOption::TF_WAIT_TIME);
}

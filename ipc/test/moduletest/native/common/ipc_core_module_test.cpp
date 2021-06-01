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

#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <gtest/gtest.h>
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "ipc_test_helper.h"
#include "test_service.h"
#include "test_service_skeleton.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ipc_object_proxy.h"

#include "log_tags.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

class IPCNativeFrameworkTest : public testing::Test {
public:
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCModuleTest" };
    static constexpr int saId = 3202;
    static constexpr int checkTimes = 1000;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static void RegisterThread();
    const int threadNums = 10;
    const int flushTimes = 10;
    const int repeatTimes = 30000;
    // Test transferring big data with different sizes
    const int rawData10K = 10 * 1024;
    const int rawData10M = 10 * 1024 * 1024;
    const int rawData100M = 100 * 1024 * 1024;
    const int rawData33K = 33 * 1024;
    const int errorCode = 2020;
    std::string ashmemName = "AshmemIpc";
    std::string ashmemString = "HelloWorld2020";
private:
    static inline IPCTestHelper *g_globalHelper = { nullptr };
};

void IPCNativeFrameworkTest::SetUpTestCase()
{
    if (g_globalHelper == nullptr) {
        g_globalHelper = new IPCTestHelper();
        bool res = g_globalHelper->PrepareTestSuite();
        ASSERT_TRUE(res);
    }
}

void IPCNativeFrameworkTest::TearDownTestCase()
{
    if (g_globalHelper != nullptr) {
        bool res = g_globalHelper->TearDownTestSuite();
        ASSERT_TRUE(res);
        delete g_globalHelper;
        g_globalHelper = nullptr;
    }
}

void IPCNativeFrameworkTest::RegisterThread()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgr != nullptr);
    for (int i = 0; i < checkTimes; i++) {
        auto remoteObject = samgr->CheckSystemAbility(saId);
        if (remoteObject != nullptr) {
            ASSERT_TRUE(remoteObject->IsProxyObject());
        } else {
            ZLOGI(LABEL, "proxy is null");
        }
    }
}

/**
 * @tc.name: function_test_001
 * @tc.desc: Test get system ability.
 * @tc.type: FUNC
 * @tc.require: SR000CQDI2 SR000CQDI7 AR000CQDI8
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_001, TestSize.Level1)
{
    ZLOGI(LABEL, "Start IPC Testcase001");
    // service instance
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(saMgr != NULL);
}

/**
 * @tc.name: function_test_002
 * @tc.desc: Test basic ipc communication.
 * @tc.type: FUNC
 * @tc.require: SR000CQDI2 SR000CQDI7 AR000CQDI8
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_002, TestSize.Level1)
{
    ZLOGI(LABEL, "Start IPC Testcase002");
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != NULL);
    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);

    sptr<IRemoteObject::DeathRecipient> death(new TestDeathRecipient());
    int result = object->AddDeathRecipient(death.GetRefPtr());

    ZLOGI(LABEL, "AddDeathRecipient result = %d", result);
    EXPECT_TRUE(result != ERR_INVALID_OPERATION);

    sptr<ITestService> testService = iface_cast<ITestService>(object);

    int reply = 0;
    result = testService->TestSyncTransaction(2019, reply);
    ZLOGI(LABEL, "testService ReverseInt result = %d, get reply = %d", result, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    res = helper.StopTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    EXPECT_EQ(TestDeathRecipient::GotDeathRecipient(), true);

    bool returnResult = object->RemoveDeathRecipient(death.GetRefPtr());
    EXPECT_EQ(returnResult, false);
}

/**
 * @tc.name: function_test_003
 * @tc.desc: Test basic ipc communication in one process and Link Death.
 * @tc.type: FUNC
 * @tc.require: AR000CT7RU AR000CQDI9
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_003, TestSize.Level1)
{
    ZLOGI(LABEL, "Start IPC Testcase003");

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);
    ISystemAbilityManager *smp = saMgr.GetRefPtr();
    ASSERT_TRUE(smp != nullptr);

    sptr<IRemoteObject> service = new TestService();
    int result = smp->AddSystemAbility(IPC_EXTRA_TEST_SERVICE, service);

    ZLOGI(LABEL, "Testcase003: Add TestService result=%d", result);
    EXPECT_EQ(result, 0);

    // test get service and call it
    ASSERT_TRUE(smp != nullptr);

    sptr<IRemoteObject> object = smp->GetSystemAbility(IPC_EXTRA_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGI(LABEL, "Testcase003: Get test.service OK");

    sptr<IRemoteObject::DeathRecipient> death(new TestDeathRecipient());
    bool ret = object->AddDeathRecipient(death.GetRefPtr());

    ZLOGI(LABEL, "Testcase003: AddDeathRecipient result = %d", result);
    EXPECT_TRUE(ret == false);

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    int reply = 0;
    result = testService->TestSyncTransaction(0, reply);
    ZLOGI(LABEL, "Testcase003: ReverseInt result = %d, get reply = %d", result, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 0);
}

/**
 * @tc.name: function_test_004
 * @tc.desc: Test sync ipc communication call and ipc thread poll.
 * @tc.type: FUNC
 * @tc.require: SR000CT84J AR000CQDI3 AR000CQDI6
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_004, TestSize.Level1)
{
    ZLOGI(LABEL, "Start IPC Testcase004");
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGI(LABEL, "get test.service OK");

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    long startTime = helper.GetCurrentTimeMs();
    int reply = 0;
    int result = 0;
    result = testService->TestSyncTransaction(2019, reply, 2);
    ZLOGI(LABEL, "testService ReverseInt result = %d, get reply = %d", result, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    long finishTime = helper.GetCurrentTimeMs();
    ZLOGI(LABEL, "startTime = %ld, finishTime = %ld", startTime, finishTime);
    EXPECT_GE(finishTime - startTime, 2000);
}

/**
 * @tc.name: function_test_005
 * @tc.desc: Test async ipc communication call.
 * @tc.type: FUNC
 * @tc.require: SR000CT84J AR000CQDI4 AR000CT84K
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_005, TestSize.Level1)
{
    ZLOGI(LABEL, "Start IPC Testcase005");
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGI(LABEL, "get test.service OK");

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    long startTime = helper.GetCurrentTimeMs();
    int result = 0;
    result = testService->TestAsyncTransaction(2019, 0);
    ZLOGI(LABEL, "testService ReverseInt result = %d, get reply = %d", result, reply);
    EXPECT_EQ(result, 0);
    long finishTime = helper.GetCurrentTimeMs();
    ZLOGI(LABEL, "startTime = %ld, finishTime = %ld", startTime, finishTime);
    EXPECT_LT(finishTime - startTime, 100);
}

/**
 * @tc.name: function_test_006
 * @tc.desc: Test for GetFileDescriptor.
 * @tc.type: FUNC
 * @tc.require: AR000CQDI5
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_006, TestSize.Level1)
{
    ZLOGI(LABEL, "Start IPC Testcase006");
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGI(LABEL, "get test.service OK");

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    for (int i = 0; i < repeatTimes; i++) {
        int fd = testService->TestGetFileDescriptor();
        ZLOGW(LABEL, "Got fd:%{public}d!\n", fd);
        ASSERT_TRUE(fd > 0);

        ssize_t len = write(fd, "client write!\n", strlen("client write!\n"));
        EXPECT_GT(len, 0);

        close(fd);
    }
}

/**
 * @tc.name: function_test_007
 * @tc.desc: Get the Strong reference of Service.
 * @tc.type: FUNC
 * @tc.require: SR000CRQIJ AR000CT7RS AR000CT7RT
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_007, TestSize.Level1)
{
    ZLOGI(LABEL, "Start IPC Testcase007");
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGI(LABEL, "get test.service OK");

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    sptr<IFoo> fooService = testService->TestGetFooService();
    EXPECT_TRUE(fooService != nullptr);

    std::string fooName = fooService->GetFooName();
    EXPECT_EQ(fooName, "ReallFoo");
}

/**
 * @tc.name: function_test_008
 * @tc.desc: Test Dump Interface.
 * @tc.type: FUNC
 * @tc.require: AR000CRQIK AR000CPNKQ
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_008, TestSize.Level1)
{
    ZLOGI(LABEL, "Start IPC Testcase008");
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();

    ASSERT_TRUE(saMgr != nullptr);
    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGI(LABEL, "get test.service OK");

    int fd = open("/data/test/dump.txt",
        O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

    ASSERT_TRUE(fd > 0);

    std::vector<std::u16string> args;
    args.push_back(u"test");

    int result = object->Dump(fd, args);
    close(fd);
    EXPECT_TRUE(result == ERR_NONE);
}

/**
 * @tc.name: function_test_009
 * @tc.desc: Test ipc communication big raw data call.
 * @tc.type: FUNC
 * @tc.require: SR000D48A6 AR000D4CFM
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_009, TestSize.Level1)
{
    ZLOGE(LABEL, "Start IPC Testcase009");
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGE(LABEL, "get test.service OK");

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    long startTime = helper.GetCurrentTimeMs();
    int reply = 0;
    // TestRawDataTransaction cannot transfer data less than 2.
    int result = testService->TestRawDataTransaction(rawData10M, reply);
    ZLOGE(LABEL, "testService ReverseInt result = %{public}d, get reply = %{public}d", result, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, rawData10M);

    result = testService->TestRawDataTransaction(rawData100M, reply);
    ZLOGE(LABEL, "testService ReverseInt result = %{public}d, get reply = %{public}d", result, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, rawData100M);

    long finishTime = helper.GetCurrentTimeMs();
    ZLOGE(LABEL, "startTime = %{public}ld, finishTime = %{public}ld", startTime, finishTime);
    EXPECT_LT(finishTime - startTime, 2000);
}

/**
 * @tc.name: function_test_010
 * @tc.desc: Test ipc reply big raw data.
 * @tc.type: FUNC
 * @tc.require: SR000CQSAB AR000DAPPO
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_010, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    long startTime = helper.GetCurrentTimeMs();
    // TestRawDataTransaction cannot transfer data less than 2.
    int result = testService->TestRawDataReply(rawData10M);
    ZLOGE(LABEL, "testService ReverseInt result = %{public}d", result);
    EXPECT_EQ(result, 0);

    result = testService->TestRawDataReply(rawData100M);
    ZLOGE(LABEL, "testService ReverseInt result = %{public}d", result);
    EXPECT_EQ(result, 0);

    long finishTime = helper.GetCurrentTimeMs();
    ZLOGE(LABEL, "startTime = %{public}ld, finishTime = %{public}ld", startTime, finishTime);
    EXPECT_LT(finishTime - startTime, 2000);
}

/**
 * @tc.name: function_test_011
 * @tc.desc: Test ipc get calling uid and pid.
 * @tc.type: FUNC
 * @tc.require: SR000CQSAB AR000DAPPO
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_011, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    long startTime = helper.GetCurrentTimeMs();
    int result = testService->TestCallingUidPid();
    EXPECT_EQ(result, 0);

    long finishTime = helper.GetCurrentTimeMs();
    EXPECT_LT(finishTime - startTime, 2000);
}

/**
 * @tc.name: function_test_016
 * @tc.desc: Test ipc flush asynchronous calls.
 * @tc.type: FUNC
 * @tc.require: AR000DPV5I
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_016, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    long startTime = helper.GetCurrentTimeMs();
    int result = testService->TestFlushAsyncCalls(flushTimes, rawData10K);
    EXPECT_EQ(result, 0);

    long finishTime = helper.GetCurrentTimeMs();
    EXPECT_LT(finishTime - startTime, 2000);
}

/**
 * @tc.name: function_test_017
 * @tc.desc: Test ipc proxy gets descriptor.
 * @tc.type: FUNC
 * @tc.require: AR000DPV5I
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_017, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);

    auto proxy = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    std::u16string descriptor = proxy->GetInterfaceDescriptor();
    ASSERT_TRUE(IsSameTextStr(Str16ToStr8(descriptor), "test.ipc.ITestService"));
}

/**
 * @tc.name: function_test_018
 * @tc.desc: Test ashmem reads and writes.
 * @tc.type: FUNC
 * @tc.require: SR000ER7PG
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_018, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);
    for (int i = 0; i < repeatTimes; i++) {
        sptr<Ashmem> ashmem = Ashmem::CreateAshmem(ashmemName.c_str(), rawData10K);
        ASSERT_TRUE(ashmem != nullptr);
        bool ret = ashmem->MapReadAndWriteAshmem();
        ASSERT_TRUE(ret);
        ret = ashmem->WriteToAshmem(ashmemString.c_str(), strlen(ashmemString.c_str()), 0);
        ASSERT_TRUE(ret);

        long startTime = helper.GetCurrentTimeMs();
        std::u16string readStr = testService->TestAshmem(ashmem, strlen(ashmemString.c_str()));

        long finishTime = helper.GetCurrentTimeMs();
        EXPECT_EQ(readStr, Str8ToStr16(ashmemString));
        EXPECT_LT(finishTime - startTime, 2000);
        ashmem->UnmapAshmem();
        ashmem->CloseAshmem();
    }
}

#ifndef CONFIG_STANDARD_SYSTEM
/**
 * @tc.name: function_test_019
 * @tc.desc: Test raw data reads and writes.
 * @tc.type: FUNC
 * @tc.require: SR000ER7PG
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_019, TestSize.Level1)
{
    for (int i = 0; i < repeatTimes; i++) {
        unsigned char *buffer = new (std::nothrow) unsigned char[rawData10M];
        if (buffer == nullptr) {
            ZLOGE(LABEL, "new buffer failed of length = %{public}d", rawData10M);
            return;
        }
        buffer[0] = 'a';
        buffer[rawData10M - 1] = 'z';

        MessageParcel dataParcel;
        dataParcel.WriteRawData(buffer, rawData10M);
        dataParcel.RewindRead(0);
        const char *buffer2 = nullptr;
        buffer2 = reinterpret_cast<const char *>(dataParcel.ReadRawData(rawData10M));
        ASSERT_TRUE(buffer2 != nullptr);
        EXPECT_EQ(buffer2[0], 'a');
        EXPECT_EQ(buffer2[rawData10M - 1], 'z');
        delete[] buffer;
    }
}
#endif

/**
 * @tc.name: function_test_020
 * @tc.desc: Test ipc communication big raw data call.
 * @tc.type: FUNC
 * @tc.require: SR000ER7PG
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_020, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGE(LABEL, "get test.service OK");

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    int reply = 0;
    for (int i = 0; i < repeatTimes; i++) {
        int result = testService->TestRawDataTransaction(rawData33K, reply);
        ZLOGE(LABEL, "testService ReverseInt result = %{public}d, get reply = %{public}d", result, reply);
        EXPECT_EQ(result, 0);
        EXPECT_EQ(reply, rawData33K);
    }
}

/**
 * @tc.name: function_test_021
 * @tc.desc: Test ipc communication big raw data call.
 * @tc.type: FUNC
 * @tc.require: SR000ER7PG
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_021, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    // test get service and call it
    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    ZLOGE(LABEL, "get test.service OK");

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    for (int i = 0; i < repeatTimes; i++) {
        int result = testService->TestRawDataReply(rawData33K);
        ZLOGE(LABEL, "testService ReverseInt result = %{public}d", result);
        EXPECT_EQ(result, 0);
    }
}

/**
 * @tc.name: function_test_022
 * @tc.desc: Test marshalling and unmarshalling Ashmem.
 * @tc.type: FUNC
 * @tc.require: SR000ER7PG
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_022, TestSize.Level1)
{
    for (int i = 0; i < repeatTimes; i++) {
        sptr<Ashmem> ashmem = Ashmem::CreateAshmem(ashmemName.c_str(), 1024);
        ASSERT_TRUE(ashmem != nullptr);
        bool ret = ashmem->MapReadAndWriteAshmem();
        ASSERT_TRUE(ret);
        ret = ashmem->WriteToAshmem(ashmemString.c_str(), strlen(ashmemString.c_str()), 0);
        ASSERT_TRUE(ret);

        MessageParcel parcel;
        parcel.WriteAshmem(ashmem);
        parcel.RewindRead(0);

        sptr<Ashmem> ashmem2 = parcel.ReadAshmem();
        ASSERT_TRUE(ashmem2 != nullptr);
        ASSERT_TRUE(ashmem2->MapReadOnlyAshmem());
        const void *content = ashmem2->ReadFromAshmem(strlen(ashmemString.c_str()), 0);
        ASSERT_TRUE(content != nullptr);

        auto readContent = static_cast<const char *>(content);
        std::string str(readContent, strlen(ashmemString.c_str()));
        EXPECT_EQ(str, ashmemString);

        ashmem->UnmapAshmem();
        ashmem->CloseAshmem();
        ashmem2->UnmapAshmem();
        ashmem2->CloseAshmem();
    }
}

/**
 * @tc.name: function_test_023
 * @tc.desc: Test sending again after error.
 * @tc.type: FUNC
 * @tc.require: AR000CQDI5
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_023, TestSize.Level1)
{
    IPCTestHelper helper;
    bool res = helper.StartTestApp(IPCTestHelper::IPC_TEST_SERVER);
    ASSERT_TRUE(res);

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);

    sptr<ITestService> testService = iface_cast<ITestService>(object);
    ASSERT_TRUE(testService != nullptr);

    int reply = 0;
    int ret = testService->TestNestingSend(errorCode, reply);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(reply, errorCode);
}

/**
 * @tc.name: function_test_024
 * @tc.desc: Test obtaining the same proxy by multiple threads concurrently.
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeFrameworkTest, function_test_024, TestSize.Level1)
{
    std::vector<std::unique_ptr<std::thread>> threads;
    for (int i = 0; i < threadNums; i++) {
        threads.emplace_back(std::make_unique<std::thread>(&IPCNativeFrameworkTest::RegisterThread));
    }

    ZLOGI(LABEL, "Sleep IPC Testcase024");
    sleep(10);
    std::cout << "ok\n" << std::endl;
    for (auto &thread : threads) {
        thread->join();
    }
}

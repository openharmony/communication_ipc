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

#include <iostream>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <chrono>
#include <cinttypes>
#include <string>
#include <unistd.h>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <securec.h>

#include "dbinder_service.h"
#include "dbinder_service_test_helper.h"
#include "dbinder_test_service_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"
#include "ipc_types.h"
#include "if_system_ability_manager.h"
#include "string_ex.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "distributed_major.h"
#include "log_tags.h"
#include "dbinder_test_service.h"

using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::DistributeSystemTest;
using namespace OHOS::HiviewDFX;

#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DbinderTest" };
#define DBINDER_LOGF(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Fatal(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGW(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Warn(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGD(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Debug(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

class DbinderTest : public DistributeTest {
public:
    static const int UNIT = 1024;
    /* The threshold of packet size is 64 * 1024, including header.
     * The following definitions are used to test legal and illegal packets.
     */
    static const int LEGAL_SIZE_S = 3 * 1024;
    static const int LEGAL_SIZE_M = 16 * 1024;
    static const int LEGAL_SIZE_L = 63 * 1024;
    static const int ILLEGAL_SIZE = 2 * 1024 * 1024;
    static const int REPEAT_TIMES = 1000;
    static const int REPEAT_RAW_DATA_TIMES = 100;
    static const int MULTIPLEX_TIMES = 10;
    static sptr<ISystemAbilityManager> manager_;
    static char serverId_[DEVICEID_LENGTH + 1];
    // Test transferring big data with different sizes
    const int rawData10K = 10 * 1024;
    const int rawData100K = 100 * 1024;
    const int rawData1M = 1024 * 1024;
    const int rawData10M = 10 * 1024 * 1024;
    const int rawData100M = 100 * 1024 * 1024;

    DbinderTest() = default;
    ~DbinderTest() = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    virtual void SetUp();
    virtual void TearDown() {};
    std::string IpToDeviceId(const std::string &localIp);
    bool GetRemoteDeviceId();
};

sptr<ISystemAbilityManager> DbinderTest::manager_ = nullptr;
char DbinderTest::serverId_[DEVICEID_LENGTH + 1];

void DbinderTest::SetUpTestCase()
{
    DBINDER_LOGI("enter SetUpTestCase");
    StartDBinderServiceTestService();
}

void DbinderTest::TearDownTestCase()
{
    DBINDER_LOGI("enter TearDownTestCase");
    StopDBinderServiceTestService();
}

void DbinderTest::SetUp()
{
    bool ret = GetRemoteDeviceId();
    ASSERT_TRUE(ret);

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    manager_ = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(manager_ != nullptr);
}

bool DbinderTest::GetRemoteDeviceId()
{
    std::string msg = "Ask Device ID";
    int ret = SendMessage(AGENT_NO::ONE, msg, strlen(msg.c_str()), [&](const std::string &retId, int retLen) -> bool {
        if (memcpy_s(serverId_, DEVICEID_LENGTH, retId.c_str(), DEVICEID_LENGTH) != 0 || retLen != DEVICEID_LENGTH) {
            DBINDER_LOGE("fail to copy string");
            return false;
        }
        serverId_[DEVICEID_LENGTH] = '\0';
        return true;
    });

    return ret > 0;
}

/*
 * @tc.name: DbinderRemoteCall001
 * @tc.desc: Verify local client can acquire registered system ability
 * and invoke remote function on remote server.
 * @tc.type: FUNC
 * @tc.require: SR000CS1C1/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall001, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_001);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to invoke remote function.
     * @tc.expected: step2.Remote call succeeds and returns 0.
     */
    int reply = 0;
    int result = testService->ReverseInt(2019, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}
/*
 * @tc.name: DbinderRemoteCall002
 * @tc.desc: Verify local client cannot acquire unregistered system ability
 * @tc.type: FUNC
 * @tc.require: SR000CS1C1/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall002, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_002);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get an unregistered System Ability from remote server.
     * @tc.expected: step1.Failed to get the SA and return nullptr.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_UNREGISTERED_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object == nullptr);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall003
 * @tc.desc: Verify the limit to the size of data sent to remote server
 * @tc.type: FUNC
 * @tc.require: SR000CS1C1/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall003, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_003);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to invoke remote function with legal and illegal data respectively.
     * @tc.expected: step2.Succeed in transferring legal data but fail to transfer illegal data.
     */
    std::string reply;
    std::string emptyData;
    testService->TransOversizedPkt(emptyData, reply);
    ASSERT_TRUE(emptyData == reply);

    std::string legalDataS(LEGAL_SIZE_S, 'a');
    int64_t startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        testService->TransOversizedPkt(legalDataS, reply);
        ASSERT_TRUE(legalDataS == reply);
    }
    int64_t finishTime = GetCurrentTime();
    float speed = GetSpeed(finishTime - startTime, LEGAL_SIZE_S, MULTIPLEX_TIMES);
    printf("Transfer 3k data with speed of %.2fk/s.\n", speed);

    std::string legalDataM(LEGAL_SIZE_M, 'a');
    startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        testService->TransOversizedPkt(legalDataM, reply);
        ASSERT_TRUE(legalDataM == reply);
    }
    finishTime = GetCurrentTime();
    speed = GetSpeed(finishTime - startTime, LEGAL_SIZE_M, MULTIPLEX_TIMES);
    printf("Transfer 16k data with speed of %.2fk/s.\n", speed);

    std::string legalDataL(LEGAL_SIZE_L, 'a');
    startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        testService->TransOversizedPkt(legalDataL, reply);
        ASSERT_TRUE(legalDataL == reply);
    }
    finishTime = GetCurrentTime();
    speed = GetSpeed(finishTime - startTime, LEGAL_SIZE_L, MULTIPLEX_TIMES);
    printf("Transfer 63k data with speed of %.2fk/s.\n", speed);

    std::string illegalData(ILLEGAL_SIZE, 'a');
    testService->TransOversizedPkt(illegalData, reply);
    ASSERT_TRUE(illegalData != reply);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall004
 * @tc.desc: Verify the communication with remote server is stable
 * @tc.type: PERF
 * @tc.require: SR000CS1C1/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall004, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_004);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to call remote function repeatedly.
     * @tc.expected: step2.All remote calls succeed and return 0.
     */
    for (int i = 0; i < REPEAT_TIMES; i++) {
        int reply = 0;
        int result = testService->ReverseInt(2019, reply);
        EXPECT_EQ(result, 0);
        EXPECT_EQ(reply, 9102);
    }

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall005
 * @tc.desc: Test the delay of remote call with remote server
 * @tc.type: PERF
 * @tc.require: SR000CS1C1/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall005, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_005);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to call remote function, and calculate the time consumption.
     * @tc.expected: step2.Remote call succeeds and the time delay is close to 15ms.
     */
    int64_t startTime = GetCurrentTime();
    int reply = 0;
    int result = testService->ReverseInt(2019, reply);
    int64_t finishTime = GetCurrentTime();
    EXPECT_GE(finishTime - startTime, 0L);
    printf("Remote call costs %" PRId64"ms\n", (finishTime - startTime));
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall006
 * @tc.desc: Verify the communications with remote device can be multiplexed
 * @tc.type: FUNC
 * @tc.require: SR000CS1C1/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall006, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_006);
    DBINDER_LOGI("");

    vector<sptr<IRemoteObject>> objects;
    vector<sptr<IDBinderTestService>> testServices;
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        /*
         * @tc.steps: step1.Get a proxy from remote server and stores it.
         * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
         */
        objects.push_back(manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_));
        testServices.push_back(iface_cast<IDBinderTestService>(objects[i]));

        /*
         * @tc.steps: step2.Use the proxy object to invoke remote function.
         * @tc.expected: step2.Remote call succeeds and returns 0.
         */
        int reply = 0;
        int result = testServices[i]->ReverseInt(2019, reply);
        EXPECT_EQ(result, 0);
        EXPECT_EQ(reply, 9102);
    }

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall007
 * @tc.desc: Verify local client can transfer a local object to remote device.
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall007, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_007);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a local binder object and a proxy pointing to remote stub.
     * @tc.expected: step1.Get both objects successfully.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    sptr<IRemoteObject> remoteObject = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(remoteObject != nullptr);

    sptr<IDBinderTestService> remoteTestService = iface_cast<IDBinderTestService>(remoteObject);
    ASSERT_TRUE(remoteTestService != nullptr);

    /*
     * @tc.steps: step2.Transfer the binder object to remote device.
     * @tc.expected: step2.Remote device receives the object and use it to communicate with server.
     */
    int reply = 0;
    int withdrawRes = 0;
    int result =
        remoteTestService->TransProxyObject(2019, object, OHOS::DBinderTestServiceProxy::NOT_SAVE, reply, withdrawRes);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);
    EXPECT_EQ(withdrawRes, 0);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall008
 * @tc.desc: Verify local client can transfer two different local objects to remote device.
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall008, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_008);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a local binder object and a proxy pointing to remote stub.
     * @tc.expected: step1.Get both objects successfully.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    sptr<IRemoteObject> object2 = manager_->GetSystemAbility(RPC_TEST_SERVICE);
    ASSERT_TRUE(object2 != nullptr);
    sptr<IRemoteObject> remoteObject = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(remoteObject != nullptr);

    sptr<IDBinderTestService> remoteTestService = iface_cast<IDBinderTestService>(remoteObject);
    ASSERT_TRUE(remoteTestService != nullptr);

    /*
     * @tc.steps: step2.Transfer two binder objects to remote device.
     * @tc.expected: step2.Remote device receives the objects and use them to communicate with server.
     */
    int reply = 0;
    int withdrawRes = 0;
    int result =
        remoteTestService->TransProxyObject(2019, object, OHOS::DBinderTestServiceProxy::NOT_SAVE, reply, withdrawRes);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);
    EXPECT_EQ(withdrawRes, 0);

    result =
        remoteTestService->TransProxyObject(2019, object2, OHOS::DBinderTestServiceProxy::NOT_SAVE, reply, withdrawRes);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);
    EXPECT_EQ(withdrawRes, 0);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall009
 * @tc.desc: Verify local client is transmitting the same proxy every time to server.
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall009, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_009);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a local binder object and a proxy pointing to remote stub.
     * @tc.expected: step1.Get both objects successfully.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    sptr<IRemoteObject> remoteObject = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(remoteObject != nullptr);

    sptr<IDBinderTestService> remoteTestService = iface_cast<IDBinderTestService>(remoteObject);
    ASSERT_TRUE(remoteTestService != nullptr);

    /*
     * @tc.steps: step2.Transfer the binder object to remote device twice.
     * @tc.expected: step2.Remote device receives same object in two transmissions.
     */
    int reply = 0;
    int withdrawRes = 0;
    int result = remoteTestService->TransProxyObject(2019, object, DBinderTestServiceProxy::SAVE, reply, withdrawRes);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);
    EXPECT_EQ(withdrawRes, 0);

    result = remoteTestService->TransProxyObject(2019, object, DBinderTestServiceProxy::WITHDRAW, reply, withdrawRes);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);
    EXPECT_EQ(withdrawRes, 0);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall011
 * @tc.desc: Verify transferring objects between remote devices is stable
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall011, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_011);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a local binder object and a proxy pointing to remote stub.
     * @tc.expected: step1.Get both objects successfully.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    sptr<IRemoteObject> remoteObject = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(remoteObject != nullptr);

    sptr<IDBinderTestService> remoteTestService = iface_cast<IDBinderTestService>(remoteObject);
    ASSERT_TRUE(remoteTestService != nullptr);

    /*
     * @tc.steps: step2.Transfer the binder object to remote device repeatedly.
     * @tc.expected: step2.Remote device receives the object and use it to communicate with server.
     */
    for (int i = 0; i < REPEAT_TIMES; i++) {
        int reply = 0;
        int withdrawRes = 0;
        int result =
            remoteTestService->TransProxyObject(2019, object, DBinderTestServiceProxy::NOT_SAVE, reply, withdrawRes);
        EXPECT_EQ(result, 0);
        EXPECT_EQ(reply, 9102);
    }

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall012
 * @tc.desc: Test the delay of transferring an object between remote devices
 * @tc.type: PERF
 * @tc.require: SR000CS1C8/SR000CS1CA/SR000CUFFU
 */
HWTEST_F(DbinderTest, DbinderRemoteCall012, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_012);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a local binder object and a proxy pointing to remote stub.
     * @tc.expected: step1.Get both objects successfully.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE);
    ASSERT_TRUE(object != nullptr);
    sptr<IRemoteObject> remoteObject = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(remoteObject != nullptr);

    sptr<IDBinderTestService> remoteTestService = iface_cast<IDBinderTestService>(remoteObject);
    ASSERT_TRUE(remoteTestService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to transfer object, and calculate the time consumption.
     * @tc.expected: step2.Remote call succeeds and the time delay is close to 50ms.
     */
    int64_t startTime = GetCurrentTime();
    int reply = 0;
    int withdrawRes = 0;
    int result =
        remoteTestService->TransProxyObject(2019, object, DBinderTestServiceProxy::NOT_SAVE, reply, withdrawRes);
    int64_t finishTime = GetCurrentTime();
    EXPECT_GE(finishTime - startTime, 0L);
    printf("Transferring an object costs %" PRId64 "ms\n", (finishTime - startTime));
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall014
 * @tc.desc: Verify adding and removing death recipient successfully
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA
 */
HWTEST_F(DbinderTest, DbinderRemoteCall014, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_DEATH_RECIPIENT_001);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Add death recipient.
     * @tc.expected: step2.Register death notification successfully.
     */
    sptr<IRemoteObject::DeathRecipient> deathRecipient(new DBinderTestDeathRecipient());
    bool result = object->AddDeathRecipient(deathRecipient);
    EXPECT_EQ(result, true);

    /*
     * @tc.steps: step3.Remove death recipient
     * @tc.expected: step3.Unregister death notification successfully.
     */
    result = object->RemoveDeathRecipient(deathRecipient);
    EXPECT_EQ(result, true);

    /*
     * @tc.steps: step4.Use the proxy object to invoke remote function.
     * @tc.expected: step4.Remote call succeeds and returns 0.
     */
    int reply = 0;
    int res = testService->ReverseInt(2019, reply);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(reply, 9102);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall015
 * @tc.desc: Verify adding and removing death recipient successfully
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA
 */
HWTEST_F(DbinderTest, DbinderRemoteCall015, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_DEATH_RECIPIENT_002);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    sptr<IRemoteObject::DeathRecipient> deathRecipient;
    bool result = true;
    int reply = 0, res = 0;
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        /*
         * @tc.steps: step2.Add death recipient.
         * @tc.expected: step2.Register death notification successfully.
         */
        deathRecipient = new DBinderTestDeathRecipient();
        result = object->AddDeathRecipient(deathRecipient);
        EXPECT_EQ(result, true);

        /*
         * @tc.steps: step3.Remove death recipient
         * @tc.expected: step3.Unregister death notification successfully.
         */
        result = object->RemoveDeathRecipient(deathRecipient);
        EXPECT_EQ(result, true);

        /*
         * @tc.steps: step4.Use the proxy object to invoke remote function.
         * @tc.expected: step4.Remote call succeeds and returns 0.
         */
        res = testService->ReverseInt(2019, reply);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(reply, 9102);
    }

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall016
 * @tc.desc: Verify adding and removing death recipient successfully
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA
 */
HWTEST_F(DbinderTest, DbinderRemoteCall016, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_DEATH_RECIPIENT_003);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Add two death recipients.
     * @tc.expected: step2.Register two death notifications successfully.
     */
    sptr<IRemoteObject::DeathRecipient> deathRecipient(new DBinderTestDeathRecipient());
    bool result = object->AddDeathRecipient(deathRecipient);
    EXPECT_EQ(result, true);

    sptr<IRemoteObject::DeathRecipient> deathRecipientRepeat(new DBinderTestDeathRecipient());
    result = object->AddDeathRecipient(deathRecipientRepeat);
    EXPECT_EQ(result, true);

    /*
     * @tc.steps: step3.Remove two death recipients.
     * @tc.expected: step3.Return false when unregisterring 1st death notification because there is another one left.
     * Return true when unregisterring 2nd death notification because all clean.
     */
    result = object->RemoveDeathRecipient(deathRecipient);
    EXPECT_EQ(result, false);

    result = object->RemoveDeathRecipient(deathRecipientRepeat);
    EXPECT_EQ(result, true);

    /*
     * @tc.steps: step4.Use the proxy object to invoke remote function.
     * @tc.expected: step4.Remote call succeeds and returns 0.
     */
    int reply = 0;
    int res = testService->ReverseInt(2019, reply);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(reply, 9102);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall017
 * @tc.desc: Verify receiving death notification when remote device dies
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA
 */
HWTEST_F(DbinderTest, DbinderRemoteCall017, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_DEATH_RECIPIENT_004);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Add death recipient.
     * @tc.expected: step2.Register death notification successfully.
     */
    sptr<IRemoteObject::DeathRecipient> deathRecipient(new DBinderTestDeathRecipient());
    bool result = object->AddDeathRecipient(deathRecipient);
    ASSERT_TRUE(result == true);

    /*
     * @tc.steps: step3.Stop remote service. Wait 10s, then check death notification.
     * @tc.expected: step3.Stop it successfully, and receive death notification.
     */
    std::string command = "KILL";
    std::string cmdArgs = "server";
    std::string expectValue = "0";
    bool ret = RunCmdOnAgent(AGENT_NO::ONE, command, cmdArgs, expectValue);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(GetReturnVal(), 0);

    // wait for killing remote service
    sleep(10);
    result = DBinderTestDeathRecipient::GotDeathRecipient();
    EXPECT_EQ(result, true);
    DBinderTestDeathRecipient::ClearDeathRecipient();
    printf("Succ! Recv death notification!\n");

    /*
     * @tc.steps: step4.Remove death recipient
     * @tc.expected: step4.Fail to remove death recipient
     * because when receiving death notification, it remove death recipient automatically.
     */
    result = object->RemoveDeathRecipient(deathRecipient);
    EXPECT_EQ(result, false);

    /*
     * @tc.steps: step5.Restart remote service and wait 10s.
     * @tc.expected: step5.Restart it successfully.
     */
    std::string restartCommand = "RESTART";
    ret = RunCmdOnAgent(AGENT_NO::ONE, restartCommand, cmdArgs, expectValue);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(GetReturnVal(), 0);

    // wait for restarting server
    sleep(10);

    /*
     * @tc.steps: step6.Get a proxy (called testService2) from remote server.
     * @tc.expected: step6.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object2 = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object2 != nullptr);

    sptr<IDBinderTestService> testService2 = iface_cast<IDBinderTestService>(object2);
    ASSERT_TRUE(testService2 != nullptr);

    /*
     * @tc.steps: step7.Use the proxy object to invoke remote function.
     * @tc.expected: step7.Remote call succeeds and returns 0.
     */
    int reply = 0;
    int res = testService2->ReverseInt(2019, reply);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(reply, 9102);

    object = nullptr;
    testService = nullptr;
    object2 = nullptr;
    testService2 = nullptr;

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall018
 * @tc.desc: Verify transferring raw data
 * @tc.type: FUNC
 * @tc.require: AR000ER7PF
 */
HWTEST_F(DbinderTest, DbinderRemoteCall018, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_RAW_DATA_001);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to transfer raw data.
     * @tc.expected: step2.Remote call succeed and return the size of raw data.
     */
    // ProxyTransRawData cannot transfer data less than 2.
    int result = testService->ProxyTransRawData(rawData100M);
    EXPECT_EQ(result, 0);
    result = testService->ProxyTransRawData(rawData100M);
    EXPECT_EQ(result, 0);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall019
 * @tc.desc: Test the speed of transferring raw data by proxy
 * @tc.type: PERF
 * @tc.require: SR000D48A5
 */
HWTEST_F(DbinderTest, DbinderRemoteCall019, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_RAW_DATA_002);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to transfer raw data with different size.
     * @tc.expected: step2.Remote calls succeed and return the size of raw data.
     */
    int result;
    int64_t startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        result = testService->ProxyTransRawData(rawData10K);
        EXPECT_EQ(result, 0);
    }
    int64_t finishTime = GetCurrentTime();
    float speed = GetSpeed(finishTime - startTime, rawData10K, MULTIPLEX_TIMES);
    printf("Transfer 10K raw data with speed of %.2fk/s.\n", speed);

    startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        result = testService->ProxyTransRawData(rawData100K);
        EXPECT_EQ(result, 0);
    }
    finishTime = GetCurrentTime();
    speed = GetSpeed(finishTime - startTime, rawData100K, MULTIPLEX_TIMES);
    printf("Transfer 100K raw data with speed of %.2fk/s.\n", speed);

    startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        result = testService->ProxyTransRawData(rawData1M);
        EXPECT_EQ(result, 0);
    }
    finishTime = GetCurrentTime();
    speed = GetSpeed(finishTime - startTime, rawData1M, MULTIPLEX_TIMES);
    printf("Transfer 1M raw data with speed of %.2fk/s.\n", speed);

    startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        result = testService->ProxyTransRawData(rawData10M);
        EXPECT_EQ(result, 0);
    }
    finishTime = GetCurrentTime();
    speed = GetSpeed(finishTime - startTime, rawData10M, MULTIPLEX_TIMES);
    printf("Transfer 10M raw data with speed of %.2fk/s.\n", speed);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall020
 * @tc.desc: Verify it is stable to transfer raw data
 * @tc.type: FUNC
 * @tc.require: SR000D48A5
 */
HWTEST_F(DbinderTest, DbinderRemoteCall020, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_RAW_DATA_003);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to transfer raw data with different size.
     * @tc.expected: step2.Remote calls succeed and return the size of raw data.
     */
    int result;
    for (int i = 0; i < REPEAT_RAW_DATA_TIMES; i++) {
        result = testService->ProxyTransRawData(rawData10M);
        EXPECT_EQ(result, 0);
    }

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall021
 * @tc.desc: Verify reply can carry big raw data
 * @tc.type: FUNC
 * @tc.require: AR000DAPPO
 */
HWTEST_F(DbinderTest, DbinderRemoteCall021, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_RAW_DATA_004);
    DBINDER_LOGI("");
    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to ask stub to transfer raw data.
     * @tc.expected: step2.Remote call succeed and return 0.
     */
    // StubTransRawData cannot ask data less than 2.
    int result = testService->StubTransRawData(rawData10M);
    EXPECT_EQ(result, 0);
    result = testService->StubTransRawData(rawData100M);
    EXPECT_EQ(result, 0);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}


/*
 * @tc.name: DbinderRemoteCall022
 * @tc.desc: Test the speed of transferring raw data by stub
 * @tc.type: PERF
 * @tc.require: AR000DAPPO
 */
HWTEST_F(DbinderTest, DbinderRemoteCall022, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_RAW_DATA_005);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to transfer raw data with different size.
     * @tc.expected: step2.Remote calls succeed and return the size of raw data.
     */
    int result;
    int64_t startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        result = testService->StubTransRawData(rawData10K);
        EXPECT_EQ(result, 0);
    }
    int64_t finishTime = GetCurrentTime();
    float speed = GetSpeed(finishTime - startTime, rawData10K, MULTIPLEX_TIMES);
    printf("Receive 10K raw data with speed of %.2fk/s.\n", speed);

    startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        result = testService->StubTransRawData(rawData100K);
        EXPECT_EQ(result, 0);
    }
    finishTime = GetCurrentTime();
    speed = GetSpeed(finishTime - startTime, rawData100K, MULTIPLEX_TIMES);
    printf("Receive 100K raw data with speed of %.2fk/s.\n", speed);

    startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        result = testService->StubTransRawData(rawData1M);
        EXPECT_EQ(result, 0);
    }
    finishTime = GetCurrentTime();
    speed = GetSpeed(finishTime - startTime, rawData1M, MULTIPLEX_TIMES);
    printf("Receive 1M raw data with speed of %.2fk/s.\n", speed);

    startTime = GetCurrentTime();
    for (int i = 0; i < MULTIPLEX_TIMES; i++) {
        result = testService->StubTransRawData(rawData10M);
        EXPECT_EQ(result, 0);
    }
    finishTime = GetCurrentTime();
    speed = GetSpeed(finishTime - startTime, rawData10M, MULTIPLEX_TIMES);
    printf("Receive 10M raw data with speed of %.2fk/s.\n", speed);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall023
 * @tc.desc: Verify it is stable to transfer raw data by stub
 * @tc.type: FUNC
 * @tc.require: AR000DAPPO
 */
HWTEST_F(DbinderTest, DbinderRemoteCall023, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_RAW_DATA_006);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to transfer raw data with different size.
     * @tc.expected: step2.Remote calls succeed and return the size of raw data.
     */
    int result;
    for (int i = 0; i < REPEAT_RAW_DATA_TIMES; i++) {
        result = testService->StubTransRawData(rawData10M);
        EXPECT_EQ(result, 0);
    }

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

#ifndef CONFIG_STANDARD_SYSTEM
/*
 * @tc.name: DbinderRemoteCall024
 * @tc.desc: trace test
 * @tc.type: FUNC
 * @tc.require: SR000CPN5H AR000CPN5I AR000CPN5J
 */
HWTEST_F(DbinderTest, DbinderRemoteCall024, TestSize.Level3)
{
    DBINDER_LOGI("");
    SetCurrentTestCase(DBINDER_TEST_TRACE_001);
    HiTraceId traceId = HiTrace::Begin("rpc hitrace", 0);

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to transfer trace id.
     * @tc.expected: step2.Remote calls succeed and trace id equal local trace id.
     */
    uint64_t childId = 0;
    int result = testService->GetChildId(childId);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(childId, traceId.GetChainId());

    SetCurrentTestCase(DBINDER_TEST_INIT);
}
#endif

/*
 * @tc.name: DbinderRemoteCall025
 * @tc.desc: Test trans stub object
 * @tc.type: PERF
 * @tc.require: SR000CQSAB AR000DAPPM
 */
HWTEST_F(DbinderTest, DbinderRemoteCall025, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_TRANS_STUB_001);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a local binder object and a proxy pointing to remote stub.
     * @tc.expected: step1.Get both objects successfully.
     */
    sptr<IRemoteObject> object = new DBinderTestService();
    ASSERT_TRUE(object != nullptr);
    sptr<IRemoteObject> remoteObject = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(remoteObject != nullptr);

    sptr<IDBinderTestService> remoteTestService = iface_cast<IDBinderTestService>(remoteObject);
    ASSERT_TRUE(remoteTestService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to transfer stub object
     * @tc.expected: step2.Remote call succeeds.
     */
    int reply = 0;
    int stubReply = 0;
    int result = remoteTestService->TransStubObject(2019, object, reply, stubReply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);
    EXPECT_EQ(stubReply, 2019);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall026
 * @tc.desc: Verify it is stable to transfer raw data by stub
 * @tc.type: FUNC
 * @tc.require: AR000DHOVU SR000DHOVT
 */
HWTEST_F(DbinderTest, DbinderRemoteCall026, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_FLUSH_COMMAND_001);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a local binder object and a proxy pointing to remote stub.
     * @tc.expected: step1.Get both objects successfully.
     */
    sptr<IRemoteObject> object = new DBinderTestService();
    ASSERT_TRUE(object != nullptr);
    sptr<IRemoteObject> remoteObject = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(remoteObject != nullptr);

    sptr<IDBinderTestService> remoteTestService = iface_cast<IDBinderTestService>(remoteObject);
    ASSERT_TRUE(remoteTestService != nullptr);

    /*
     * @tc.steps: step2.Use the proxy object to flush commands
     * @tc.expected: step2.Remote call succeeds.
     */
    int result = remoteTestService->FlushAsyncCommands(MULTIPLEX_TIMES, rawData10K);
    EXPECT_EQ(result, 0);

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall027
 * @tc.desc: Death notice for anonymous objects
 * @tc.type: FUNC
 * @tc.require: SR000DP5BC
 */
HWTEST_F(DbinderTest, DbinderRemoteCall027, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_DEATH_RECIPIENT_007);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Get two anonymous objects.
     * @tc.expected: step2.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> proxy1 = testService->GetRemoteObject(IDBinderTestService::FIRST_OBJECT);
    ASSERT_TRUE(proxy1 != nullptr);

    sptr<IRemoteObject> proxy2 = testService->GetRemoteObject(IDBinderTestService::SECOND_OBJECT);
    ASSERT_TRUE(proxy2 != nullptr);

    sptr<IDBinderTestService> remoteTestService1 = iface_cast<IDBinderTestService>(proxy1);
    ASSERT_TRUE(remoteTestService1 != nullptr);

    sptr<IDBinderTestService> remoteTestService2 = iface_cast<IDBinderTestService>(proxy2);
    ASSERT_TRUE(remoteTestService2 != nullptr);

    /*
     * @tc.steps: step3.Use the proxy object to invoke remote function.
     * @tc.expected: step3.Remote call succeeds and returns 0.
     */
    int reply;
    int result = remoteTestService1->ReverseInt(2019, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    result = remoteTestService2->ReverseInt(2019, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    /*
     * @tc.steps: step4.Add death recipient.
     * @tc.expected: step4.Register death notification successfully.
     */
    sptr<IRemoteObject::DeathRecipient> deathRecipient1(new DBinderTestDeathRecipient());
    bool ret = proxy1->AddDeathRecipient(deathRecipient1);
    ASSERT_TRUE(ret == true);

    sptr<IRemoteObject::DeathRecipient> deathRecipient2(new DBinderTestDeathRecipient());
    ret = proxy2->AddDeathRecipient(deathRecipient2);
    ASSERT_TRUE(ret == true);

    /*
     * @tc.steps: step5.Stop remote service. Wait 10s, then check death notification.
     * @tc.expected: step5.Stop it successfully, and receive death notification.
     */
    std::string command = "KILL";
    std::string cmdArgs = "server";
    std::string expectValue = "0";
    ret = RunCmdOnAgent(AGENT_NO::ONE, command, cmdArgs, expectValue);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(GetReturnVal(), 0);

    // wait for killing remote service
    sleep(10);
    EXPECT_EQ(DBinderTestDeathRecipient::GotDeathRecipient(), true);
    EXPECT_EQ(DBinderTestDeathRecipient::GotDeathRecipient(), true);
    DBinderTestDeathRecipient::ClearDeathRecipient();
    printf("Succ! Recv death notification!\n");

    /*
     * @tc.steps: step6.Remove death recipient
     * @tc.expected: step6.Fail to remove death recipient
     * because when receiving death notification, it remove death recipient automatically.
     */
    ret = proxy1->RemoveDeathRecipient(deathRecipient1);
    EXPECT_EQ(ret, false);

    ret = proxy2->RemoveDeathRecipient(deathRecipient2);
    EXPECT_EQ(ret, false);

    /*
     * @tc.steps: step7.Restart remote service and wait 10s.
     * @tc.expected: step7.Restart it successfully.
     */
    std::string restartCommand = "RESTART";
    ret = RunCmdOnAgent(AGENT_NO::ONE, restartCommand, cmdArgs, expectValue);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(GetReturnVal(), 0);

    // wait for restarting server
    sleep(10);

    /*
     * @tc.steps: step8.Get a proxy (called testService2) from remote server.
     * @tc.expected: step8.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object2 = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object2 != nullptr);

    sptr<IDBinderTestService> testService2 = iface_cast<IDBinderTestService>(object2);
    ASSERT_TRUE(testService2 != nullptr);

    /*
     * @tc.steps: step9.Use the proxy object to invoke remote function.
     * @tc.expected: step9.Remote call succeeds and returns 0.
     */
    result = testService2->ReverseInt(2019, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    object = nullptr;
    testService = nullptr;
    object2 = nullptr;
    testService2 = nullptr;

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall028
 * @tc.desc: Death notice for anonymous objects
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA
 */
HWTEST_F(DbinderTest, DbinderRemoteCall028, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_015);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != nullptr);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != nullptr);

    /*
     * @tc.steps: step2.Get two anonymous objects.
     * @tc.expected: step2.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> proxy1 = testService->GetRemoteObject(IDBinderTestService::FIRST_OBJECT);
    ASSERT_TRUE(proxy1 != nullptr);

    sptr<IRemoteObject> proxy2 = testService->GetRemoteObject(IDBinderTestService::FIRST_OBJECT);
    ASSERT_TRUE(proxy2 != nullptr);

    sptr<IDBinderTestService> remoteTestService1 = iface_cast<IDBinderTestService>(proxy1);
    ASSERT_TRUE(remoteTestService1 != nullptr);

    sptr<IDBinderTestService> remoteTestService2 = iface_cast<IDBinderTestService>(proxy2);
    ASSERT_TRUE(remoteTestService2 != nullptr);

    /*
     * @tc.steps: step3.Use the proxy object to invoke remote function.
     * @tc.expected: step3.Remote call succeeds and returns 0.
     */
    int reply;
    int result = remoteTestService1->ReverseInt(2019, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    result = remoteTestService2->ReverseInt(2019, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    testService->ClearRemoteDecTimes();

    proxy1 = nullptr;
    remoteTestService1 = nullptr;
    EXPECT_EQ(testService->GetRemoteDecTimes(), 1);

    proxy2 = nullptr;
    remoteTestService2 = nullptr;
    EXPECT_EQ(testService->GetRemoteDecTimes(), 2);

    object = nullptr;
    testService = nullptr;

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

/*
 * @tc.name: DbinderRemoteCall029
 * @tc.desc: Death notice for anonymous objects
 * @tc.type: FUNC
 * @tc.require: SR000CS1C8/SR000CS1CA
 */
HWTEST_F(DbinderTest, DbinderRemoteCall029, TestSize.Level3)
{
    SetCurrentTestCase(DBINDER_TEST_REMOTE_CALL_016);
    DBINDER_LOGI("");

    /*
     * @tc.steps: step1.Get a proxy (called testService) from remote server.
     * @tc.expected: step1.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> object = manager_->GetSystemAbility(RPC_TEST_SERVICE, serverId_);
    ASSERT_TRUE(object != NULL);

    sptr<IDBinderTestService> testService = iface_cast<IDBinderTestService>(object);
    ASSERT_TRUE(testService != NULL);

    /*
     * @tc.steps: step2.Get two anonymous objects.
     * @tc.expected: step2.Get the proxy successfully, and the proxy points to remote stub.
     */
    sptr<IRemoteObject> proxy1 = testService->GetRemoteObject(IDBinderTestService::SECOND_OBJECT);
    ASSERT_TRUE(proxy1 != nullptr);

    sptr<IRemoteObject> proxy2 = testService->GetRemoteObject(IDBinderTestService::SECOND_OBJECT);
    ASSERT_TRUE(proxy2 != nullptr);
    ASSERT_TRUE(proxy2 == proxy1);

    sptr<IDBinderTestService> remoteTestService1 = iface_cast<IDBinderTestService>(proxy1);
    ASSERT_TRUE(remoteTestService1 != nullptr);

    sptr<IDBinderTestService> remoteTestService2 = iface_cast<IDBinderTestService>(proxy2);
    ASSERT_TRUE(remoteTestService2 != nullptr);

    /*
     * @tc.steps: step3.Use the proxy object to invoke remote function.
     * @tc.expected: step3.Remote call succeeds and returns 0.
     */
    int reply;
    int result = remoteTestService1->ReverseInt(2019, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    result = remoteTestService2->ReverseInt(2019, reply);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(reply, 9102);

    testService->ClearRemoteDecTimes();

    proxy1 = nullptr;
    proxy2 = nullptr;
    remoteTestService1 = nullptr;
    remoteTestService2 = nullptr;
    sleep(1);
    EXPECT_EQ(testService->GetRemoteDecTimes(), 1);

    object = nullptr;
    testService = nullptr;

    SetCurrentTestCase(DBINDER_TEST_INIT);
}

int main(int argc, char *argv[])
{
    g_pDistributetestEnv = new DistributeTestEnvironment("major.desc");
    testing::AddGlobalTestEnvironment(g_pDistributetestEnv);
    testing::GTEST_FLAG(output) = "xml:./";
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

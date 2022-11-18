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

#define private public
#include "dbinder_service.h"
#undef private
#include "dbinder_service.h"
#include "gtest/gtest.h"
#include "rpc_log.h"
#include "log_tags.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;
using Communication::SoftBus::Session;

class DBinderServiceUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderServiceUnitTest" };
};

void DBinderServiceUnitTest::SetUp() {}

void DBinderServiceUnitTest::TearDown() {}

void DBinderServiceUnitTest::SetUpTestCase() {}

void DBinderServiceUnitTest::TearDownTestCase() {}


/**
 * @tc.name: ProcessOnSessionClosed001
 * @tc.desc: Verify the ProcessOnSessionClosed function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ProcessOnSessionClosed001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService;
    std::shared_ptr<Session> session = nullptr;
    EXPECT_EQ(dBinderService->ProcessOnSessionClosed(session), false);
}

/**
 * @tc.name: StartDBinderService001
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, StartDBinderService001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService ;
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: StartDBinderService002
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, StartDBinderService002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService ;
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    DBinderService::mainThreadCreated_ = true;
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ReStartRemoteListener001
 * @tc.desc: Verify the ReStartRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ReStartRemoteListener001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    dBinderService->remoteListener_ = nullptr;
    bool res = dBinderService->ReStartRemoteListener();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: StartRemoteListener001
 * @tc.desc: Verify the StartRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, StartRemoteListener001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    dBinderService->remoteListener_ = nullptr;
    bool res = dBinderService->StartRemoteListener();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: RegisterRemoteProxy001
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, RegisterRemoteProxy001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService ;
    std::u16string serviceName = std::u16string();
    sptr<IRemoteObject> binderObject = nullptr;
    bool res = dBinderService->RegisterRemoteProxy(serviceName, binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: RegisterRemoteProxy002
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, RegisterRemoteProxy002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::u16string serviceName = std::u16string();
    int32_t systemAbilityId = 0;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, systemAbilityId), false);
}

/**
 * @tc.name: QuerySessionObject001
 * @tc.desc: Verify the QuerySessionObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, QuerySessionObject001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = 0;
    std::shared_ptr<struct SessionInfo> testSession = nullptr;
    testSession = dBinderService->QuerySessionObject(stub);
    EXPECT_EQ(testSession, nullptr);
}

/**
 * @tc.name: AttachDeathRecipient001
 * @tc.desc: Verify the AttachDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, AttachDeathRecipient001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    sptr<IRemoteObject> object = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    bool res = dBinderService->AttachDeathRecipient(object, deathRecipient);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: AttachCallbackProxy001
 * @tc.desc: Verify the AttachCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, AttachCallbackProxy001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    sptr<IRemoteObject> object = nullptr;
    DBinderServiceStub *dbStub = nullptr;
    bool res = dBinderService->AttachCallbackProxy(object, dbStub);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: DetachProxyObject001
 * @tc.desc: Verify the DetachProxyObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, DetachProxyObject001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t binderObject = 0;
    bool res = dBinderService->DetachProxyObject(binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ReGrantPermissionTest001
 * @tc.desc: Verify the ReGrantPermission function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ReGrantPermissionTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::string sessionName;
    EXPECT_EQ(dBinderService->ReGrantPermission(sessionName), false);
}

/**
 * @tc.name: ReGrantPermissionTest002
 * @tc.desc: Verify the ReGrantPermission function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ReGrantPermissionTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::string sessionName("testSession");
    EXPECT_EQ(dBinderService->ReGrantPermission(sessionName), false);
}

/**
 * @tc.name: ReGrantPermissionTest003
 * @tc.desc: Verify the ReGrantPermission function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ReGrantPermissionTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::string sessionName("000000123_456000000");
    EXPECT_EQ(dBinderService->ReGrantPermission(sessionName), false);
}

/**
 * @tc.name: ConvertToSecureDeviceIDTest001
 * @tc.desc: Verify the ConvertToSecureDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ConvertToSecureDeviceIDTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::string deviceID;
    EXPECT_EQ(dBinderService->ConvertToSecureDeviceID(deviceID), "****");
}

/**
 * @tc.name: ConvertToSecureDeviceIDTest002
 * @tc.desc: Verify the ConvertToSecureDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ConvertToSecureDeviceIDTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->ConvertToSecureDeviceID(deviceID),
    deviceID.substr(0, ENCRYPT_LENGTH) + "****" + deviceID.substr(strlen(deviceID.c_str()) - ENCRYPT_LENGTH));
}

/**
 * @tc.name: GetRemoteTransTypeTest003
 * @tc.desc: Verify the GetRemoteTransType function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, GetRemoteTransTypeTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_EQ(dBinderService->GetRemoteTransType(), IRemoteObject::DATABUS_TYPE);
}
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

#include <cstring>
#include "securec.h"
#define private public
#include "dbinder_service.h"
#undef private
#include "dbinder_remote_listener.h"
#include "gtest/gtest.h"
#include "rpc_feature_set.h"
#include "rpc_log.h"
#include "log_tags.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

namespace {
constexpr int TEST_STUB_INDEX = 1234;
}

class DBinderServiceUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "DBinderServiceUnitTest" };
};

void DBinderServiceUnitTest::SetUp() {}

void DBinderServiceUnitTest::TearDown() {}

void DBinderServiceUnitTest::SetUpTestCase() {}

void DBinderServiceUnitTest::TearDownTestCase() {}

class TestDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    TestDeathRecipient() {}
    virtual ~TestDeathRecipient() {}
    void OnRemoteDied(const wptr<IRemoteObject>& object) override {}
};

class TestRpcSystemAbilityCallback : public RpcSystemAbilityCallback {
public:
    sptr<IRemoteObject> GetSystemAbilityFromRemote(int32_t systemAbilityId) override
    {
        return nullptr;
    }

    bool LoadSystemAbilityFromRemote(const std::string& srcNetworkId, int32_t systemAbilityId) override
    {
        return true;
    }
    bool IsDistributedSystemAbility(int32_t systemAbilityId) override
    {
        return true;
    }
};

/*
 * @tc.name: ProcessOnSessionClosed001
 * @tc.desc: Verify the ProcessOnSessionClosed function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ProcessOnSessionClosed001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string networkId = "1234567890";
    EXPECT_EQ(dBinderService->ProcessOnSessionClosed(networkId), true);
}

/*
 * @tc.name: ProcessOnSessionClosed002
 * @tc.desc: Verify the ProcessOnSessionClosed function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ProcessOnSessionClosed002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string networkId = "";
    EXPECT_EQ(dBinderService->ProcessOnSessionClosed(networkId), true);
}

/**
 * @tc.name: StartDBinderService001
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, StartDBinderService001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
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
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    DBinderService::mainThreadCreated_ = true;
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: StartDBinderService003
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, StartDBinderService003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    DBinderService::mainThreadCreated_ = false;
    dBinderService->remoteListener_ = nullptr;
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: StartDBinderService004
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, StartDBinderService004, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    DBinderService::mainThreadCreated_ = false;
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_TRUE(dBinderService->remoteListener_ != nullptr);
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: ReStartRemoteListener001
 * @tc.desc: Verify the ReStartRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ReStartRemoteListener001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->remoteListener_ = nullptr;
    bool res = dBinderService->ReStartRemoteListener();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ReStartRemoteListener002
 * @tc.desc: Verify the ReStartRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ReStartRemoteListener002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_TRUE(dBinderService->remoteListener_ != nullptr);
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
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->remoteListener_ = nullptr;
    bool res = dBinderService->StartRemoteListener();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: StartRemoteListener002
 * @tc.desc: Verify the StartRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, StartRemoteListener002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_TRUE(dBinderService->remoteListener_ != nullptr);
    bool res = dBinderService->StartRemoteListener();
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: RegisterRemoteProxy001
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, RegisterRemoteProxy001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
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
    EXPECT_TRUE(dBinderService != nullptr);
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
    EXPECT_TRUE(dBinderService != nullptr);
    binder_uintptr_t stub = 0;
    std::shared_ptr<struct SessionInfo> testSession = nullptr;
    testSession = dBinderService->QuerySessionObject(stub);
    EXPECT_EQ(testSession, nullptr);
}

/**
 * @tc.name: QuerySessionObject002
 * @tc.desc: Verify the QuerySessionObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, QuerySessionObject002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    binder_uintptr_t stub = 0;
    std::shared_ptr<struct SessionInfo> Session = nullptr;
    EXPECT_EQ(dBinderService->AttachSessionObject(Session, stub), true);
    std::shared_ptr<struct SessionInfo> testSession = dBinderService->QuerySessionObject(stub);
    EXPECT_EQ(testSession, Session);
}

/**
 * @tc.name: AttachDeathRecipient001
 * @tc.desc: Verify the AttachDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, AttachDeathRecipient001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
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
    EXPECT_TRUE(dBinderService != nullptr);
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
    EXPECT_TRUE(dBinderService != nullptr);
    binder_uintptr_t binderObject = 0;
    bool res = dBinderService->DetachProxyObject(binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ConvertToSecureDeviceIDTest001
 * @tc.desc: Verify the ConvertToSecureDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ConvertToSecureDeviceIDTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
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
    EXPECT_TRUE(dBinderService != nullptr);
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
    EXPECT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService->GetRemoteTransType(), IRemoteObject::DATABUS_TYPE);
}

/**
 * @tc.name: StopRemoteListener001
 * @tc.desc: Verify the StopRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, StopRemoteListener001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<DBinderRemoteListener> testListener = std::make_shared<DBinderRemoteListener>();
    EXPECT_TRUE(testListener != nullptr);
    EXPECT_EQ(dBinderService->StartRemoteListener(), true);
    dBinderService->StopRemoteListener();
}

/**
 * @tc.name: GetRemoteTransType001
 * @tc.desc: Verify the GetRemoteTransType function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, GetRemoteListener001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<DBinderRemoteListener> testDbinder = nullptr;
    testDbinder = dBinderService->GetRemoteListener();
    EXPECT_EQ(testDbinder, nullptr);
}

/**
 * @tc.name: GetRemoteListener002
 * @tc.desc: Verify the GetRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, GetRemoteListener002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<DBinderRemoteListener> testListener = std::make_shared<DBinderRemoteListener>();
    EXPECT_TRUE(testListener != nullptr);
    EXPECT_EQ(dBinderService->StartRemoteListener(), false);
    std::shared_ptr<DBinderRemoteListener> testDbinder = nullptr;
    testDbinder = dBinderService->GetRemoteListener();
}

/**
 * @tc.name: GetSeqNumber001
 * @tc.desc: Verify the GetSeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, GetSeqNumber001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->seqNumber_ = 0;
    uint32_t ret = dBinderService->GetSeqNumber();
    EXPECT_EQ(ret, dBinderService->seqNumber_++);
}

/**
 * @tc.name: IsDeviceIdIllegal001
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsDeviceIdIllegal001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string deviceID = "";
    bool res = dBinderService->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsDeviceIdIllegal002
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsDeviceIdIllegal002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string deviceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bool res = dBinderService->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsDeviceIdIllegal003
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsDeviceIdIllegal003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string deviceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bool res = dBinderService->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: CheckBinderObject001
 * @tc.desc: Verify the CheckBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, CheckBinderObject001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<DBinderServiceStub> stub = nullptr;
    binder_uintptr_t binderObject = 1564618;
    bool res = dBinderService->CheckBinderObject(stub, binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: CheckBinderObject002
 * @tc.desc: Verify the CheckBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, CheckBinderObject002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    const std::string serviceName = "abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = 1564618;
    sptr<DBinderServiceStub> stub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(stub != nullptr);
    bool res = dBinderService->CheckBinderObject(stub, binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: IsSameStubObject001
 * @tc.desc: Verify the IsSameStubObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsSameStubObject001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<DBinderServiceStub> stub = nullptr;
    std::u16string service = std::u16string();
    const std::string device = "";
    bool res = dBinderService->IsSameStubObject(stub, service, device);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: MakeRemoteBinder001
 * @tc.desc: Verify the MakeRemoteBinder function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, MakeRemoteBinder001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::u16string serviceName = std::u16string();
    std::string deviceID = "";
    binder_uintptr_t binderObject = 12345;
    uint32_t pid = 0;
    uint32_t uid = 0;
    EXPECT_EQ(dBinderService->MakeRemoteBinder(serviceName, deviceID, binderObject, pid, uid), nullptr);
}

/**
 * @tc.name: MakeRemoteBinder002
 * @tc.desc: Verify the MakeRemoteBinder function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, MakeRemoteBinder002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::u16string serviceName;
    std::string deviceID("001");
    binder_uintptr_t binderObject = 12345;
    uint32_t pid = 0;
    uint32_t uid = 0;
    EXPECT_EQ(dBinderService->MakeRemoteBinder(serviceName, deviceID, binderObject, pid, uid), nullptr);
}

/**
 * @tc.name: MakeRemoteBinderTest003
 * @tc.desc: Verify the MakeRemoteBinder function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, MakeRemoteBinderTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::u16string serviceName;
    std::string deviceID("001");
    binder_uintptr_t binderObject = 12345;
    uint32_t pid = 10;
    uint32_t uid = 10;
    EXPECT_EQ(dBinderService->MakeRemoteBinder(serviceName, deviceID, binderObject, pid, uid), nullptr);
}

/**
 * @tc.name: SendEntryToRemote001
 * @tc.desc: Verify the SendEntryToRemote function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, SendEntryToRemote001, TestSize.Level1)
{
    std::string serviceName = "testServiceName";
    std::string deviceID = "testDeviceID";
    binder_uintptr_t binderObject = 161561;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<DBinderServiceStub> stub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(stub != nullptr);
    uint32_t seqNumber = 0;
    uint32_t pid = 0;
    uint32_t uid = 0;
    bool res = dBinderService->SendEntryToRemote(stub, seqNumber, pid, uid);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: CheckSystemAbilityId001
 * @tc.desc: Verify the CheckSystemAbilityId function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, CheckSystemAbilityId001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    int32_t systemAbilityId = 0x00000002;
    bool res = dBinderService->CheckSystemAbilityId(systemAbilityId);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: AllocFreeSocketPort001
 * @tc.desc: Verify the AllocFreeSocketPort function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, AllocFreeSocketPort001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    uint16_t ret = dBinderService->AllocFreeSocketPort();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: IsSameLoadSaItem001
 * @tc.desc: Verify the IsSameLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsSameLoadSaItem001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string srcNetworkId = "aaaaaaaaaaaaaa";
    int32_t systemAbilityId = 123;
    std::shared_ptr<DHandleEntryTxRx> loadSaItem = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(loadSaItem != nullptr);
    loadSaItem->stubIndex = 123;
    strcpy_s(loadSaItem->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, "aaaaaaaaaaaaaa");
    bool res = dBinderService->IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsSameLoadSaItem002
 * @tc.desc: Verify the IsSameLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsSameLoadSaItem002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string srcNetworkId = "bbbbbbb";
    int32_t systemAbilityId = 123;
    std::shared_ptr<DHandleEntryTxRx> loadSaItem = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(loadSaItem != nullptr);
    loadSaItem->stubIndex = 123;
    strcpy_s(loadSaItem->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, "aaaaaaaaaaaaaa");
    bool res = dBinderService->IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: IsSameLoadSaItem003
 * @tc.desc: Verify the IsSameLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsSameLoadSaItem003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string srcNetworkId = "aaaaaaaaaaaaaa";
    int32_t systemAbilityId = 321;
    std::shared_ptr<DHandleEntryTxRx> loadSaItem = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(loadSaItem != nullptr);
    loadSaItem->stubIndex = 123;
    strcpy_s(loadSaItem->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, "aaaaaaaaaaaaaa");
    bool res = dBinderService->IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: OnRemoteInvokerMessage002
 * @tc.desc: Verify the OnRemoteInvokerMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, OnRemoteInvokerMessage002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(message != nullptr);
    memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->stubIndex = TEST_STUB_INDEX;
    dBinderService->dbinderCallback_ = std::make_shared<TestRpcSystemAbilityCallback>();
    EXPECT_TRUE(dBinderService->dbinderCallback_ != nullptr);
    bool res = dBinderService->OnRemoteInvokerMessage(message);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: GetDatabusNameByProxyTest001
 * @tc.desc: Verify the GetDatabusNameByProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, GetDatabusNameByProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    IPCObjectProxy* proxy = nullptr;
    std::string res = dBinderService->GetDatabusNameByProxy(proxy);
    EXPECT_EQ(res, "");
    IPCObjectProxy object(16);
    res = dBinderService->GetDatabusNameByProxy(&object);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: InvokerRemoteDBinderTest001
 * @tc.desc: Verify the InvokerRemoteDBinder function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, InvokerRemoteDBinderTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<DBinderServiceStub> stub = nullptr;
    uint32_t seqNumber = 123456;
    uint32_t pid = 0;
    uint32_t uid = 0;
    int32_t ret = dBinderService->InvokerRemoteDBinder(stub, seqNumber, pid, uid);
    EXPECT_EQ(ret, DBinderErrorCode::STUB_INVALID);
    std::string serviceName("testServer");
    std::string deviceID("123456");
    binder_uintptr_t binderObject = 100;
    stub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(stub != nullptr);
    ret = dBinderService->InvokerRemoteDBinder(stub, seqNumber, pid, uid);
    EXPECT_EQ(ret, DBinderErrorCode::SEND_MESSAGE_FAILED);
}

/**
 * @tc.name: CreateDatabusNameTest001
 * @tc.desc: Verify the CreateDatabusName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, CreateDatabusNameTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    int pid = 0;
    int uid = 0;
    std::string res = dBinderService->CreateDatabusName(pid, uid);
    EXPECT_EQ(res, "");
    pid = 10;
    uid = 10;
    res = dBinderService->CreateDatabusName(pid, uid);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: FindServicesByDeviceIDTest001
 * @tc.desc: Verify the FindServicesByDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, FindServicesByDeviceIDTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string serviceName("testServer");
    std::string deviceID("123456");
    binder_uintptr_t binderObject = 100;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    dBinderService->DBinderStubRegisted_.push_back(dBinderServiceStub);
    std::list<std::u16string> serviceNames;
    serviceNames.push_back(Str8ToStr16(serviceName));
    EXPECT_EQ(dBinderService->FindServicesByDeviceID(deviceID), serviceNames);
}

/**
 * @tc.name: NoticeDeviceDieTest001
 * @tc.desc: Verify the NoticeDeviceDie function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, NoticeDeviceDieTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string deviceID;
    EXPECT_EQ(dBinderService->NoticeDeviceDie(deviceID), DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: NoticeDeviceDieTest002
 * @tc.desc: Verify the NoticeDeviceDie function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, NoticeDeviceDieTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->NoticeDeviceDie(deviceID), DBINDER_SERVICE_NOTICE_DIE_ERR);
}

/**
 * @tc.name: NoticeDeviceDieTest003
 * @tc.desc: Verify the NoticeDeviceDie function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, NoticeDeviceDieTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string deviceID("123456");
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_TRUE(dBinderService->remoteListener_ != nullptr);
    EXPECT_EQ(dBinderService->NoticeDeviceDie(deviceID), DBINDER_SERVICE_NOTICE_DIE_ERR);
}

/**
 * @tc.name: NoticeServiceDieTest001
 * @tc.desc: Verify the NoticeServiceDie function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, NoticeServiceDieTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->StartRemoteListener();
    std::u16string serviceName;
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->NoticeServiceDie(serviceName, deviceID), DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: NoticeServiceDieInnerTest001
 * @tc.desc: Verify the NoticeServiceDieInner function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, NoticeServiceDieInnerTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->StartRemoteListener();
    std::u16string serviceName;
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->NoticeServiceDieInner(serviceName, deviceID), DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: NoticeServiceDieInnerTest002
 * @tc.desc: Verify the NoticeServiceDieInner function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, NoticeServiceDieInnerTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->StartRemoteListener();
    std::u16string serviceName(u"test");
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->NoticeServiceDieInner(serviceName, deviceID), ERR_NONE);
}

/**
 * @tc.name: NoticeServiceDieInnerTest003
 * @tc.desc: Verify the NoticeServiceDieInner function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, NoticeServiceDieInnerTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->StartRemoteListener();
    std::u16string serviceName(u"testServer");
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->NoticeServiceDieInner(serviceName, deviceID), ERR_NONE);
}

/**
 * @tc.name: ProcessCallbackProxyTest001
 * @tc.desc: Verify the ProcessCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ProcessCallbackProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new IPCObjectProxy(16);
    EXPECT_TRUE(object != nullptr);
    std::string serviceName("testServer");
    std::string deviceID("123456");
    binder_uintptr_t binderObject = 100;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    bool res = dBinderService->AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    dBinderService->ProcessCallbackProxy(dBinderServiceStub);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: NoticeCallbackProxyTest001
 * @tc.desc: Verify the NoticeCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, NoticeCallbackProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new IPCObjectProxy(16);
    EXPECT_TRUE(object != nullptr);
    std::string serviceName("testServer");
    std::string deviceID("123456");
    binder_uintptr_t binderObject = 100;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    dBinderService->AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    EXPECT_EQ(dBinderService->NoticeCallbackProxy(dBinderServiceStub), false);
}

/**
 * @tc.name: DetachCallbackProxyTest001
 * @tc.desc: Verify the DetachCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, DetachCallbackProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new IPCObjectProxy(16);
    EXPECT_TRUE(object != nullptr);
    std::string serviceName("test1");
    std::string deviceID("12345");
    binder_uintptr_t binderObject = 100;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    dBinderService->AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    EXPECT_EQ(dBinderService->DetachCallbackProxy(object), true);
}

/**
 * @tc.name: DetachCallbackProxyTest002
 * @tc.desc: Verify the DetachCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, DetachCallbackProxyTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new IPCObjectProxy(100);
    EXPECT_TRUE(object != nullptr);
    EXPECT_EQ(dBinderService->DetachCallbackProxy(object), false);
}

/**
 * @tc.name: QueryDeathRecipientTest001
 * @tc.desc: Verify the QueryDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, QueryDeathRecipientTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new IPCObjectProxy(20);
    EXPECT_TRUE(object != nullptr);
    sptr<IRemoteObject::DeathRecipient> deathRecipient = new TestDeathRecipient();
    EXPECT_TRUE(deathRecipient != nullptr);
    dBinderService->AttachDeathRecipient(object, deathRecipient);
    EXPECT_EQ(dBinderService->QueryDeathRecipient(object), deathRecipient);
}

/**
 * @tc.name: QueryDeathRecipientTest002
 * @tc.desc: Verify the QueryDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, QueryDeathRecipientTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService->QueryDeathRecipient(nullptr), nullptr);
}

/**
 * @tc.name: AttachProxyObjectTest001
 * @tc.desc: Verify the AttachProxyObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, AttachProxyObjectTest001, TestSize.Level1)
{
    std::string name("Test");
    binder_uintptr_t binderObject = 10;
    binder_uintptr_t binderObject1 = 11;
    sptr<IRemoteObject> object = new IPCObjectProxy(16);
    EXPECT_TRUE(object != nullptr);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService->AttachProxyObject(object, binderObject), true);
    EXPECT_EQ(dBinderService->QueryProxyObject(binderObject), object);
    EXPECT_EQ(dBinderService->QueryProxyObject(binderObject1), nullptr);
}

/**
 * @tc.name: AttachProxyObjectTest002
 * @tc.desc: Verify the AttachProxyObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, AttachProxyObjectTest002, TestSize.Level1)
{
    uint32_t seqNumber = 10;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<OHOS::ThreadLockInfo> threadLockInfo = std::make_shared<OHOS::ThreadLockInfo>();
    EXPECT_TRUE(threadLockInfo != nullptr);
    dBinderService->AttachThreadLockInfo(seqNumber, "networkId", threadLockInfo);
    dBinderService->WakeupThreadByStub(seqNumber);
    EXPECT_TRUE(dBinderService->QueryThreadLockInfo(seqNumber) != nullptr);
    EXPECT_EQ(dBinderService->QueryThreadLockInfo(seqNumber), threadLockInfo);
    dBinderService->DetachThreadLockInfo(seqNumber);
    dBinderService->WakeupThreadByStub(seqNumber);
    EXPECT_TRUE(dBinderService->QueryThreadLockInfo(seqNumber) == nullptr);
}

/**
 * @tc.name: MakeSessionByReplyMessageTest001
 * @tc.desc: Verify the MakeSessionByReplyMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, MakeSessionByReplyMessageTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(replyMessage != nullptr);
    memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    dBinderService->MakeSessionByReplyMessage(replyMessage);
    EXPECT_EQ(dBinderService->HasDBinderStub(replyMessage->binderObject), false);

    std::string serviceName("testServer");
    std::string deviceID;
    binder_uintptr_t binderObject = 161561;
    sptr<DBinderServiceStub> stub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(stub != nullptr);
    replyMessage->stub = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    dBinderService->MakeSessionByReplyMessage(replyMessage);
}

/**
 * @tc.name: RegisterRemoteProxyTest001
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, RegisterRemoteProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::u16string serviceName;
    int32_t systemAbilityId = 1;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, systemAbilityId), false);
    serviceName = u"testServer";
    systemAbilityId = 0;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, systemAbilityId), false);
    systemAbilityId = 1;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, systemAbilityId), true);
}

/**
 * @tc.name: RegisterRemoteProxyTest002
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, RegisterRemoteProxyTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::u16string serviceName;
    sptr<IRemoteObject> binderObject = nullptr;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, binderObject), false);
    serviceName = u"testServer";
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, binderObject), false);
    sptr<IRemoteObject> object = new IPCObjectProxy(16);
    EXPECT_TRUE(object != nullptr);
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, object), true);
}

/**
 * @tc.name: GetRegisterServiceTest001
 * @tc.desc: Verify the GetRegisterService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, GetRegisterServiceTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    binder_uintptr_t binderObject = 1;
    EXPECT_EQ(dBinderService->GetRegisterService(binderObject), std::u16string());
    std::u16string serviceName(u"testServer");
    dBinderService->RegisterRemoteProxyInner(serviceName, binderObject);
    EXPECT_EQ(dBinderService->GetRegisterService(binderObject), serviceName);
}

/**
 * @tc.name: OnRemoteMessageTaskTest001
 * @tc.desc: Verify the OnRemoteMessageTask function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, OnRemoteMessageTaskTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<struct DHandleEntryTxRx> handleEntryTxRx = nullptr;
    EXPECT_EQ(dBinderService->OnRemoteMessageTask(handleEntryTxRx), false);
    std::shared_ptr<DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(message != nullptr);
    message->head.len = 10;
    message->head.version = 1;
    message->transType = 0;
    message->fromPort = 1;
    message->toPort = 2;
    message->stubIndex = 1;
    message->seqNumber = 1;
    message->binderObject = 10;
    message->deviceIdInfo.tokenId = 1;
    message->deviceIdInfo.fromDeviceId[0] = 't';
    message->deviceIdInfo.toDeviceId[0] = 't';
    message->stub = 10;
    message->serviceNameLength = 10;
    message->serviceName[0] = 't';
    message->pid = 100;
    message->uid = 100;
    dBinderService->dbinderCallback_ = std::make_shared<TestRpcSystemAbilityCallback>();
    EXPECT_TRUE(dBinderService->dbinderCallback_ != nullptr);
    message->dBinderCode = DBinderCode::MESSAGE_AS_INVOKER;
    EXPECT_EQ(dBinderService->OnRemoteMessageTask(message), true);
    message->dBinderCode = DBinderCode::MESSAGE_AS_REPLY;
    EXPECT_EQ(dBinderService->OnRemoteMessageTask(message), true);
    message->dBinderCode = DBinderCode::MESSAGE_AS_OBITUARY;
    EXPECT_EQ(dBinderService->OnRemoteMessageTask(message), false);
    message->dBinderCode = DBinderCode::MESSAGE_AS_REMOTE_ERROR;
    EXPECT_EQ(dBinderService->OnRemoteMessageTask(message), true);
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest001
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, OnRemoteInvokerDataBusMessageTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    IPCObjectProxy* proxy = nullptr;
    std::string remoteDeviceId;
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(replyMessage != nullptr);
    memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    EXPECT_EQ(dBinderService->OnRemoteInvokerDataBusMessage(
        proxy, replyMessage, remoteDeviceId, pid, uid, tokenId), DBinderErrorCode::DEVICEID_INVALID);
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest002
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, OnRemoteInvokerDataBusMessageTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string remoteDeviceId("test");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    IPCObjectProxy objectProxy(0);
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(replyMessage != nullptr);
    memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    EXPECT_EQ(dBinderService->OnRemoteInvokerDataBusMessage(
        &objectProxy, replyMessage, remoteDeviceId, pid, uid, tokenId), DBinderErrorCode::SESSION_NAME_NOT_FOUND);
}

/*
 * @tc.name: ProcessOnSessionClosedTest002
 * @tc.desc: Verify the ProcessOnSessionClosed function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ProcessOnSessionClosedTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::shared_ptr<OHOS::ThreadLockInfo> threadLockInfo = std::make_shared<OHOS::ThreadLockInfo>();
    EXPECT_TRUE(threadLockInfo != nullptr);
    uint32_t seqNumber = 10;
    std::string networkId = "networkId";
    dBinderService->AttachThreadLockInfo(seqNumber, networkId, threadLockInfo);
    EXPECT_EQ(dBinderService->ProcessOnSessionClosed(networkId), true);
}

/**
 * @tc.name: FindDBinderStub001
 * @tc.desc: Verify the FindDBinderStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, FindDBinderStub001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::u16string service(u"test");
    std::string device = "aaa";
    binder_uintptr_t binderObject = 100;
    sptr<DBinderServiceStub> testDdBinderStub1 = dBinderService->FindOrNewDBinderStub(service, device, binderObject);
    EXPECT_TRUE(testDdBinderStub1 != nullptr);
    sptr<DBinderServiceStub> testDdBinderStub2 = dBinderService->FindOrNewDBinderStub(service, device, binderObject);
    EXPECT_TRUE(testDdBinderStub2 != nullptr);
    EXPECT_EQ(testDdBinderStub1.GetRefPtr(), testDdBinderStub2.GetRefPtr());

    sptr<DBinderServiceStub> testDdBinderStub3 = dBinderService->FindDBinderStub(service, device);
    EXPECT_TRUE(testDdBinderStub3 != nullptr);
    EXPECT_EQ(testDdBinderStub1.GetRefPtr(), testDdBinderStub3.GetRefPtr());

    std::u16string service1(u"test1");
    std::string device1 = "bbb";
    EXPECT_EQ(dBinderService->FindDBinderStub(service1, device1), nullptr);

    EXPECT_EQ(dBinderService->DeleteDBinderStub(service1, device1), false);
    EXPECT_EQ(dBinderService->DeleteDBinderStub(service, device), true);
}

/**
 * @tc.name: ReStartRemoteListenerTest001
 * @tc.desc: Verify the ReStartRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ReStartRemoteListenerTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->remoteListener_ = nullptr;
    bool res = dBinderService->ReStartRemoteListener();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ReStartRemoteListenerTest002
 * @tc.desc: Verify the ReStartRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, ReStartRemoteListenerTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_TRUE(dBinderService->remoteListener_ != nullptr);
    bool res = dBinderService->ReStartRemoteListener();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: IsSameStubObjectTest002
 * @tc.desc: Verify the IsSameStubObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsSameStubObjectTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string serviceName = "test";
    std::string deviceID = "001";
    binder_uintptr_t binderObject = 1;
    sptr<DBinderServiceStub> stub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(stub != nullptr);
    std::u16string service(u"test");
    bool res = dBinderService->IsSameStubObject(stub, service, deviceID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: SendEntryToRemoteTest002
 * @tc.desc: Verify the SendEntryToRemote function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, SendEntryToRemoteTest002, TestSize.Level1)
{
    std::string serviceName("testServer");
    std::string deviceID;
    binder_uintptr_t binderObject = 161561;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    sptr<DBinderServiceStub> stub = new DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(stub != nullptr);
    uint32_t seqNumber = 0;
    uint32_t pid = 0;
    uint32_t uid = 0;
    bool res = dBinderService->SendEntryToRemote(stub, seqNumber, pid, uid);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: PopLoadSaItemTest001
 * @tc.desc: Verify the PopLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, PopLoadSaItemTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    std::string srcNetworkId;
    int32_t systemAbilityId = 1;
    EXPECT_EQ(dBinderService->PopLoadSaItem(srcNetworkId, systemAbilityId), nullptr);

    srcNetworkId = "t";
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(message != nullptr);
    memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->stubIndex = systemAbilityId;
    message->deviceIdInfo.fromDeviceId[0] = 't';
    dBinderService->dbinderCallback_ = std::make_shared<TestRpcSystemAbilityCallback>();
    EXPECT_TRUE(dBinderService->dbinderCallback_ != nullptr);
    dBinderService->OnRemoteInvokerMessage(message);
    std::shared_ptr<DHandleEntryTxRx> dHandleEntryTxRx = dBinderService->PopLoadSaItem(srcNetworkId, systemAbilityId);
    EXPECT_TRUE(dHandleEntryTxRx != nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    dBinderService->LoadSystemAbilityComplete("test", 2, remoteObject);
    dBinderService->LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject);
    sptr<IRemoteObject> remoteObject1 = new IPCObjectProxy(1);
    EXPECT_TRUE(remoteObject1 != nullptr);
    dBinderService->LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject1);
}

/**
 * @tc.name: SendReplyMessageToRemote001
 * @tc.desc: Verify the SendReplyMessageToRemote function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, SendReplyMessageToRemote001, TestSize.Level1)
{
    uint32_t dBinderCode = 4;
    uint32_t reason = 0;
    std::shared_ptr<DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(replyMessage != nullptr);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_TRUE(dBinderService->remoteListener_ != nullptr);
    dBinderService->SendReplyMessageToRemote(dBinderCode, reason, replyMessage);
    dBinderCode = 1;
    dBinderService->SendReplyMessageToRemote(dBinderCode, reason, replyMessage);
    DBinderService *temp = new DBinderService();
    EXPECT_TRUE(temp != nullptr);
    DBinderService::instance_ = temp;
    dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService, DBinderService::instance_);
}

/**
 * @tc.name: AddAsynMessageTask001
 * @tc.desc: Verify the AddAsynMessageTask function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, AddAsynMessageTask001, TestSize.Level1)
{
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<struct DHandleEntryTxRx>();
    EXPECT_NE(message.get(), nullptr);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    dBinderService->AddAsynMessageTask(message);
}

/**
 * @tc.name: IsSameSession002
 * @tc.desc: Verify the IsSameSession function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, IsSameSession002, TestSize.Level1)
{
    std::shared_ptr<struct SessionInfo> oldSession= std::make_shared<struct SessionInfo>();
    EXPECT_NE(oldSession.get(), nullptr);
    std::shared_ptr<struct SessionInfo> newSession= std::make_shared<struct SessionInfo>();
    EXPECT_NE(newSession.get(), nullptr);
    oldSession->stubIndex = 1;
    oldSession->toPort = 2;
    oldSession->fromPort = 3;
    oldSession->type = 4;
    oldSession->serviceName[0] = 't';
    newSession->stubIndex = 2;
    newSession->toPort = 2;
    newSession->fromPort = 3;
    newSession->type = 4;
    newSession->serviceName[0] = 't';
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService->IsSameSession(oldSession, newSession), false);
    newSession->stubIndex = 1;
    newSession->toPort = 12;
    EXPECT_EQ(dBinderService->IsSameSession(oldSession, newSession), false);
    newSession->toPort = 2;
    newSession->fromPort = 13;
    EXPECT_EQ(dBinderService->IsSameSession(oldSession, newSession), false);
    newSession->fromPort = 3;
    newSession->type = 14;
    EXPECT_EQ(dBinderService->IsSameSession(oldSession, newSession), false);
    newSession->type = 4;
    EXPECT_EQ(dBinderService->IsSameSession(oldSession, newSession), true);
}

/**
 * @tc.name: AttachSessionObject001
 * @tc.desc: Verify the AttachSessionObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceUnitTest, AttachSessionObject001, TestSize.Level1)
{
    std::shared_ptr<struct SessionInfo> object = nullptr;
    binder_uintptr_t stub = 0;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService->AttachSessionObject(object, stub), true);
}

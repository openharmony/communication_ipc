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
#include <gmock/gmock.h>
#include <string>

#include "dbinder_service.h"
#include "dbinder_remote_listener.h"
#include "mock_dbinder_remote_listener.h"
#include "mock_iremote_invoker.h"
#include "ipc_thread_skeleton.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

namespace {
    const std::u16string ZERO_SERVICENAME = u"";
    const std::u16string RANDOM_SERVICENAME = u"servicename";
    const std::string RANDOM_DEVICEID = "device";
    const std::string SERVICE_NAME_TEST = "serviceNameTest";
    const std::string ZERO_DEVICEID = "";
    const std::u16string DESCRIPTOR_TEST = u"proxyTest";
    const std::string SESSION_NAME_TEST = "sessionNameTest";
    const std::u16string TEST_MOCK_DESCRIPTOR = u"mockProxyService";
    const int32_t BINDEROBJECT = 1;
    const uint32_t PID = 1;
    const uint32_t UID = 1;
    const uint32_t TOKEN_ID = 1;
    const binder_uintptr_t BINDER_OBJECT = 1ULL;
    constexpr binder_uintptr_t TEST_BINDER_OBJECT_PTR = 1564618;
    constexpr int TEST_STUB_INDEX = 1234;
    constexpr int32_t TEST_SYSTEM_ABILITY_ID = 0x2;
    constexpr int TEST_OBJECT_HANDLE = 16;
    constexpr uint32_t TEST_SEQ_NUMBER = 123456;
    constexpr int TEST_PID = 10;
    constexpr int TEST_UID = 10;
}

class DBinderServiceInterface {
public:
    DBinderServiceInterface() {};
    virtual ~DBinderServiceInterface() {};
    
    virtual bool StartListener() = 0;
    virtual std::shared_ptr<struct DHandleEntryTxRx> CreateMessage(const sptr<DBinderServiceStub> &stub,
        uint32_t seqNumber, uint32_t pid, uint32_t uid) = 0;
    virtual bool SendDataToRemote(const std::string &networkId, const struct DHandleEntryTxRx *msg) = 0;
    virtual int32_t GetLocalNodeDeviceId(const std::string &pkgName, std::string &devId) = 0;
    virtual std::string GetSessionName() = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual bool WriteUint16(uint16_t value) = 0;
    virtual uint64_t ReadUint64() = 0;
    virtual const std::string ReadString() = 0;
    virtual int32_t DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName) = 0;
};
class DBinderServiceInterfaceMock : public DBinderServiceInterface {
public:
    DBinderServiceInterfaceMock();
    ~DBinderServiceInterfaceMock() override;

    MOCK_METHOD0(StartListener, bool());
    MOCK_METHOD4(CreateMessage, std::shared_ptr<struct DHandleEntryTxRx>(const sptr<DBinderServiceStub> &stub,
        uint32_t seqNumber, uint32_t pid, uint32_t uid));
    MOCK_METHOD2(SendDataToRemote, bool(const std::string &networkId, const struct DHandleEntryTxRx *msg));
    MOCK_METHOD2(GetLocalNodeDeviceId, int32_t(const std::string &pkgName, std::string &devId));
    MOCK_METHOD0(GetSessionName, std::string());
    MOCK_METHOD1(WriteUint32, bool(uint32_t value));
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD1(WriteUint16, bool(uint16_t value));
    MOCK_METHOD0(ReadUint64, uint64_t());
    MOCK_METHOD0(ReadString, const std::string());
    MOCK_METHOD3(DBinderGrantPermission, int32_t(int32_t uid, int32_t pid, const std::string &socketName));
};

static void *g_interface = nullptr;

DBinderServiceInterfaceMock::DBinderServiceInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DBinderServiceInterfaceMock::~DBinderServiceInterfaceMock()
{
    g_interface = nullptr;
}

static DBinderServiceInterfaceMock *GetDBinderServiceInterfaceMock()
{
    return reinterpret_cast<DBinderServiceInterfaceMock *>(g_interface);
}

extern "C" {
    bool DBinderRemoteListener::StartListener()
    {
        if (g_interface == nullptr) {
            return false;
        }
        return GetDBinderServiceInterfaceMock()->StartListener();
    }

    std::shared_ptr<struct DHandleEntryTxRx> DBinderService::CreateMessage(
        const sptr<DBinderServiceStub> &stub, uint32_t seqNumber, uint32_t pid, uint32_t uid)
    {
        if (g_interface == nullptr) {
            return nullptr;
        }
        return GetDBinderServiceInterfaceMock()->CreateMessage(stub, seqNumber, pid, uid);
    }

    bool DBinderRemoteListener::SendDataToRemote(const std::string &networkId, const struct DHandleEntryTxRx *msg)
    {
        if (g_interface == nullptr) {
            return false;
        }
        return GetDBinderServiceInterfaceMock()->SendDataToRemote(networkId, msg);
    }

    int32_t DBinderSoftbusClient::GetLocalNodeDeviceId(const std::string &pkgName, std::string &devId)
    {
        if (g_interface == nullptr) {
            return SOFTBUS_CLIENT_SUCCESS;
        }
        devId = RANDOM_DEVICEID;

        return GetDBinderServiceInterfaceMock()->GetLocalNodeDeviceId(pkgName, devId);
    }
    std::string IPCObjectProxy::GetSessionName()
    {
        if (GetDBinderServiceInterfaceMock() == nullptr) {
            return "";
        }
        return GetDBinderServiceInterfaceMock()->GetSessionName();
    }
    bool Parcel::WriteUint32(uint32_t value)
    {
        if (GetDBinderServiceInterfaceMock() == nullptr) {
            return false;
        }
        return GetDBinderServiceInterfaceMock()->WriteUint32(value);
    }
    bool Parcel::WriteString(const std::string &value)
    {
        if (GetDBinderServiceInterfaceMock() == nullptr) {
            return false;
        }
        return GetDBinderServiceInterfaceMock()->WriteString(value);
    }
    bool Parcel::WriteUint16(uint16_t value)
    {
        if (GetDBinderServiceInterfaceMock() == nullptr) {
            return false;
        }
        return GetDBinderServiceInterfaceMock()->WriteUint16(value);
    }
    uint64_t Parcel::ReadUint64()
    {
        if (GetDBinderServiceInterfaceMock() == nullptr) {
            return 0;
        }
        return GetDBinderServiceInterfaceMock()->ReadUint64();
    }
    const std::string Parcel::ReadString()
    {
        if (GetDBinderServiceInterfaceMock() == nullptr) {
            return "";
        }
        return GetDBinderServiceInterfaceMock()->ReadString();
    }
    int32_t DBinderSoftbusClient::DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName)
    {
        if (g_interface == nullptr) {
            return 0;
        }
        return GetDBinderServiceInterfaceMock()->DBinderGrantPermission(uid, pid, socketName);
    }
}

class DBinderServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void DBinderServiceTest::SetUpTestCase()
{
}

void DBinderServiceTest::TearDownTestCase()
{
}

void DBinderServiceTest::SetUp()
{
}

void DBinderServiceTest::TearDown()
{
}

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
        return isLoad_;
    }
    bool IsDistributedSystemAbility(int32_t systemAbilityId) override
    {
        return isSystemAbility_;
    }
    bool isSystemAbility_ = true;
    bool isLoad_ = true;
};

/*
 * @tc.name: ProcessOnSessionClosedTest001
 * @tc.desc: Verify the ProcessOnSessionClosed function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ProcessOnSessionClosedTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string networkId = "1234567890";
    EXPECT_EQ(dBinderService->ProcessOnSessionClosed(networkId), true);
}

/*
 * @tc.name: ProcessOnSessionClosedTest002
 * @tc.desc: Verify the ProcessOnSessionClosed function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ProcessOnSessionClosedTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string networkId = "";
    EXPECT_EQ(dBinderService->ProcessOnSessionClosed(networkId), true);
}

/*
 * @tc.name: ProcessOnSessionClosedTest003
 * @tc.desc: Verify the ProcessOnSessionClosed function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ProcessOnSessionClosedTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    auto info = std::make_shared<ThreadLockInfo>();
    info->networkId = "1";
    dBinderService->threadLockInfo_.insert({1, info});

    std::string networkId = "2";
    bool ret = dBinderService->ProcessOnSessionClosed(networkId);
    ASSERT_TRUE(ret);
}

/*
 * @tc.name: ProcessOnSessionClosedTest004
 * @tc.desc: Verify the ProcessOnSessionClosed function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ProcessOnSessionClosedTest004, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<OHOS::ThreadLockInfo> threadLockInfo = std::make_shared<OHOS::ThreadLockInfo>();
    ASSERT_TRUE(threadLockInfo != nullptr);
    uint32_t seqNumber = TEST_SEQ_NUMBER;
    std::string networkId = "networkId";
    dBinderService->AttachThreadLockInfo(seqNumber, networkId, threadLockInfo);
    EXPECT_EQ(dBinderService->ProcessOnSessionClosed(networkId), true);
}

/**
 * @tc.name: FindDBinderStubTest001
 * @tc.desc: Verify the FindDBinderStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, FindDBinderStubTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string service(u"test");
    std::string device = "aaa";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    bool isNew = false;
    sptr<DBinderServiceStub> testDdBinderStub1 = dBinderService->FindOrNewDBinderStub(service, device, binderObject,
        0, 0, isNew);
    EXPECT_TRUE(testDdBinderStub1 != nullptr);
    sptr<DBinderServiceStub> testDdBinderStub2 = dBinderService->FindOrNewDBinderStub(service, device, binderObject,
        0, 0, isNew);
    EXPECT_TRUE(testDdBinderStub2 != nullptr);
    EXPECT_EQ(testDdBinderStub1.GetRefPtr(), testDdBinderStub2.GetRefPtr());

    std::vector<sptr<DBinderServiceStub>> vec = dBinderService->FindDBinderStub(service, device);
    EXPECT_TRUE(vec.size() == 1);
    EXPECT_EQ(testDdBinderStub1.GetRefPtr(), vec[0].GetRefPtr());

    std::u16string service1(u"test1");
    std::string device1 = "bbb";
    vec = dBinderService->FindDBinderStub(service1, device1);
    EXPECT_EQ(vec.size(), 0);

    EXPECT_EQ(dBinderService->DeleteDBinderStub(service1, device1), false);
    EXPECT_EQ(dBinderService->DeleteDBinderStub(service, device), true);
}

/**
 * @tc.name: StartDBinderServiceTest001
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, StartDBinderServiceTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: StartDBinderServiceTest002
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, StartDBinderServiceTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    DBinderService::mainThreadCreated_ = true;
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: StartDBinderServiceTest003
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, StartDBinderServiceTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    DBinderService::mainThreadCreated_ = false;
    dBinderService->remoteListener_ = nullptr;
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: StartDBinderServiceTest004
 * @tc.desc: Verify the StartDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, StartDBinderServiceTest004, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<RpcSystemAbilityCallback> callbackImpl = nullptr;
    DBinderService::mainThreadCreated_ = false;
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    ASSERT_TRUE(dBinderService->remoteListener_ != nullptr);
    bool res = dBinderService->StartDBinderService(callbackImpl);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: StartRemoteListenerTest001
 * @tc.desc: Verify the StartRemoteListener function when remoteListener_ == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, StartRemoteListenerTest001, TestSize.Level1)
{
    DBinderService dBinderService;
    dBinderService.remoteListener_ = nullptr;
    EXPECT_FALSE(dBinderService.StartRemoteListener());
}

/**
 * @tc.name: StartRemoteListenerTest002
 * @tc.desc: Verify the StartRemoteListener function when remoteListener_.StartListener() return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, StartRemoteListenerTest002, TestSize.Level1)
{
    DBinderService dBinderService;
    NiceMock<DBinderServiceInterfaceMock> mock;
    dBinderService.remoteListener_ = nullptr;
    EXPECT_CALL(mock, StartListener).WillOnce(testing::Return(false));

    bool result = dBinderService.StartRemoteListener();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: StartRemoteListenerTest003
 * @tc.desc: Verify the StartRemoteListener function remoteListener_ not nullptr
 *           and remoteListener_.StartListener() return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, StartRemoteListenerTest003, TestSize.Level1)
{
    DBinderService dBinderService;
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    ASSERT_TRUE(dBinderService.remoteListener_ != nullptr);

    bool result = dBinderService.StartRemoteListener();
    ASSERT_TRUE(result);
}

/**
 * @tc.name: ReStartRemoteListenerTest001
 * @tc.desc: Verify the ReStartRemoteListener function when remoteListener_ == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ReStartRemoteListenerTest001, TestSize.Level1)
{
    DBinderService dBinderService;
    dBinderService.remoteListener_ = nullptr;
    bool result = dBinderService.ReStartRemoteListener();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ReStartRemoteListenerTest002
 * @tc.desc: Verify the ReStartRemoteListener function when remoteListener_.StartListener() return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ReStartRemoteListenerTest002, TestSize.Level1)
{
    DBinderService dBinderService;
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, StartListener).WillOnce(testing::Return(false));

    bool result = dBinderService.ReStartRemoteListener();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ReStartRemoteListenerTest003
 * @tc.desc: Verify the ReStartRemoteListener function remoteListener_ not nullptr
 *           and remoteListener_.StartListener() return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ReStartRemoteListenerTest003, TestSize.Level1)
{
    DBinderService dBinderService;
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, StartListener).WillOnce(testing::Return(true));

    bool result = dBinderService.ReStartRemoteListener();
    ASSERT_TRUE(result);
}

/**
 * @tc.name: RegisterRemoteProxyTest001
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, RegisterRemoteProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string serviceName = std::u16string();
    sptr<IRemoteObject> binderObject = nullptr;
    bool res = dBinderService->RegisterRemoteProxy(serviceName, binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: RegisterRemoteProxyTest002
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, RegisterRemoteProxyTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string serviceName = std::u16string();
    int32_t systemAbilityId = 0;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, systemAbilityId), false);
}

/**
 * @tc.name: RegisterRemoteProxyTest003
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, RegisterRemoteProxyTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
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
 * @tc.name: RegisterRemoteProxyTest004
 * @tc.desc: Verify the RegisterRemoteProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, RegisterRemoteProxyTest004, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string serviceName;
    sptr<IRemoteObject> binderObject = nullptr;
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, binderObject), false);
    serviceName = u"testServer";
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, binderObject), false);
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(TEST_OBJECT_HANDLE);
    ASSERT_TRUE(object != nullptr);
    EXPECT_EQ(dBinderService->RegisterRemoteProxy(serviceName, object), true);
}

/**
 * @tc.name: GetRegisterServiceTest001
 * @tc.desc: Verify the GetRegisterService function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, GetRegisterServiceTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
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
HWTEST_F(DBinderServiceTest, OnRemoteMessageTaskTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<struct DHandleEntryTxRx> handleEntryTxRx = nullptr;
    EXPECT_EQ(dBinderService->OnRemoteMessageTask(handleEntryTxRx), false);
    std::shared_ptr<DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    message->head.len = 10;
    message->head.version = 1;
    message->transType = 0;
    message->fromPort = 1;
    message->toPort = 2;
    message->stubIndex = 1;
    message->seqNumber = 1;
    message->binderObject = TEST_BINDER_OBJECT_PTR;
    message->deviceIdInfo.tokenId = 1;
    message->deviceIdInfo.fromDeviceId[0] = 't';
    message->deviceIdInfo.toDeviceId[0] = 't';
    message->stub = 10;
    message->serviceNameLength = 10;
    message->serviceName[0] = 't';
    message->pid = TEST_PID;
    message->uid = TEST_UID;
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
 * @tc.name: QuerySessionObjectTest001
 * @tc.desc: Verify the QuerySessionObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, QuerySessionObjectTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    binder_uintptr_t stub = 0;
    std::shared_ptr<struct SessionInfo> testSession = nullptr;
    testSession = dBinderService->QuerySessionObject(stub);
    EXPECT_EQ(testSession, nullptr);
}

/**
 * @tc.name: QuerySessionObjectTest002
 * @tc.desc: Verify the QuerySessionObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, QuerySessionObjectTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    binder_uintptr_t stub = 0;
    std::shared_ptr<struct SessionInfo> Session = nullptr;
    EXPECT_EQ(dBinderService->AttachSessionObject(Session, stub), true);
    std::shared_ptr<struct SessionInfo> testSession = dBinderService->QuerySessionObject(stub);
    EXPECT_EQ(testSession, Session);
}

/**
 * @tc.name: AttachDeathRecipientTest001
 * @tc.desc: Verify the AttachDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AttachDeathRecipientTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    bool res = dBinderService->AttachDeathRecipient(object, deathRecipient);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: AttachCallbackProxyTest001
 * @tc.desc: Verify the AttachCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AttachCallbackProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = nullptr;
    DBinderServiceStub *dbStub = nullptr;
    bool res = dBinderService->AttachCallbackProxy(object, dbStub);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: DetachProxyObjectTest001
 * @tc.desc: Verify the DetachProxyObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, DetachProxyObjectTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    binder_uintptr_t binderObject = 0;
    bool res = dBinderService->DetachProxyObject(binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ConvertToSecureDeviceIDTest001
 * @tc.desc: Verify the ConvertToSecureDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ConvertToSecureDeviceIDTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceID;
    EXPECT_EQ(dBinderService->ConvertToSecureDeviceID(deviceID), "****");
}

/**
 * @tc.name: ConvertToSecureDeviceIDTest002
 * @tc.desc: Verify the ConvertToSecureDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ConvertToSecureDeviceIDTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->ConvertToSecureDeviceID(deviceID),
    deviceID.substr(0, ENCRYPT_LENGTH) + "****" + deviceID.substr(strlen(deviceID.c_str()) - ENCRYPT_LENGTH));
}

/**
 * @tc.name: GetRemoteTransTypeTest003
 * @tc.desc: Verify the GetRemoteTransType function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, GetRemoteTransTypeTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService->GetRemoteTransType(), IRemoteObject::DATABUS_TYPE);
}

/**
 * @tc.name: StopRemoteListenerTest001
 * @tc.desc: Verify the StopRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, StopRemoteListenerTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<DBinderRemoteListener> testListener = std::make_shared<DBinderRemoteListener>();
    ASSERT_TRUE(testListener != nullptr);
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, StartListener).WillOnce(testing::Return(true));
    EXPECT_EQ(dBinderService->StartRemoteListener(), true);
    dBinderService->StopRemoteListener();
}

/**
 * @tc.name: GetRemoteListenerTest001
 * @tc.desc: Verify the GetRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, GetRemoteListenerTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    dBinderService->remoteListener_ = nullptr;
    std::shared_ptr<DBinderRemoteListener> remoteListener = dBinderService->GetRemoteListener();
    EXPECT_EQ(remoteListener, nullptr);
}

/**
 * @tc.name: GetRemoteListenerTest002
 * @tc.desc: Verify the GetRemoteListener function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, GetRemoteListenerTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<DBinderRemoteListener> testListener = std::make_shared<DBinderRemoteListener>();
    ASSERT_TRUE(testListener != nullptr);
    EXPECT_EQ(dBinderService->StartRemoteListener(), false);
    std::shared_ptr<DBinderRemoteListener> testDbinder = nullptr;
    testDbinder = dBinderService->GetRemoteListener();
}

/**
 * @tc.name: GetSeqNumberTest001
 * @tc.desc: Verify the GetSeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, GetSeqNumberTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->seqNumber_ = 0;
    uint32_t ret = dBinderService->GetSeqNumber();
    EXPECT_EQ(ret, dBinderService->seqNumber_++);
}

/**
 * @tc.name: GetSeqNumberTest002
 * @tc.desc: Verify the GetSeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, GetSeqNumberTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->seqNumber_ = std::numeric_limits<uint32_t>::max();
    uint32_t ret = dBinderService->GetSeqNumber();
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: IsDeviceIdIllegalTest001
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsDeviceIdIllegalTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceID = "";
    bool res = dBinderService->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsDeviceIdIllegalTest002
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsDeviceIdIllegalTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bool res = dBinderService->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsDeviceIdIllegalTest003
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsDeviceIdIllegalTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bool res = dBinderService->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: AddStubByTagTest001
 * @tc.desc: Verify the AddStubByTag function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AddStubByTagTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);
    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());

    binder_uintptr_t stubTag = dBinderService->stubTagNum_++;
    auto result = dBinderService->mapDBinderStubRegisters_.insert({stubTag, binderObjectPtr});
    ASSERT_TRUE(result.second);

    binder_uintptr_t stubTag2 = dBinderService->AddStubByTag(binderObjectPtr);
    EXPECT_EQ(stubTag2, stubTag);

    dBinderService->stubTagNum_ = 1;
    dBinderService->mapDBinderStubRegisters_.clear();
}

/**
 * @tc.name: AddStubByTagTest002
 * @tc.desc: Verify the AddStubByTag function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AddStubByTagTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);
    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());

    binder_uintptr_t stubTag = dBinderService->AddStubByTag(binderObjectPtr);
    EXPECT_GT(stubTag, 0);

    dBinderService->stubTagNum_ = 1;
    dBinderService->mapDBinderStubRegisters_.clear();
}

/**
 * @tc.name: AddStubByTagTest003
 * @tc.desc: Verify the AddStubByTag function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AddStubByTagTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_NE(stub, nullptr);
    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    binder_uintptr_t stubTag = dBinderService->AddStubByTag(binderObjectPtr);
    EXPECT_GT(stubTag, 0);

    sptr<DBinderServiceStub> stub2 = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_NE(stub2, nullptr);
    binder_uintptr_t binderObject2Ptr = reinterpret_cast<binder_uintptr_t>(stub2.GetRefPtr());
    auto result = dBinderService->mapDBinderStubRegisters_.insert_or_assign(stubTag, binderObject2Ptr);
    EXPECT_FALSE(result.second);

    dBinderService->stubTagNum_--;
    binder_uintptr_t stubTag2 = dBinderService->AddStubByTag(binderObjectPtr);
    EXPECT_EQ(stubTag2, 0);

    dBinderService->stubTagNum_ = 1;
    dBinderService->mapDBinderStubRegisters_.clear();
}

/**
 * @tc.name: QueryStubPtrTest001
 * @tc.desc: Verify the QueryStubPtr function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, QueryStubPtrTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_NE(stub, nullptr);
    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());

    binder_uintptr_t stubTag = dBinderService->AddStubByTag(binderObjectPtr);
    EXPECT_GT(stubTag, 0);

    binder_uintptr_t stubPtr = dBinderService->QueryStubPtr(stubTag);
    EXPECT_EQ(stubPtr, binderObjectPtr);

    dBinderService->stubTagNum_ = 1;
    dBinderService->mapDBinderStubRegisters_.clear();
}

/**
 * @tc.name: QueryStubPtrTest002
 * @tc.desc: Verify the QueryStubPtr function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, QueryStubPtrTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    binder_uintptr_t binderObject = 0;
    binder_uintptr_t stubPtr = dBinderService->QueryStubPtr(binderObject);
    EXPECT_EQ(stubPtr, 0);
}

/**
 * @tc.name: CheckBinderObjectTest001
 * @tc.desc: Verify the CheckBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckBinderObjectTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<DBinderServiceStub> stub = nullptr;
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    bool res = dBinderService->CheckBinderObject(stub, binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: CheckBinderObjectTest002
 * @tc.desc: Verify the CheckBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckBinderObjectTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);
    bool res = dBinderService->CheckBinderObject(stub, binderObject);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: CheckBinderObjectTest003
 * @tc.desc: Verify the CheckBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckBinderObjectTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);

    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    bool ret = dBinderService->CheckBinderObject(stub, binderObjectPtr);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: HasDBinderStubTest001
 * @tc.desc: Verify the HasDBinderStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, HasDBinderStubTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->DBinderStubRegisted_.clear();

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);
    dBinderService->DBinderStubRegisted_.push_back(stub);

    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    bool ret = dBinderService->HasDBinderStub(binderObjectPtr);
    ASSERT_TRUE(ret);

    dBinderService->DBinderStubRegisted_.clear();
}

/**
 * @tc.name: HasDBinderStubTest002
 * @tc.desc: Verify the HasDBinderStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, HasDBinderStubTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->DBinderStubRegisted_.clear();

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);

    binderObject = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    stub->binderObject_ = binderObject;

    dBinderService->DBinderStubRegisted_.push_back(stub);
    bool ret = dBinderService->HasDBinderStub(binderObject);
    ASSERT_TRUE(ret);

    dBinderService->DBinderStubRegisted_.clear();
}

/**
 * @tc.name: IsSameStubObjectTest001
 * @tc.desc: Verify the IsSameStubObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsSameStubObjectTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<DBinderServiceStub> stub = nullptr;
    std::u16string service = std::u16string();
    const std::string device = "";
    bool res = dBinderService->IsSameStubObject(stub, service, device);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: IsSameStubObjectTest002
 * @tc.desc: Verify the IsSameStubObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsSameStubObjectTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string serviceName = u"test";
    std::string deviceID = "001";
    binder_uintptr_t binderObject = 1;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);
    std::u16string service(u"test");
    bool res = dBinderService->IsSameStubObject(stub, service, deviceID);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: MakeRemoteBinderTest001
 * @tc.desc: Verify the MakeRemoteBinder function when error serviceName and deviceID
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, MakeRemoteBinderTest001, TestSize.Level1)
{
    DBinderService dBinderService;
    sptr<DBinderServiceStub> result = dBinderService.MakeRemoteBinder(
        ZERO_SERVICENAME, ZERO_DEVICEID, BINDEROBJECT, PID, UID);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: MakeRemoteBinderTest002
 * @tc.desc: Verify the MakeRemoteBinder function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, MakeRemoteBinderTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string serviceName;
    std::string deviceID("001");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    uint32_t pid = 0;
    uint32_t uid = 0;
    EXPECT_EQ(dBinderService->MakeRemoteBinder(serviceName, deviceID, binderObject, pid, uid), nullptr);
}

/**
 * @tc.name: MakeRemoteBinderTest003
 * @tc.desc: Verify the MakeRemoteBinder function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, MakeRemoteBinderTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string serviceName;
    std::string deviceID("001");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    uint32_t pid = TEST_PID;
    uint32_t uid = TEST_UID;
    EXPECT_EQ(dBinderService->MakeRemoteBinder(serviceName, deviceID, binderObject, pid, uid), nullptr);
}

/**
 * @tc.name: MakeRemoteBinderTest004
 * @tc.desc: Verify the MakeRemoteBinder function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, MakeRemoteBinderTest004, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string serviceName = u"abcd";
    std::string deviceID("001");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    uint32_t pid = TEST_PID;
    uint32_t uid = TEST_UID;
    sptr<DBinderServiceStub> ret = dBinderService->MakeRemoteBinder(serviceName, deviceID, binderObject, pid, uid);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: CheckDeviceIDsInvalidTest001
 * @tc.desc: Verify the CheckDeviceIDsInvalid function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckDeviceIDsInvalidTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    std::string deviceID;
    std::string localDevID;
    bool ret = dBinderService->CheckDeviceIDsInvalid(deviceID, localDevID);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: CheckDeviceIDsInvalidTest002
 * @tc.desc: Verify the CheckDeviceIDsInvalid function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckDeviceIDsInvalidTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    std::string deviceID(DEVICEID_LENGTH - 1, 'a');
    std::string localDevID(DEVICEID_LENGTH - 1, 'a');
    bool ret = dBinderService->CheckDeviceIDsInvalid(deviceID, localDevID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CopyDeviceIDsToMessageTest001
 * @tc.desc: Verify the CopyDeviceIDsToMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CopyDeviceIDsToMessageTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    auto message = std::make_shared<struct DHandleEntryTxRx>();

    std::string localDevID(DEVICEID_LENGTH + 1, 'a');
    std::string deviceID(DEVICEID_LENGTH + 1, 'a');
    bool ret = dBinderService->CopyDeviceIDsToMessage(message, localDevID, deviceID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CopyDeviceIDsToMessageTest002
 * @tc.desc: Verify the CopyDeviceIDsToMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CopyDeviceIDsToMessageTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    auto message = std::make_shared<struct DHandleEntryTxRx>();

    std::string localDevID(DEVICEID_LENGTH - 1, 'a');
    std::string deviceID(DEVICEID_LENGTH - 1, 'a');
    bool ret = dBinderService->CopyDeviceIDsToMessage(message, localDevID, deviceID);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SendEntryToRemoteTest001
 * @tc.desc: Verify the SendEntryToRemote function when deviceID is error
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, SendEntryToRemoteTest001, TestSize.Level1)
{
    DBinderService dBinderService;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(
        RANDOM_SERVICENAME, ZERO_DEVICEID, BINDER_OBJECT);
    bool result = dBinderService.SendEntryToRemote(dBinderServiceStub, PID, PID, PID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SendEntryToRemoteTest002
 * @tc.desc: Verify the SendEntryToRemote function when dBinderService.remoteListener_ == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, SendEntryToRemoteTest002, TestSize.Level1)
{
    DBinderService dBinderService;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(
        RANDOM_SERVICENAME, RANDOM_DEVICEID, BINDER_OBJECT);
    NiceMock<DBinderServiceInterfaceMock> mock;
    dBinderService.remoteListener_ = nullptr;
    EXPECT_CALL(mock, GetLocalNodeDeviceId).WillOnce(testing::Return(SOFTBUS_CLIENT_SUCCESS));
    EXPECT_CALL(mock, SendDataToRemote).WillRepeatedly(testing::Return(false));

    bool result = dBinderService.SendEntryToRemote(dBinderServiceStub, PID, PID, PID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SendEntryToRemoteTest003
 * @tc.desc: Verify the SendEntryToRemote function when remoteListener_.SendDataToRemote == false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, SendEntryToRemoteTest003, TestSize.Level1)
{
    DBinderService dBinderService;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(
        RANDOM_SERVICENAME, RANDOM_DEVICEID, BINDER_OBJECT);
    NiceMock<DBinderServiceInterfaceMock> mock;
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_CALL(mock, SendDataToRemote).WillOnce(testing::Return(false));
    std::shared_ptr<struct DHandleEntryTxRx> entry = std::make_shared<struct DHandleEntryTxRx>();
    ASSERT_NE(entry, nullptr);
    EXPECT_CALL(mock, CreateMessage(_, _, _, _)).WillOnce(testing::Return(entry));
    EXPECT_CALL(mock, GetLocalNodeDeviceId).WillOnce(testing::Return(SOFTBUS_CLIENT_SUCCESS));

    bool result = dBinderService.SendEntryToRemote(dBinderServiceStub, PID, PID, PID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SendEntryToRemoteTest004
 * @tc.desc: Verify the SendEntryToRemote function can work
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, SendEntryToRemoteTest004, TestSize.Level1)
{
    DBinderService dBinderService;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(
        RANDOM_SERVICENAME, RANDOM_DEVICEID, BINDER_OBJECT);
    NiceMock<DBinderServiceInterfaceMock> mock;
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_CALL(mock, SendDataToRemote).WillOnce(testing::Return(true));
    std::shared_ptr<struct DHandleEntryTxRx> entry = std::make_shared<struct DHandleEntryTxRx>();
    ASSERT_NE(entry, nullptr);
    EXPECT_CALL(mock, CreateMessage(_, _, _, _)).WillOnce(testing::Return(entry));
    EXPECT_CALL(mock, GetLocalNodeDeviceId).WillOnce(testing::Return(SOFTBUS_CLIENT_SUCCESS));

    bool result = dBinderService.SendEntryToRemote(dBinderServiceStub, PID, PID, PID);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: SendEntryToRemoteTest005
 * @tc.desc: Verify the SendEntryToRemote function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, SendEntryToRemoteTest005, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    NiceMock<DBinderServiceInterfaceMock> mock;
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_CALL(mock, SendDataToRemote).WillOnce(testing::Return(false));
    std::shared_ptr<struct DHandleEntryTxRx> entry = std::make_shared<struct DHandleEntryTxRx>();
    ASSERT_NE(entry, nullptr);
    EXPECT_CALL(mock, CreateMessage).WillOnce(testing::Return(entry));
    EXPECT_CALL(mock, GetLocalNodeDeviceId).WillOnce(testing::Return(SOFTBUS_CLIENT_SUCCESS));

    sptr<DBinderServiceStub> dBinderServiceStub =
        sptr<DBinderServiceStub>::MakeSptr(RANDOM_SERVICENAME, RANDOM_DEVICEID, BINDER_OBJECT);
    ASSERT_NE(dBinderServiceStub, nullptr);
    uint32_t seqNumber = 1;
    uint32_t pid = PID;
    uint32_t uid = UID;
    bool result = dBinderService->SendEntryToRemote(dBinderServiceStub, seqNumber, pid, uid);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PopLoadSaItemTest001
 * @tc.desc: Verify the PopLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, PopLoadSaItemTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string srcNetworkId;
    int32_t systemAbilityId = 1;
    EXPECT_EQ(dBinderService->PopLoadSaItem(srcNetworkId, systemAbilityId), nullptr);

    srcNetworkId = "t";
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    (void)memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->stubIndex = systemAbilityId;
    message->deviceIdInfo.fromDeviceId[0] = 't';
    dBinderService->dbinderCallback_ = std::make_shared<TestRpcSystemAbilityCallback>();
    ASSERT_TRUE(dBinderService->dbinderCallback_ != nullptr);
    dBinderService->OnRemoteInvokerMessage(message);
    std::shared_ptr<DHandleEntryTxRx> dHandleEntryTxRx = dBinderService->PopLoadSaItem(srcNetworkId, systemAbilityId);
    EXPECT_TRUE(dHandleEntryTxRx != nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    dBinderService->LoadSystemAbilityComplete("test", 2, remoteObject);

    /* verify running into the remoteObject is null branch */
    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = MockDBinderRemoteListener::SendBytes;
    PeerSocketInfo info;
    info.networkId = message->deviceIdInfo.fromDeviceId;
    int32_t socket = 1001;
    DBinderRemoteListener::ServerOnBind(socket, info);

    std::shared_ptr<MockDBinderRemoteListener> mockListener = std::make_shared<MockDBinderRemoteListener>();
    dBinderService->remoteListener_ = std::static_pointer_cast<DBinderRemoteListener>(mockListener);
    EXPECT_TRUE(dBinderService->remoteListener_ != nullptr);
    dBinderService->LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject);
    EXPECT_EQ(MockDBinderRemoteListener::GetInstance().GetResult(), SA_NOT_FOUND);

    /* verify running into the add death recipient fail branch */
    dBinderService->loadSaReply_.push_back(message);
    sptr<MockIPCObjectProxy> remoteObject1 = sptr<MockIPCObjectProxy>::MakeSptr();
    EXPECT_TRUE(remoteObject1 != nullptr);
    EXPECT_CALL(*remoteObject1, AddDeathRecipient(testing::_)).WillRepeatedly(testing::Return(false));
    dBinderService->LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject1);
    EXPECT_EQ(MockDBinderRemoteListener::GetInstance().GetResult(), SA_NOT_FOUND);
    dBinderService->remoteListener_ = nullptr;
    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = nullptr;
}

/**
 * @tc.name: PopLoadSaItemTest002
 * @tc.desc: Verify the PopLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, PopLoadSaItemTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    std::string srcNetworkId = "t";
    int32_t systemAbilityId = 1;
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    (void)memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->stubIndex = systemAbilityId;
    message->deviceIdInfo.fromDeviceId[0] = 't';
    message->binderObject = 0;
    dBinderService->loadSaReply_.push_back(message);

    sptr<IRemoteObject> remoteObject1 = new (std::nothrow) IPCObjectProxy(1);
    ASSERT_TRUE(remoteObject1 != nullptr);
    dBinderService->LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject1);
}

/**
 * @tc.name: PopLoadSaItemTest003
 * @tc.desc: Verify the PopLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, PopLoadSaItemTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    std::string srcNetworkId = "t";
    int32_t systemAbilityId = 1;
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    (void)memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->binderObject  = systemAbilityId;
    message->deviceIdInfo.fromDeviceId[0] = 't';
    message->transType = IRemoteObject::DATABUS_TYPE + 1;
    dBinderService->loadSaReply_.push_back(message);

    sptr<IRemoteObject> remoteObject1 = new (std::nothrow) IPCObjectProxy(1);
    EXPECT_TRUE(remoteObject1 != nullptr);
    dBinderService->proxyObject_.clear();
    bool ret = dBinderService->AttachProxyObject(remoteObject1, message->binderObject);
    EXPECT_TRUE(ret);

    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = MockDBinderRemoteListener::SendBytes;
    PeerSocketInfo info;
    info.networkId = message->deviceIdInfo.fromDeviceId;
    int32_t socket = 1001;
    DBinderRemoteListener::ServerOnBind(socket, info);

    /* verify running into the transType invalid branch */
    std::shared_ptr<MockDBinderRemoteListener> mockListener = std::make_shared<MockDBinderRemoteListener>();
    dBinderService->remoteListener_ = std::static_pointer_cast<DBinderRemoteListener>(mockListener);
    EXPECT_TRUE(dBinderService->remoteListener_ != nullptr);
    dBinderService->LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject1);
    EXPECT_EQ(MockDBinderRemoteListener::GetInstance().GetResult(), SA_INVOKE_FAILED);
    dBinderService->remoteListener_ = nullptr;
    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = nullptr;
    dBinderService->DetachProxyObject(message->binderObject);
}

/**
 * @tc.name: PopLoadSaItemTest004
 * @tc.desc: Verify the PopLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, PopLoadSaItemTest004, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    std::string srcNetworkId = "t";
    int32_t systemAbilityId = 1;
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    (void)memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->binderObject  = systemAbilityId;
    message->deviceIdInfo.fromDeviceId[0] = 't';
    message->transType = IRemoteObject::DATABUS_TYPE;
    dBinderService->loadSaReply_.push_back(message);

    /* verify running into the OnRemoteInvokerDataBusMessage fail branch */
    sptr<MockIPCObjectProxy> remoteObject1 = sptr<MockIPCObjectProxy>::MakeSptr();
    ASSERT_TRUE(remoteObject1 != nullptr);
    bool ret = dBinderService->AttachProxyObject(remoteObject1, message->binderObject);
    ASSERT_TRUE(ret);

    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = MockDBinderRemoteListener::SendBytes;
    PeerSocketInfo info;
    info.networkId = message->deviceIdInfo.fromDeviceId;;
    int32_t socket = 1001;
    DBinderRemoteListener::ServerOnBind(socket, info);

    std::shared_ptr<MockDBinderRemoteListener> mockListener = std::make_shared<MockDBinderRemoteListener>();
    dBinderService->remoteListener_ = std::static_pointer_cast<DBinderRemoteListener>(mockListener);
    ASSERT_TRUE(dBinderService->remoteListener_ != nullptr);
    dBinderService->LoadSystemAbilityComplete(srcNetworkId, systemAbilityId, remoteObject1);
    EXPECT_EQ(MockDBinderRemoteListener::GetInstance().GetResult(), SESSION_NAME_NOT_FOUND);
    dBinderService->remoteListener_ = nullptr;
    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = nullptr;
    ret = dBinderService->DetachProxyObject(message->binderObject);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: SendReplyMessageToRemoteTest001
 * @tc.desc: Verify the SendReplyMessageToRemote function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, SendReplyMessageToRemoteTest001, TestSize.Level1)
{
    uint32_t dBinderCode = 4;
    uint32_t reason = 0;
    std::shared_ptr<DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    EXPECT_TRUE(replyMessage != nullptr);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    ASSERT_TRUE(dBinderService->remoteListener_ != nullptr);
    dBinderService->SendReplyMessageToRemote(dBinderCode, reason, replyMessage);
    dBinderCode = 1;
    dBinderService->SendReplyMessageToRemote(dBinderCode, reason, replyMessage);
    DBinderService *temp = DBinderService::GetInstance();
    ASSERT_TRUE(temp != nullptr);
    DBinderService::instance_ = temp;
    dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService, DBinderService::instance_);
}

/**
 * @tc.name: CheckSystemAbilityIdTest001
 * @tc.desc: Verify the CheckSystemAbilityId function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckSystemAbilityIdTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    int32_t systemAbilityId = TEST_SYSTEM_ABILITY_ID;
    bool res = dBinderService->CheckSystemAbilityId(systemAbilityId);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: AllocFreeSocketPortTest001
 * @tc.desc: Verify the AllocFreeSocketPort function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AllocFreeSocketPortTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    uint16_t ret = dBinderService->AllocFreeSocketPort();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: IsSameLoadSaItemTest001
 * @tc.desc: Verify the IsSameLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsSameLoadSaItemTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string srcNetworkId = "aaaaaaaaaaaaaa";
    int32_t systemAbilityId = TEST_SYSTEM_ABILITY_ID;
    std::shared_ptr<DHandleEntryTxRx> loadSaItem = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(loadSaItem != nullptr);
    loadSaItem->binderObject  = TEST_SYSTEM_ABILITY_ID;
    strcpy_s(loadSaItem->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, "aaaaaaaaaaaaaa");
    bool res = dBinderService->IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsSameLoadSaItemTest002
 * @tc.desc: Verify the IsSameLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsSameLoadSaItemTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string srcNetworkId = "bbbbbbb";
    int32_t systemAbilityId = TEST_SYSTEM_ABILITY_ID;
    std::shared_ptr<DHandleEntryTxRx> loadSaItem = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(loadSaItem != nullptr);
    loadSaItem->stubIndex = TEST_STUB_INDEX;
    strcpy_s(loadSaItem->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, "aaaaaaaaaaaaaa");
    bool res = dBinderService->IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: IsSameLoadSaItemTest003
 * @tc.desc: Verify the IsSameLoadSaItem function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsSameLoadSaItemTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string srcNetworkId = "aaaaaaaaaaaaaa";
    int32_t systemAbilityId = TEST_SYSTEM_ABILITY_ID;
    std::shared_ptr<DHandleEntryTxRx> loadSaItem = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(loadSaItem != nullptr);
    loadSaItem->stubIndex = TEST_STUB_INDEX;
    strcpy_s(loadSaItem->deviceIdInfo.fromDeviceId, DEVICEID_LENGTH, "aaaaaaaaaaaaaa");
    bool res = dBinderService->IsSameLoadSaItem(srcNetworkId, systemAbilityId, loadSaItem);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: OnRemoteInvokerMessageTest001
 * @tc.desc: Verify the OnRemoteInvokerMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerMessageTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<MockDBinderRemoteListener> mockListener = std::make_shared<MockDBinderRemoteListener>();
    dBinderService->remoteListener_ = std::static_pointer_cast<DBinderRemoteListener>(mockListener);
    ASSERT_TRUE(dBinderService->remoteListener_ != nullptr);

    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    (void)memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->stubIndex = DBinderService::FIRST_SYS_ABILITY_ID - 1;
    message->binderObject = DBinderService::FIRST_SYS_ABILITY_ID - 1;
    message->deviceIdInfo.fromDeviceId[0] = 't';

    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = MockDBinderRemoteListener::SendBytes;
    PeerSocketInfo info;
    info.networkId = message->deviceIdInfo.fromDeviceId;
    int32_t socket = 1001;
    DBinderRemoteListener::ServerOnBind(socket, info);

    bool ret = dBinderService->OnRemoteInvokerMessage(message);
    EXPECT_FALSE(ret);
    EXPECT_EQ(MockDBinderRemoteListener::GetInstance().GetResult(), SAID_INVALID_ERR);
    dBinderService->remoteListener_ = nullptr;
    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = nullptr;
}

/**
 * @tc.name: OnRemoteInvokerMessageTest002
 * @tc.desc: Verify the OnRemoteInvokerMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerMessageTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    (void)memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->stubIndex = TEST_STUB_INDEX;
    dBinderService->dbinderCallback_ = std::make_shared<TestRpcSystemAbilityCallback>();
    ASSERT_TRUE(dBinderService->dbinderCallback_ != nullptr);
    bool res = dBinderService->OnRemoteInvokerMessage(message);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: OnRemoteInvokerMessageTest003
 * @tc.desc: Verify the OnRemoteInvokerMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerMessageTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<MockDBinderRemoteListener> mockListener = std::make_shared<MockDBinderRemoteListener>();
    dBinderService->remoteListener_ = std::static_pointer_cast<DBinderRemoteListener>(mockListener);
    ASSERT_TRUE(dBinderService->remoteListener_ != nullptr);

    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    (void)memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->stubIndex = DBinderService::FIRST_SYS_ABILITY_ID;
    message->binderObject = DBinderService::FIRST_SYS_ABILITY_ID;
    message->deviceIdInfo.fromDeviceId[0] = 't';

    std::shared_ptr<TestRpcSystemAbilityCallback> cb = std::make_shared<TestRpcSystemAbilityCallback>();
    cb->isSystemAbility_ = false;
    dBinderService->dbinderCallback_ = cb;

    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = MockDBinderRemoteListener::SendBytes;
    PeerSocketInfo info;
    info.networkId = message->deviceIdInfo.fromDeviceId;
    int32_t socket = 1001;
    DBinderRemoteListener::ServerOnBind(socket, info);

    bool ret = dBinderService->OnRemoteInvokerMessage(message);
    EXPECT_FALSE(ret);
    EXPECT_EQ(MockDBinderRemoteListener::GetInstance().GetResult(), SA_NOT_DISTRUBUTED_ERR);
    dBinderService->remoteListener_ = nullptr;
    cb->isSystemAbility_ = true;
    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = nullptr;
}

/**
 * @tc.name: OnRemoteInvokerMessageTest004
 * @tc.desc: Verify the OnRemoteInvokerMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerMessageTest004, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<MockDBinderRemoteListener> mockListener = std::make_shared<MockDBinderRemoteListener>();
    dBinderService->remoteListener_ = std::static_pointer_cast<DBinderRemoteListener>(mockListener);
    ASSERT_TRUE(dBinderService->remoteListener_ != nullptr);

    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(message != nullptr);
    (void)memset_s(message.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    message->stubIndex = DBinderService::FIRST_SYS_ABILITY_ID;
    message->binderObject = DBinderService::FIRST_SYS_ABILITY_ID;
    message->deviceIdInfo.fromDeviceId[0] = 't';

    std::shared_ptr<TestRpcSystemAbilityCallback> cb = std::make_shared<TestRpcSystemAbilityCallback>();
    cb->isLoad_ = false;
    dBinderService->dbinderCallback_ = cb;

    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = MockDBinderRemoteListener::SendBytes;
    PeerSocketInfo info;
    info.networkId = message->deviceIdInfo.fromDeviceId;
    int32_t socket = 1001;
    DBinderRemoteListener::ServerOnBind(socket, info);

    bool ret = dBinderService->OnRemoteInvokerMessage(message);
    EXPECT_FALSE(ret);
    EXPECT_EQ(MockDBinderRemoteListener::GetInstance().GetResult(), SA_NOT_AVAILABLE);
    dBinderService->remoteListener_ = nullptr;
    cb->isLoad_ = true;
    DBinderSoftbusClient::GetInstance().sendBytesFunc_ = nullptr;
}

/**
 * @tc.name: GetDatabusNameByProxyTest001
 * @tc.desc: Verify the GetDatabusNameByProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, GetDatabusNameByProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    IPCObjectProxy* proxy = nullptr;
    std::string res = dBinderService->GetDatabusNameByProxy(proxy);
    EXPECT_EQ(res, "");
    IPCObjectProxy object(TEST_OBJECT_HANDLE);
    res = dBinderService->GetDatabusNameByProxy(&object);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: InvokerRemoteDBinderTest001
 * @tc.desc: Verify the InvokerRemoteDBinder function when dBinderServiceStub is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, InvokerRemoteDBinderTest001, TestSize.Level1)
{
    DBinderService dBinderService;
    int32_t result = dBinderService.InvokerRemoteDBinder(nullptr, PID, PID, PID);
    EXPECT_EQ(result, DBinderErrorCode::STUB_INVALID);
}

/**
 * @tc.name: InvokerRemoteDBinderTest002
 * @tc.desc: Verify the InvokerRemoteDBinder function when dBinderServiceStub.Deviceid is error
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, InvokerRemoteDBinderTest002, TestSize.Level1)
{
    DBinderService dBinderService;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(
        RANDOM_SERVICENAME, ZERO_DEVICEID, BINDER_OBJECT);
    int32_t result = dBinderService.InvokerRemoteDBinder(dBinderServiceStub, PID, PID, PID);
    EXPECT_EQ(result, DBinderErrorCode::SEND_MESSAGE_FAILED);
}

/**
 * @tc.name: InvokerRemoteDBinderTest003
 * @tc.desc: Verify the InvokerRemoteDBinder function when dBinderService.AttachThreadLockInfo is error
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, InvokerRemoteDBinderTest003, TestSize.Level1)
{
    DBinderService dBinderService;
    sptr<DBinderServiceStub> dBinderServiceStub = new DBinderServiceStub(
        RANDOM_SERVICENAME, RANDOM_DEVICEID, BINDER_OBJECT);
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = std::make_shared<struct ThreadLockInfo>();
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    dBinderService.AttachThreadLockInfo(PID, RANDOM_DEVICEID, threadLockInfo);

    int32_t result = dBinderService.InvokerRemoteDBinder(dBinderServiceStub, PID, PID, PID);
    EXPECT_EQ(result, DBinderErrorCode::MAKE_THREADLOCK_FAILED);
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest001
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function when WriteUint16 function false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerDataBusMessageTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceId(RANDOM_DEVICEID);
    int pid = PID;
    int uid = UID;
    uint32_t tokenId = TOKEN_ID;
    sptr<IPCObjectProxy> proxy = new IPCObjectProxy(REGISTRY_HANDLE, DESCRIPTOR_TEST, IRemoteObject::IF_PROT_BINDER);

    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    NiceMock<DBinderServiceInterfaceMock> mock;

    EXPECT_CALL(mock, GetSessionName).WillOnce(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint16).WillRepeatedly(testing::Return(false));

    auto result = dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, deviceId, pid, uid, tokenId);
    EXPECT_EQ(result, DBinderErrorCode::WRITE_PARCEL_FAILED);
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest002
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function when WriteString function false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerDataBusMessageTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceId(RANDOM_DEVICEID);
    sptr<IPCObjectProxy> proxy = new IPCObjectProxy(REGISTRY_HANDLE, DESCRIPTOR_TEST, IRemoteObject::IF_PROT_BINDER);

    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    NiceMock<DBinderServiceInterfaceMock> mock;

    EXPECT_CALL(mock, GetSessionName).WillOnce(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint16).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(false));

    auto result = dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, deviceId, PID, UID, TOKEN_ID);
    EXPECT_EQ(result, DBinderErrorCode::WRITE_PARCEL_FAILED);
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest003
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function when WriteUint32 function false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerDataBusMessageTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceId(RANDOM_DEVICEID);
    sptr<IPCObjectProxy> proxy = new IPCObjectProxy(REGISTRY_HANDLE, DESCRIPTOR_TEST, IRemoteObject::IF_PROT_BINDER);

    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    NiceMock<DBinderServiceInterfaceMock> mock;

    EXPECT_CALL(mock, GetSessionName).WillOnce(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint16).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteUint32).WillRepeatedly(testing::Return(false));

    auto result = dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, deviceId, PID, UID, TOKEN_ID);
    EXPECT_EQ(result, DBinderErrorCode::WRITE_PARCEL_FAILED);
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest004
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function when IsObjectDead function true
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerDataBusMessageTest004, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceId(RANDOM_DEVICEID);
    sptr<IPCObjectProxy> proxy = new IPCObjectProxy(REGISTRY_HANDLE, DESCRIPTOR_TEST, IRemoteObject::IF_PROT_BINDER);

    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    NiceMock<DBinderServiceInterfaceMock> mock;
    sptr<MockIPCObjectProxy> objectMock = sptr<MockIPCObjectProxy>::MakeSptr();

    EXPECT_CALL(mock, GetSessionName).WillOnce(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint16).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteUint32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*objectMock, IsObjectDead).WillRepeatedly(testing::Return(true));

    auto result = dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, deviceId, PID, UID, TOKEN_ID);
    EXPECT_EQ(result, DBinderErrorCode::INVOKE_STUB_THREAD_FAILED);
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest005
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function when ReadUint64 function 0
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerDataBusMessageTest005, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceId(RANDOM_DEVICEID);
    sptr<IPCObjectProxy> proxy = new IPCObjectProxy(REGISTRY_HANDLE, DESCRIPTOR_TEST, IRemoteObject::IF_PROT_BINDER);

    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    NiceMock<DBinderServiceInterfaceMock> mock;
    sptr<MockIPCObjectProxy> objectMock = sptr<MockIPCObjectProxy>::MakeSptr();
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, GetSessionName).WillOnce(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint16).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteUint32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*objectMock, IsObjectDead).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(*invoker, SendRequest).WillRepeatedly(testing::Return(ERR_NONE));
    EXPECT_CALL(mock, ReadUint64).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(mock, ReadString).WillRepeatedly(testing::Return(SERVICE_NAME_TEST));

    auto result = dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, deviceId, PID, UID, TOKEN_ID);
    EXPECT_EQ(result, DBinderErrorCode::SESSION_NAME_INVALID);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest006
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function when 0
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerDataBusMessageTest006, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceId(RANDOM_DEVICEID);
    sptr<IPCObjectProxy> proxy = new IPCObjectProxy(REGISTRY_HANDLE, DESCRIPTOR_TEST, IRemoteObject::IF_PROT_BINDER);

    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    NiceMock<DBinderServiceInterfaceMock> mock;
    sptr<MockIPCObjectProxy> objectMock = sptr<MockIPCObjectProxy>::MakeSptr();
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, GetSessionName).WillOnce(testing::Return(SESSION_NAME_TEST));
    EXPECT_CALL(mock, WriteUint16).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteUint32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*objectMock, IsObjectDead).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(*invoker, SendRequest).WillRepeatedly(testing::Return(ERR_NONE));
    EXPECT_CALL(mock, ReadUint64).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, ReadString).WillRepeatedly(testing::Return(SERVICE_NAME_TEST));

    auto result = dBinderService->OnRemoteInvokerDataBusMessage(proxy, replyMessage, deviceId, PID, UID, TOKEN_ID);
    EXPECT_EQ(result, 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest007
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerDataBusMessageTest007, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    IPCObjectProxy* proxy = nullptr;
    std::string remoteDeviceId;
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(replyMessage != nullptr);
    (void)memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    EXPECT_EQ(dBinderService->OnRemoteInvokerDataBusMessage(
        proxy, replyMessage, remoteDeviceId, pid, uid, tokenId), DBinderErrorCode::DEVICEID_INVALID);
}

/**
 * @tc.name: OnRemoteInvokerDataBusMessageTest008
 * @tc.desc: Verify the OnRemoteInvokerDataBusMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, OnRemoteInvokerDataBusMessageTest008, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string remoteDeviceId("test");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    IPCObjectProxy objectProxy(0);
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(replyMessage != nullptr);
    (void)memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    EXPECT_EQ(dBinderService->OnRemoteInvokerDataBusMessage(
        &objectProxy, replyMessage, remoteDeviceId, pid, uid, tokenId), DBinderErrorCode::SESSION_NAME_NOT_FOUND);
}

/**
 * @tc.name: DeleteDBinderStubTest001
 * @tc.desc: Verify the DeleteDBinderStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, DeleteDBinderStubTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    dBinderService->DBinderStubRegisted_.clear();
    dBinderService->mapDBinderStubRegisters_.clear();

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);
    dBinderService->DBinderStubRegisted_.push_back(stub);

    const std::u16string serviceName2 = u"abcd";
    const std::string deviceID2 = "bcde";
    binder_uintptr_t binderObject2 = TEST_BINDER_OBJECT_PTR + 1;
    sptr<DBinderServiceStub> stub2 = new (std::nothrow) DBinderServiceStub(serviceName2, deviceID2, binderObject2);
    ASSERT_TRUE(stub2 != nullptr);

    binder_uintptr_t binderPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    dBinderService->mapDBinderStubRegisters_.insert({binderPtr, binderPtr});

    binder_uintptr_t binderPtr2 = reinterpret_cast<binder_uintptr_t>(stub2.GetRefPtr());
    dBinderService->mapDBinderStubRegisters_.insert({binderPtr2, binderPtr2});
    bool ret = dBinderService->DeleteDBinderStub(serviceName, deviceID);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: DeleteDBinderStubTest002
 * @tc.desc: Verify the DeleteDBinderStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, DeleteDBinderStubTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    dBinderService->DBinderStubRegisted_.clear();
    dBinderService->mapDBinderStubRegisters_.clear();
    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    bool ret = dBinderService->DeleteDBinderStub(serviceName, deviceID, 0, 0);
    ASSERT_FALSE(ret);

    binder_uintptr_t binderObject = BINDEROBJECT;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    ASSERT_TRUE(stub != nullptr);
    dBinderService->DBinderStubRegisted_.push_back(stub);
    ret = dBinderService->DeleteDBinderStub(serviceName, deviceID, 0, 0);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InvokerRemoteDBinderWhenRequestTest001
 * @tc.desc: Verify the InvokerRemoteDBinderWhenRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, InvokerRemoteDBinderWhenRequestTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    std::u16string serviceName(u"abcd");
    std::string deviceID("001");
    binder_uintptr_t binderObject = BINDEROBJECT;
    uint32_t pid = PID;
    uint32_t uid = UID;
    uint32_t seqNumber = 0;
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo;

    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID,
        binderObject, pid, uid);
    EXPECT_NE(stub, nullptr);
    dBinderService->threadLockInfo_[seqNumber] = threadLockInfo;
    int32_t ret = dBinderService->InvokerRemoteDBinderWhenRequest(stub, seqNumber, pid, uid, threadLockInfo);
    EXPECT_EQ(ret, MAKE_THREADLOCK_FAILED);
    dBinderService->threadLockInfo_.clear();

    ret = dBinderService->InvokerRemoteDBinderWhenRequest(stub, seqNumber, pid, uid, threadLockInfo);
    EXPECT_EQ(ret, SEND_MESSAGE_FAILED);
}

/**
 * @tc.name: InvokerRemoteDBinderWhenWaitRspTest001
 * @tc.desc: Verify the InvokerRemoteDBinderWhenWaitRsp function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, InvokerRemoteDBinderWhenWaitRspTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    std::u16string serviceName(u"abcd");
    std::string deviceID("001");
    binder_uintptr_t binderObject = BINDEROBJECT;
    uint32_t pid = PID;
    uint32_t uid = UID;
    uint32_t seqNumber = 0;
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo;

    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID,
        binderObject, pid, uid);
    EXPECT_NE(stub, nullptr);
    int32_t ret = dBinderService->InvokerRemoteDBinderWhenWaitRsp(stub, seqNumber, pid, uid, threadLockInfo);
    EXPECT_EQ(ret, MAKE_THREADLOCK_FAILED);

    dBinderService->threadLockInfo_[seqNumber] = std::make_shared<struct ThreadLockInfo>();
    ret = dBinderService->InvokerRemoteDBinderWhenWaitRsp(stub, seqNumber, pid, uid, threadLockInfo);
    EXPECT_EQ(ret, DBINDER_OK);
}

/**
 * @tc.name: ProcessCallbackProxyTest001
 * @tc.desc: Verify the ProcessCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ProcessCallbackProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(TEST_OBJECT_HANDLE);
    EXPECT_TRUE(object != nullptr);
    std::u16string serviceName(u"testServer");
    std::string deviceID("123456");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> dBinderServiceStub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID,
        binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    bool res = dBinderService->AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    std::vector<sptr<DBinderServiceStub>> vec;
    vec.emplace_back(dBinderServiceStub);
    dBinderService->ProcessCallbackProxy(vec);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: ProcessCallbackProxyInner001
 * @tc.desc: Verify the ProcessCallbackProxyInner function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, ProcessCallbackProxyInner001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    dBinderService->ProcessCallbackProxyInner(nullptr, nullptr);

    std::u16string serviceName(u"abcd");
    std::string deviceID("001");
    binder_uintptr_t binderObject = BINDEROBJECT;
    uint32_t pid = PID;
    uint32_t uid = UID;
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo;

    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID,
        binderObject, pid, uid);
    EXPECT_NE(stub, nullptr);
    sptr<IRemoteObject> proxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_NE(proxy, nullptr);
    dBinderService->ProcessCallbackProxyInner(stub, proxy);
}

/**
 * @tc.name: NoticeCallbackProxyTest001
 * @tc.desc: Verify the NoticeCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, NoticeCallbackProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(TEST_OBJECT_HANDLE);
    EXPECT_TRUE(object != nullptr);
    std::u16string serviceName(u"testServer");
    std::string deviceID("123456");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> dBinderServiceStub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID,
        binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    dBinderService->AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    EXPECT_EQ(dBinderService->NoticeCallbackProxy(serviceName, deviceID), true);
}

/**
 * @tc.name: DetachCallbackProxyTest001
 * @tc.desc: Verify the DetachCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, DetachCallbackProxyTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(TEST_OBJECT_HANDLE);
    EXPECT_TRUE(object != nullptr);
    std::u16string serviceName(u"test1");
    std::string deviceID("12345");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> dBinderServiceStub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID,
        binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    dBinderService->AttachCallbackProxy(object, dBinderServiceStub.GetRefPtr());
    EXPECT_EQ(dBinderService->DetachCallbackProxy(object), true);
}

/**
 * @tc.name: DetachCallbackProxyTest002
 * @tc.desc: Verify the DetachCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, DetachCallbackProxyTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(TEST_OBJECT_HANDLE);
    EXPECT_TRUE(object != nullptr);
    EXPECT_EQ(dBinderService->DetachCallbackProxy(object), false);
}

/**
 * @tc.name: QueryDeathRecipientTest001
 * @tc.desc: Verify the QueryDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, QueryDeathRecipientTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(TEST_OBJECT_HANDLE);
    EXPECT_TRUE(object != nullptr);
    sptr<IRemoteObject::DeathRecipient> deathRecipient = new (std::nothrow) TestDeathRecipient();
    EXPECT_TRUE(deathRecipient != nullptr);
    dBinderService->AttachDeathRecipient(object, deathRecipient);
    EXPECT_EQ(dBinderService->QueryDeathRecipient(object), deathRecipient);
}

/**
 * @tc.name: QueryDeathRecipientTest002
 * @tc.desc: Verify the QueryDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, QueryDeathRecipientTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService->QueryDeathRecipient(nullptr), nullptr);
}

/**
 * @tc.name: AttachProxyObjectTest001
 * @tc.desc: Verify the AttachProxyObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AttachProxyObjectTest001, TestSize.Level1)
{
    std::string name("Test");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    binder_uintptr_t binderObject1 = TEST_BINDER_OBJECT_PTR + 1;
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(TEST_OBJECT_HANDLE);
    EXPECT_TRUE(object != nullptr);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    EXPECT_EQ(dBinderService->AttachProxyObject(object, binderObject), true);
    EXPECT_EQ(dBinderService->QueryProxyObject(binderObject), object);
    EXPECT_EQ(dBinderService->QueryProxyObject(binderObject1), nullptr);
}

/**
 * @tc.name: AttachProxyObjectTest002
 * @tc.desc: Verify the AttachProxyObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AttachProxyObjectTest002, TestSize.Level1)
{
    uint32_t seqNumber = TEST_SEQ_NUMBER;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
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
HWTEST_F(DBinderServiceTest, MakeSessionByReplyMessageTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::shared_ptr<struct DHandleEntryTxRx> replyMessage = std::make_shared<DHandleEntryTxRx>();
    ASSERT_TRUE(replyMessage != nullptr);
    (void)memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    dBinderService->MakeSessionByReplyMessage(replyMessage);
    EXPECT_EQ(dBinderService->HasDBinderStub(replyMessage->binderObject), false);

    std::u16string serviceName(u"testServer");
    std::string deviceID;
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_TRUE(stub != nullptr);
    replyMessage->stub = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    dBinderService->MakeSessionByReplyMessage(replyMessage);
}

/**
 * @tc.name: MakeSessionByReplyMessageTest002
 * @tc.desc: Verify the MakeSessionByReplyMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, MakeSessionByReplyMessageTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_NE(stub, nullptr);
    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    binder_uintptr_t stubTag = dBinderService->AddStubByTag(binderObjectPtr);
    EXPECT_GT(stubTag, 0);

    dBinderService->DBinderStubRegisted_.push_back(stub);

    auto replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    (void)memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));

    replyMessage->dBinderCode = MESSAGE_AS_REPLY;
    replyMessage->stubIndex = 0;
    dBinderService->MakeSessionByReplyMessage(replyMessage);

    replyMessage->stubIndex = 1;
    dBinderService->MakeSessionByReplyMessage(replyMessage);

    replyMessage->stub = binderObjectPtr;
    dBinderService->MakeSessionByReplyMessage(replyMessage);
}

/**
 * @tc.name: GetInstanceTest001
 * @tc.desc: Verify the GetInstance function return not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, GetInstanceTest001, TestSize.Level1)
{
    DBinderService::instance_ = nullptr;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);
}

/**
 * @tc.name: CheckAndAmendSaIdTest001
 * @tc.desc: Verify the CheckAndAmendSaId function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckAndAmendSaIdTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<struct DHandleEntryTxRx>();
    ASSERT_NE(message, nullptr);

    int32_t vaildId = DBinderService::FIRST_SYS_ABILITY_ID + 1;
    int32_t invaildId = DBinderService::LAST_SYS_ABILITY_ID + 1;
    message->stubIndex = vaildId;
    message->binderObject = invaildId;
    int ret = dBinderService->CheckAndAmendSaId(message);
    EXPECT_EQ(message->binderObject, vaildId);
    EXPECT_TRUE(ret);
    message->stubIndex = invaildId;
    message->binderObject = vaildId;
    ret = dBinderService->CheckAndAmendSaId(message);
    EXPECT_EQ(message->stubIndex, vaildId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: AddAsynMessageTaskTest001
 * @tc.desc: Verify the AddAsynMessageTask function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AddAsynMessageTaskTest001, TestSize.Level1)
{
    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<struct DHandleEntryTxRx>();
    EXPECT_NE(message.get(), nullptr);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->AddAsynMessageTask(message);
}

/**
 * @tc.name: CreateDatabusNameTest001
 * @tc.desc: Verify the CreateDatabusName function return not empty
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CreateDatabusNameTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    DBinderSoftbusClient &softbusClient = DBinderSoftbusClient::GetInstance();
    softbusClient.grantPermissionFunc_ = [](int32_t uid, int32_t pid, const char *permission) -> int32_t {
        return ERR_NONE;
    };
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, DBinderGrantPermission).WillOnce(testing::Return(ERR_NONE));
    std::string databusName = dBinderService->CreateDatabusName(UID, PID);
    EXPECT_FALSE(databusName.empty());
}

/**
 * @tc.name: CreateDatabusNameTest002
 * @tc.desc: Verify the CreateDatabusName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CreateDatabusNameTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    int pid = 0;
    int uid = 0;
    NiceMock<DBinderServiceInterfaceMock> mock;
    EXPECT_CALL(mock, DBinderGrantPermission).WillOnce(testing::Return(DBINDER_SERVICE_INVALID_DATA_ERR));
    std::string res = dBinderService->CreateDatabusName(pid, uid);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: FindServicesByDeviceIDTest001
 * @tc.desc: Verify the FindServicesByDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, FindServicesByDeviceIDTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::u16string serviceName(u"testServer");
    std::string deviceID("123456");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> dBinderServiceStub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID,
        binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    dBinderService->DBinderStubRegisted_.push_back(dBinderServiceStub);
    std::set<std::u16string> serviceNames;
    serviceNames.emplace(serviceName);
    EXPECT_EQ(dBinderService->FindServicesByDeviceID(deviceID), serviceNames);
}

/**
 * @tc.name: IsSameSessionTest001
 * @tc.desc: Verify the IsSameSession function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsSameSessionTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    std::shared_ptr<struct SessionInfo> oldSession = std::make_shared<struct SessionInfo>();
    std::shared_ptr<struct SessionInfo> newSession = std::make_shared<struct SessionInfo>();
    ASSERT_NE(oldSession, nullptr);
    ASSERT_NE(newSession, nullptr);

    oldSession->stubIndex = 0;
    newSession->stubIndex = 1;
    bool ret = dBinderService->IsSameSession(oldSession, newSession);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsSameSessionTest002
 * @tc.desc: Verify the IsSameSession function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsSameSessionTest002, TestSize.Level1)
{
    std::shared_ptr<struct SessionInfo> oldSession= std::make_shared<struct SessionInfo>();
    ASSERT_NE(oldSession.get(), nullptr);
    std::shared_ptr<struct SessionInfo> newSession= std::make_shared<struct SessionInfo>();
    ASSERT_NE(newSession.get(), nullptr);
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
    ASSERT_TRUE(dBinderService != nullptr);
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
 * @tc.name: IsSameSessionTest003
 * @tc.desc: Verify the IsSameSession function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsSameSessionTest003, TestSize.Level1)
{
    std::shared_ptr<struct SessionInfo> oldSession= std::make_shared<struct SessionInfo>();
    ASSERT_NE(oldSession.get(), nullptr);
    std::shared_ptr<struct SessionInfo> newSession= std::make_shared<struct SessionInfo>();
    ASSERT_NE(newSession.get(), nullptr);

    oldSession->stubIndex = 1;
    oldSession->toPort = 2;
    oldSession->fromPort = 3;
    oldSession->type = 4;
    oldSession->serviceName[0] = 't';
    oldSession->deviceIdInfo.fromDeviceId[0] = 'a';

    newSession->stubIndex = oldSession->stubIndex;
    newSession->toPort = oldSession->toPort;
    newSession->fromPort = oldSession->fromPort;
    newSession->type = oldSession->type;
    newSession->serviceName[0] = 't';
    newSession->deviceIdInfo.fromDeviceId[0] = 'b';

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);

    bool ret = dBinderService->IsSameSession(oldSession, newSession);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AttachSessionObjectTest001
 * @tc.desc: Verify the AttachSessionObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, AttachSessionObjectTest001, TestSize.Level1)
{
    std::shared_ptr<struct SessionInfo> object = nullptr;
    binder_uintptr_t stub = 0;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->sessionObject_.clear();
    EXPECT_EQ(dBinderService->AttachSessionObject(object, stub), true);
}

/**
 * @tc.name: CheckInvokeListenThreadIllegalTest001
 * @tc.desc: Verify the CheckInvokeListenThreadIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckInvokeListenThreadIllegalTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    IPCObjectProxy object(TEST_OBJECT_HANDLE);
    MessageParcel data;
    MessageParcel reply;
    bool ret = dBinderService->CheckInvokeListenThreadIllegal(&object, data, reply);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CheckStubIndexAndSessionNameIllegalTest001
 * @tc.desc: Verify the CheckStubIndexAndSessionNameIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CheckStubIndexAndSessionNameIllegalTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    uint64_t stubIndex = 0;
    std::string serverSessionName;
    std::string deviceId;
    IPCObjectProxy proxy(TEST_OBJECT_HANDLE);
    bool ret = dBinderService->CheckStubIndexAndSessionNameIllegal(stubIndex, serverSessionName, deviceId, &proxy);
    EXPECT_TRUE(ret);

    stubIndex = 1;
    serverSessionName = SERVICE_NAME_TEST;
    deviceId = RANDOM_DEVICEID;
    ret = dBinderService->CheckStubIndexAndSessionNameIllegal(stubIndex, serverSessionName, deviceId, &proxy);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetReplyMessageTest001
 * @tc.desc: Verify the SetReplyMessage function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, SetReplyMessageTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    auto replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    (void)memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    replyMessage->head.version = RPC_TOKENID_SUPPORT_VERSION + 1;

    uint64_t stubIndex = 0;
    std::string serverSessionName(SERVICENAME_LENGTH + 1, 'a');
    uint32_t selfTokenId = 0;
    IPCObjectProxy proxy(TEST_OBJECT_HANDLE);
    bool ret = dBinderService->SetReplyMessage(replyMessage, stubIndex, serverSessionName, selfTokenId, &proxy);
    EXPECT_FALSE(ret);

    serverSessionName = string(SERVICENAME_LENGTH - 1, 'a');
    ret = dBinderService->SetReplyMessage(replyMessage, stubIndex, serverSessionName, selfTokenId, &proxy);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: IsInvalidStubTest001
 * @tc.desc: Verify the IsInvalidStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsInvalidStubTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    const std::u16string serviceName = u"abc";
    const std::string deviceID = "bcd";
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> stub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID, binderObject);
    EXPECT_NE(stub, nullptr);

    binder_uintptr_t binderObjectPtr = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    binder_uintptr_t stubTag = dBinderService->stubTagNum_++;
    auto result = dBinderService->mapDBinderStubRegisters_.insert({stubTag, binderObjectPtr});
    EXPECT_TRUE(result.second);

    dBinderService->DBinderStubRegisted_.push_back(stub);

    auto replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    (void)memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));
    replyMessage->stub = stubTag;

    bool ret = dBinderService->IsInvalidStub(replyMessage);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CopyDeviceIdInfoTest001
 * @tc.desc: Verify the CopyDeviceIdInfo function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, CopyDeviceIdInfoTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    auto session = std::make_shared<SessionInfo>();

    auto replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    (void)memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));

    dBinderService->InitializeSession(session, replyMessage);
    bool ret = dBinderService->CopyDeviceIdInfo(session, replyMessage);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: NoticeDeviceDieTest001
 * @tc.desc: Verify the NoticeDeviceDie function return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, NoticeDeviceDieTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    dBinderService->remoteListener_ = std::make_shared<DBinderRemoteListener>();
    std::string deviceId = RANDOM_DEVICEID;
    int ret = dBinderService->NoticeDeviceDie(deviceId);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: NoticeDeviceDieTest002
 * @tc.desc: Verify the NoticeDeviceDie function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, NoticeDeviceDieTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceID;
    EXPECT_EQ(dBinderService->NoticeDeviceDie(deviceID), DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: NoticeDeviceDieTest003
 * @tc.desc: Verify the NoticeDeviceDie function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, NoticeDeviceDieTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->NoticeDeviceDie(deviceID), DBINDER_SERVICE_NOTICE_DIE_ERR);
}

/**
 * @tc.name: NoticeServiceDieTest001
 * @tc.desc: Verify the NoticeServiceDie function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, NoticeServiceDieTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->StartRemoteListener();
    std::u16string serviceName;
    std::string deviceID("123456");
    EXPECT_EQ(dBinderService->NoticeServiceDie(serviceName, deviceID), DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: NoticeServiceDieTest002
 * @tc.desc: Verify the NoticeServiceDie function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, NoticeServiceDieTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    std::u16string serviceName;
    std::string deviceID;

    int32_t ret = dBinderService->NoticeServiceDie(serviceName, deviceID);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: NoticeServiceDieInnerTest001
 * @tc.desc: Verify the NoticeServiceDieInner function return DBINDER_SERVICE_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, NoticeServiceDieInnerTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    std::u16string serviceName;
    std::string deviceId = RANDOM_DEVICEID;
    int ret = dBinderService->NoticeServiceDieInner(serviceName, deviceId);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: NoticeServiceDieInnerTest002
 * @tc.desc: Verify the NoticeServiceDieInner function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, NoticeServiceDieInnerTest002, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
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
HWTEST_F(DBinderServiceTest, NoticeServiceDieInnerTest003, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_TRUE(dBinderService != nullptr);
    dBinderService->StartRemoteListener();
    std::u16string serviceName(u"testServer");
    std::string deviceID("123456");
    binder_uintptr_t binderObject = TEST_BINDER_OBJECT_PTR;
    sptr<DBinderServiceStub> dBinderServiceStub = new (std::nothrow) DBinderServiceStub(serviceName, deviceID,
        binderObject);
    EXPECT_TRUE(dBinderServiceStub != nullptr);
    dBinderService->DBinderStubRegisted_.push_back(dBinderServiceStub);
    EXPECT_EQ(dBinderService->NoticeServiceDieInner(serviceName, deviceID), DBINDER_SERVICE_NOTICE_DIE_ERR);
    dBinderService->DBinderStubRegisted_.clear();
}

/**
 * @tc.name: IsValidSessionNameTest001
 * @tc.desc: Verify the IsValidSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, IsValidSessionNameTest001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    ASSERT_NE(dBinderService, nullptr);

    auto replyMessage = std::make_shared<struct DHandleEntryTxRx>();
    (void)memset_s(replyMessage.get(), sizeof(DHandleEntryTxRx), 0, sizeof(DHandleEntryTxRx));

    // empty sessionName
    replyMessage->serviceNameLength = 0;
    (void)memset_s(replyMessage->serviceName, SERVICENAME_LENGTH + 1, 0, SERVICENAME_LENGTH + 1);
    bool ret = dBinderService->IsValidSessionName(replyMessage);
    ASSERT_TRUE(ret);

    // serviceNameLength > SERVICENAME_LENGTH
    replyMessage->serviceNameLength = SERVICENAME_LENGTH + 1;
    ret = dBinderService->IsValidSessionName(replyMessage);
    ASSERT_FALSE(ret);

    // testName length < serviceNameLength < SERVICENAME_LENGTH
    std::string testName = "abc";
    replyMessage->serviceNameLength = testName.size() + 1;
    ASSERT_EQ(strcpy_s(replyMessage->serviceName, SERVICENAME_LENGTH + 1, testName.c_str()), EOK);
    ret = dBinderService->IsValidSessionName(replyMessage);
    ASSERT_FALSE(ret);

    // serviceNameLength == testName length
    replyMessage->serviceNameLength = testName.size();
    ret = dBinderService->IsValidSessionName(replyMessage);
    ASSERT_TRUE(ret);
}
}
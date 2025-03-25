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

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

namespace {
    const std::u16string ZERO_SERVICENAME = u"";
    const std::u16string RANDOM_SERVICENAME = u"servicename";
    const std::string RANDOM_DEVICEID = "device";
    const std::string ZERO_DEVICEID = "";
    const int32_t BINDEROBJECT = 1;
    const uint32_t PID = 1;
    const uint32_t UID = 1;
    const binder_uintptr_t BINDER_OBJECT = 1ULL;
}

class DBinderServiceInterface {
public:
    DBinderServiceInterface() {};
    virtual ~DBinderServiceInterface() {};
    
    virtual bool StartListener() = 0;
    virtual std::shared_ptr<struct DHandleEntryTxRx> CreateMessage(const sptr<DBinderServiceStub> &stub,
        uint32_t seqNumber, uint32_t pid, uint32_t uid) = 0;
    virtual std::shared_ptr<DBinderRemoteListener> GetRemoteListener() = 0;
    virtual bool SendDataToRemote(const std::string &networkId, const struct DHandleEntryTxRx *msg) = 0;
    virtual int32_t GetLocalNodeDeviceId(const std::string &pkgName, std::string &devId) = 0;
};
class DBinderServiceInterfaceMock : public DBinderServiceInterface {
public:
    DBinderServiceInterfaceMock();
    ~DBinderServiceInterfaceMock() override;

    MOCK_METHOD0(StartListener, bool());
    MOCK_METHOD4(CreateMessage, std::shared_ptr<struct DHandleEntryTxRx>(const sptr<DBinderServiceStub> &stub,
        uint32_t seqNumber, uint32_t pid, uint32_t uid));
    MOCK_METHOD0(GetRemoteListener, std::shared_ptr<DBinderRemoteListener>());
    MOCK_METHOD2(SendDataToRemote, bool(const std::string &networkId, const struct DHandleEntryTxRx *msg));
    MOCK_METHOD2(GetLocalNodeDeviceId, int32_t(const std::string &pkgName, std::string &devId));
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

    std::shared_ptr<DBinderRemoteListener> DBinderService::GetRemoteListener()
    {
        if (g_interface == nullptr) {
            return nullptr;
        }
        return GetDBinderServiceInterfaceMock()->GetRemoteListener();
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
}

class DBinderServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
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
    NiceMock<DBinderServiceInterfaceMock> mock;
    dBinderService.remoteListener_ = nullptr;
    EXPECT_CALL(mock, StartListener).WillOnce(testing::Return(true));

    bool result = dBinderService.StartRemoteListener();
    EXPECT_TRUE(result);
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
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MakeRemoteBinderTest001
 * @tc.desc: Verify the MakeRemoteBinder function when error serviceName and deviceID
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceTest, MakeRemoteBinderTest001, TestSize.Level1)
{
    DBinderService dBinderService;
    NiceMock<DBinderServiceInterfaceMock> mock;
    sptr<DBinderServiceStub> result = dBinderService.MakeRemoteBinder(
        ZERO_SERVICENAME, ZERO_DEVICEID, BINDEROBJECT, PID, UID);
    EXPECT_EQ(result, nullptr);
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
        RANDOM_DEVICEID, ZERO_DEVICEID, BINDER_OBJECT);
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
        RANDOM_DEVICEID, RANDOM_DEVICEID, BINDER_OBJECT);
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
        RANDOM_DEVICEID, RANDOM_DEVICEID, BINDER_OBJECT);
    NiceMock<DBinderServiceInterfaceMock> mock;
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_CALL(mock, SendDataToRemote).WillOnce(testing::Return(false));
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
        RANDOM_DEVICEID, RANDOM_DEVICEID, BINDER_OBJECT);
    NiceMock<DBinderServiceInterfaceMock> mock;
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    EXPECT_CALL(mock, SendDataToRemote).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, GetLocalNodeDeviceId).WillOnce(testing::Return(SOFTBUS_CLIENT_SUCCESS));

    bool result = dBinderService.SendEntryToRemote(dBinderServiceStub, PID, PID, PID);
    EXPECT_TRUE(result);
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
        RANDOM_DEVICEID, ZERO_DEVICEID, BINDER_OBJECT);
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
        RANDOM_DEVICEID, RANDOM_DEVICEID, BINDER_OBJECT);
    NiceMock<DBinderServiceInterfaceMock> mock;
    std::shared_ptr<struct ThreadLockInfo> threadLockInfo = std::make_shared<struct ThreadLockInfo>();
    dBinderService.remoteListener_ = std::make_shared<DBinderRemoteListener>();
    dBinderService.AttachThreadLockInfo(PID, RANDOM_DEVICEID, threadLockInfo);
    EXPECT_CALL(mock, SendDataToRemote).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, GetLocalNodeDeviceId).WillOnce(testing::Return(SOFTBUS_CLIENT_SUCCESS));

    int32_t result = dBinderService.InvokerRemoteDBinder(dBinderServiceStub, PID, PID, PID);
    EXPECT_EQ(result, DBinderErrorCode::MAKE_THREADLOCK_FAILED);
}
}
/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#define private public
#include "comm_auth_info.h"
#include "databus_session_callback.h"
#include "dbinder_session_object.h"
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "test_service_skeleton.h"
#include "test_service.h"
#include "test_service_command.h"
#include "test_service_client.h"
#include "ipc_test_helper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "dbinder_session_object.h"
#include "message_option.h"
#include "mock_session_impl.h"
#include "stub_refcount_object.h"
#include "system_ability_definition.h"
#include "log_tags.h"
#undef private
#ifndef CONFIG_STANDARD_SYSTEM
#include "jni_help.h"
#endif

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

namespace {
constexpr int MAX_TEST_COUNT = 1000;
constexpr bool SUPPORT_ZBINDER = false;
constexpr uint32_t INVAL_TOKEN_ID = 0x0;
constexpr int MAX_WAIT_TIME = 3000;
constexpr int INVALID_LEN = 9999;
}

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
 * @tc.name: GetObjectRefCountTest001
 * @tc.desc: Verify the GetObjectRefCount function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetObjectRefCountTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    int count = testStub->GetObjectRefCount();
    EXPECT_GE(count, 0);
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
 * @tc.name: OnRemoteDumpTest001
 * @tc.desc: Verify the OnRemoteDump function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, OnRemoteDumpTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->OnRemoteDump(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendRequestTest001
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = INTERFACE_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: SendRequestTest002
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest002, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = SYNCHRONIZE_REFERENCE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: SendRequestTest003
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest003, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = DUMP_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendRequestTest004
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest004, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

#ifndef CONFIG_IPC_SINGLE
/**
 * @tc.name: SendRequestTest005
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest005, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = INVOKE_LISTEN_THREAD;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVOKE_THREAD_ERR);
}

/**
 * @tc.name: SendRequestTest007
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest007, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = DBINDER_INCREFS_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendRequestTest008
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest008, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = DBINDER_DECREFS_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendRequestTest009
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest009, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = DBINDER_DECREFS_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendRequestTest010
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest010, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = DBINDER_ADD_COMMAUTH;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendRequestTest011
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest011, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = DBINDER_TRANS_COMMAUTH;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendRequestTest012
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest012, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = GET_UIDPID_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: SendRequestTest013
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest013, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = GRANT_DATABUS_NAME;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: SendRequestTest014
 * @tc.desc: Verify the SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, SendRequestTest014, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t code = TRANS_DATABUS_NAME;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int result = testStub->SendRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: InvokerDataBusThread001
 * @tc.desc: Verify the InvokerDataBusThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, InvokerDataBusThread001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    MessageParcel data;
    MessageParcel reply;

    std::string deviceId = "testdeviceId";
    data.WriteString(deviceId);
    uint32_t remotePid = 1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid = 1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "testremoteDeviceId";
    data.WriteString(remoteDeviceId);
    std::string sessionName = "testsessionName";
    data.WriteString(sessionName);
    uint32_t featureSet = 1;
    data.WriteUint32(featureSet);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->stubObjects_[0] = testStub.GetRefPtr();
    auto ret = testStub->InvokerDataBusThread(data, reply);
    EXPECT_EQ(ret, IPC_STUB_CREATE_BUS_SERVER_ERR);
    current->stubObjects_.clear();
}

/**
 * @tc.name: InvokerDataBusThread002
 * @tc.desc: Verify the InvokerDataBusThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, InvokerDataBusThread002, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    MessageParcel data;
    MessageParcel reply;
    std::string deviceId = "testdeviceId";
    data.WriteString(deviceId);
    uint32_t remotePid = 1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid = 1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "testremoteDeviceId";
    data.WriteString(remoteDeviceId);
    std::string sessionName = "testsessionName";
    data.WriteString(sessionName);
    uint32_t featureSet = 1;
    data.WriteUint32(featureSet);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->stubObjects_[1] = testStub.GetRefPtr();

    std::string appInfo = remoteDeviceId +
        std::to_string(remotePid) + std::to_string(remoteUid);
    current->appInfoToStubIndex_[appInfo] = std::map<uint64_t, bool> { { 1, true } };

    auto ret = testStub->InvokerDataBusThread(data, reply);
    EXPECT_EQ(ret, IPC_STUB_CREATE_BUS_SERVER_ERR);
    current->stubObjects_.clear();
    current->appInfoToStubIndex_.clear();
}

/**
 * @tc.name: InvokerDataBusThread003
 * @tc.desc: Verify the InvokerDataBusThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, InvokerDataBusThread003, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    MessageParcel data;
    MessageParcel reply;
    std::string deviceId = "testdeviceId";
    data.WriteString(deviceId);
    uint32_t remotePid = 1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid = 1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "testremoteDeviceId";
    data.WriteString(remoteDeviceId);
    std::string sessionName = "testsessionName";
    data.WriteString(sessionName);
    uint32_t featureSet = 1;
    data.WriteUint32(featureSet);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->stubObjects_[1] = testStub.GetRefPtr();

    std::string appInfo = remoteDeviceId +
        std::to_string(remotePid) + std::to_string(remoteUid);
    current->appInfoToStubIndex_[appInfo] = std::map<uint64_t, bool> { { 0, true } };

    auto ret = testStub->InvokerDataBusThread(data, reply);
    EXPECT_EQ(ret, IPC_STUB_CREATE_BUS_SERVER_ERR);
    current->stubObjects_.clear();
    current->appInfoToStubIndex_.clear();
}

/**
 * @tc.name: InvokerThread001
 * @tc.desc: Verify the InvokerThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, InvokerThread001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    uint32_t type = IRemoteObject::DATABUS_TYPE;
    data.WriteUint32(type);
    std::string deviceId = "";
    data.WriteString(deviceId);
    uint32_t remotePid = 1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid = 1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "";
    data.WriteString(remoteDeviceId);
    std::string sessionName = "";
    data.WriteString(sessionName);
    uint32_t featureSet = 1;
    data.WriteUint32(featureSet);
    MessageOption option;

    auto ret = testStub->InvokerThread(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_INVOKE_THREAD_ERR);
}

/**
 * @tc.name: NoticeServiceDieTest001
 * @tc.desc: Verify the NoticeServiceDie function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, NoticeServiceDieTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->noticeStub_[objectProxy.GetRefPtr()] = testStub;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto result = testStub->NoticeServiceDie(data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    current->noticeStub_.erase(objectProxy.GetRefPtr());
}

/**
 * @tc.name: NoticeServiceDieTest002
 * @tc.desc: Verify the NoticeServiceDie function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, NoticeServiceDieTest002, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto result = testStub->NoticeServiceDie(data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: IncStubRefsTest001
 * @tc.desc: Verify the IncStubRefs function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, IncStubRefsTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    MessageParcel data;
    MessageParcel reply;
    auto result = testStub->IncStubRefs(data, reply);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: AddAuthInfoeTest001
 * @tc.desc: Verify the AddAuthInfoe function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, AddAuthInfoeTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    MessageParcel data;
    MessageParcel reply;
    uint32_t code = 0;
    int32_t ret = testStub->AddAuthInfo(data, reply, code);
    EXPECT_EQ(ret, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: AddAuthInfoeTest002
 * @tc.desc: Verify the AddAuthInfoe function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, AddAuthInfoeTest002, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    MessageParcel data;
    uint32_t remotePid =  1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid =  1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "testRemoteDeviceId";
    data.WriteString(remoteDeviceId);
    uint32_t remoteFeature =  1;
    data.WriteUint32(remoteFeature);
    uint64_t stubIndex = 1;
    data.WriteUint64(stubIndex);

    MessageParcel reply;
    uint32_t code = DBINDER_TRANS_COMMAUTH;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();
    std::shared_ptr<CommAuthInfo> info =
        std::make_shared<CommAuthInfo>(testStub.GetRefPtr(), remotePid, remoteUid, remoteDeviceId, rpcFeatureSet);
    current->commAuth_.push_back(info);

    int32_t ret = testStub->AddAuthInfo(data, reply, code);
    EXPECT_EQ(ret, ERR_NONE);
    info->stub_ = nullptr;
    current->commAuth_.remove(info);
}

/**
 * @tc.name: AddAuthInfoeTest003
 * @tc.desc: Verify the AddAuthInfoe function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, AddAuthInfoeTest003, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    MessageParcel data;
    uint32_t remotePid =  1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid =  1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "testRemoteDeviceId";
    data.WriteString(remoteDeviceId);
    uint32_t remoteFeature =  1;
    data.WriteUint32(remoteFeature);
    uint64_t stubIndex = 1;
    data.WriteUint64(stubIndex);

    MessageParcel reply;
    uint32_t code = DBINDER_TRANS_COMMAUTH;

    int32_t ret = testStub->AddAuthInfo(data, reply, code);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: AddAuthInfoeTest004
 * @tc.desc: Verify the AddAuthInfoe function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, AddAuthInfoeTest004, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    MessageParcel data;
    uint32_t remotePid =  1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid =  1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "testRemoteDeviceId";
    data.WriteString(remoteDeviceId);
    uint32_t remoteFeature =  1;
    data.WriteUint32(remoteFeature);
    uint64_t stubIndex = 1;
    data.WriteUint64(stubIndex);

    MessageParcel reply;
    uint32_t code = DBINDER_ADD_COMMAUTH;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();
    std::shared_ptr<CommAuthInfo> info =
        std::make_shared<CommAuthInfo>(testStub.GetRefPtr(), remotePid, remoteUid, remoteDeviceId, rpcFeatureSet);
    current->commAuth_.push_back(info);

    int32_t ret = testStub->AddAuthInfo(data, reply, code);
    EXPECT_EQ(ret, ERR_NONE);
    info->stub_ = nullptr;
    current->commAuth_.remove(info);
}

/**
 * @tc.name: AddAuthInfoeTest005
 * @tc.desc: Verify the AddAuthInfoe function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, AddAuthInfoeTest005, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    MessageParcel data;
    uint32_t remotePid =  1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid =  1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "testRemoteDeviceId";
    data.WriteString(remoteDeviceId);
    uint32_t remoteFeature =  1;
    data.WriteUint32(remoteFeature);
    uint64_t stubIndex = 0;
    data.WriteUint64(stubIndex);

    MessageParcel reply;
    uint32_t code = DBINDER_TRANS_COMMAUTH;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();
    std::shared_ptr<CommAuthInfo> info =
        std::make_shared<CommAuthInfo>(testStub.GetRefPtr(), remotePid, remoteUid, remoteDeviceId, rpcFeatureSet);
    current->commAuth_.push_back(info);

    int32_t ret = testStub->AddAuthInfo(data, reply, code);
    EXPECT_EQ(ret, BINDER_CALLBACK_STUBINDEX_ERR);
    info->stub_ = nullptr;
    current->commAuth_.remove(info);
}

/**
 * @tc.name: AddAuthInfoeTest006
 * @tc.desc: Verify the AddAuthInfoe function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, AddAuthInfoeTest006, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    MessageParcel data;
    uint32_t remotePid =  1;
    data.WriteUint32(remotePid);
    uint32_t remoteUid =  1;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = "testRemoteDeviceId";
    data.WriteString(remoteDeviceId);
    uint32_t remoteFeature =  1;
    data.WriteUint32(remoteFeature);
    uint64_t stubIndex = 1;
    data.WriteUint64(stubIndex);

    MessageParcel reply;
    uint32_t code = DBINDER_TRANS_COMMAUTH;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();
    std::shared_ptr<CommAuthInfo> info =
        std::make_shared<CommAuthInfo>(testStub.GetRefPtr(), remotePid, remoteUid, remoteDeviceId, rpcFeatureSet);
    current->commAuth_.push_back(info);

    std::string appInfo = remoteDeviceId + std::to_string(remotePid) + std::to_string(remoteUid);
    current->appInfoToStubIndex_[appInfo] = std::map<uint64_t, bool> { { 1, true } };

    int32_t ret = testStub->AddAuthInfo(data, reply, code);
    EXPECT_EQ(ret, ERR_NONE);
    info->stub_ = nullptr;
    current->commAuth_.remove(info);
}


/**
 * @tc.name: TransDataBusNameTest001
 * @tc.desc: Verify the TransDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, TransDataBusNameTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    MessageParcel data;
    MessageParcel reply;
    uint32_t code = DBINDER_TRANS_COMMAUTH;
    MessageOption option;

    int32_t ret = testStub->TransDataBusName(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: CreateDatabusNameTest001
 * @tc.desc: Verify the CreateDatabusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CreateDatabusNameTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    int uid = 1;
    int pid = 1;
    int systemAbilityId = 1;

    auto ret = testStub->CreateDatabusName(uid, pid, systemAbilityId);
    ASSERT_TRUE(ret.empty());
}

/**
 * @tc.name: CreateDatabusNameTest002
 * @tc.desc: Verify the CreateDatabusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CreateDatabusNameTest002, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    int uid = 1;
    int pid = 1;
    int systemAbilityId = 2;

    auto ret = testStub->CreateDatabusName(uid, pid, systemAbilityId);
    ASSERT_TRUE(ret.empty());
}

/**
 * @tc.name: IsSamgrCallTest001
 * @tc.desc: Verify the IsSamgrCall function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, IsSamgrCallTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    uint32_t accessToken = 1;
    auto ret = testStub->IsSamgrCall(accessToken);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: HasDumpPermissionTest001
 * @tc.desc: Verify the HasDumpPermission function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, HasDumpPermissionTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");

    uint32_t accessToken = 1;
    auto ret = testStub->HasDumpPermission(accessToken);
    ASSERT_FALSE(ret);
}
#endif

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

/**
 * @tc.name: GetCallingPidTest001
 * @tc.desc: Verify the GetCallingPid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetCallingPidTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    pid_t id = testStub->GetCallingPid();
    EXPECT_NE(id, -1);
}

/**
 * @tc.name: GetCallingUidTest001
 * @tc.desc: Verify the GetCallingUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetCallingUidTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    pid_t id = testStub->GetCallingUid();
    EXPECT_NE(id, -1);
}

/**
 * @tc.name: GetCallingTokenIDTest001
 * @tc.desc: Verify the GetCallingTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetCallingTokenIDTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t token = testStub->GetCallingTokenID();
    EXPECT_NE(token, INVAL_TOKEN_ID);
}

/**
 * @tc.name: GetFirstTokenIDTest001
 * @tc.desc: Verify the GetFirstTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetFirstTokenIDTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint32_t token = testStub->GetFirstTokenID();
    EXPECT_EQ(token, INVAL_TOKEN_ID);
}

/**
 * @tc.name: GetObjectTypeTest001
 * @tc.desc: Verify the GetObjectType function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetObjectTypeTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    int ret = testStub->GetObjectType();
    EXPECT_EQ(ret, IPCObjectStub::OBJECT_TYPE_NATIVE);
}

/**
 * @tc.name: IsDeviceIdIllegalTest001
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, IsDeviceIdIllegalTest001, TestSize.Level1)
{
    std::string deviceID = "test";
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"test");
    bool ret = testStub->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsDeviceIdIllegalTest002
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, IsDeviceIdIllegalTest002, TestSize.Level1)
{
    std::string deviceID = "";
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"test");
    bool ret = testStub->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsDeviceIdIllegalTest003
 * @tc.desc: Verify the IsDeviceIdIllegal function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, IsDeviceIdIllegalTest003, TestSize.Level1)
{
    std::string deviceID(INVALID_LEN, '1');
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"test");
    bool ret = testStub->IsDeviceIdIllegal(deviceID);
    EXPECT_EQ(ret, true);
}

#ifndef CONFIG_IPC_SINGLE
/**
 * @tc.name: OnRemoteRequestTest001
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, OnRemoteRequestTest001, TestSize.Level1)
{
    std::string deviceID(INVALID_LEN, '1');
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"test");
    uint32_t code = DBINDER_OBITUARY_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto ret = testStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnRemoteRequestTest002
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, OnRemoteRequestTest002, TestSize.Level1)
{
    std::string deviceID(INVALID_LEN, '1');
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"test");
    uint32_t code = DBINDER_OBITUARY_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto ret = testStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnRemoteRequestTest003
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, OnRemoteRequestTest003, TestSize.Level1)
{
    std::string deviceID(INVALID_LEN, '1');
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"test");
    uint32_t code = DBINDER_OBITUARY_TRANSACTION;
    MessageParcel data;
    data.WriteInt32(IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT);
    MessageParcel reply;
    MessageOption option;
    auto ret = testStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnRemoteRequestTest004
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, OnRemoteRequestTest004, TestSize.Level1)
{
    std::string deviceID(INVALID_LEN, '1');
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"test");
    uint32_t code = DBINDER_INCREFS_TRANSACTION;
    MessageParcel data;
    data.WriteInt32(IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT);
    MessageParcel reply;
    MessageOption option;
    auto ret = testStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}
#endif

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
        ZLOGD(LABEL, "Got Proxy node");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int ret = proxy->TestSyncTransaction(2019, reply);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(reply, 9102);
    } else {
        ZLOGD(LABEL, "Got Stub node");
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

    ZLOGD(LABEL, "Get test.service OK\n");
    if (service->IsProxyObject()) {
        ZLOGD(LABEL,  "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int reply = 0;
        int ret = proxy->TestAsyncTransaction(2019, reply);
        EXPECT_EQ(ret, ERR_NONE);
    } else {
        ZLOGD(LABEL, "Got Stub node\n");
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

    ZLOGD(LABEL, "Get test.service OK\n");
    if (service->IsProxyObject()) {
        ZLOGD(LABEL,  "Got Proxy node\n");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int reply = 0;
        int ret = proxy->TestAsyncTransaction(2019, reply);
        EXPECT_EQ(ret, ERR_NONE);
    } else {
        ZLOGD(LABEL, "Got Stub node\n");
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
 * @tc.name: GetRawDataCapacityTest001
 * @tc.desc: Verify the GetRawDataCapacity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetRawDataCapacityTest001, TestSize.Level1)
{
    MessageParcel parcel;
    size_t ret = parcel.GetRawDataCapacity();
    EXPECT_EQ(ret, MAX_RAWDATA_SIZE);
}

/**
 * @tc.name: GetRawDataCapacityTest002
 * @tc.desc: Verify the GetRawDataCapacity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetRawDataCapacityTest002, TestSize.Level1)
{
    MessageParcel data;
    uint8_t bytes[8] = {0};
    data.WriteBuffer(bytes, 8);
    MessageParcel parcel;
    bool ret = parcel.Append(data);
    EXPECT_EQ(ret, true);
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

/**
 * @tc.name: MessageOptionTest002
 * @tc.desc:  Verify the SetWaitTime function
 * @tc.type: FUNC
 * @tc.require: AR000ER7PF
 */
HWTEST_F(IPCNativeUnitTest, MessageOptionTest002, TestSize.Level1)
{
    MessageOption messageOption;
    messageOption.SetWaitTime(MAX_WAIT_TIME + 1);
    ASSERT_EQ(messageOption.GetWaitTime(), MAX_WAIT_TIME);
}

/**
 * @tc.name: MessageOptionTest003
 * @tc.desc:  Verify the SetWaitTime function
 * @tc.type: FUNC
 * @tc.require: AR000ER7PF
 */
HWTEST_F(IPCNativeUnitTest, MessageOptionTest003, TestSize.Level1)
{
    MessageOption messageOption;
    messageOption.SetWaitTime(MessageOption::TF_ASYNC);
    ASSERT_EQ(messageOption.GetWaitTime(), MessageOption::TF_ASYNC);
}

/**
 * @tc.name: AccessTokenid001
 * @tc.desc: Test IPC AccessTokenid transport
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, AccessTokenid001, TestSize.Level1)
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
        ZLOGD(LABEL, "Got Proxy node");
        TestServiceProxy *proxy = static_cast<TestServiceProxy *>(testService.GetRefPtr());
        int ret = proxy->TestAccessTokenID(3571);
        EXPECT_EQ(ret, 0);
    } else {
        ZLOGE(LABEL, "Got Stub node");
    }
}

/**
 * @tc.name: GetStubObjectTest001
 * @tc.desc: Verify the StubRefCountObject class
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetStubObjectTest001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObj = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remoteObj != nullptr);

    IRemoteObject *stub = remoteObj.GetRefPtr();
    int remotePid = 1;
    std::string deviceId = "test";
    StubRefCountObject object(stub, remotePid, deviceId);
    EXPECT_NE(object.GetStubObject(), nullptr);
}

/**
 * @tc.name: GetRemotePidTest002
 * @tc.desc: Verify the StubRefCountObject::GetRemotePid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetRemotePidTest002, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObj = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remoteObj != nullptr);

    IRemoteObject *stub = remoteObj.GetRefPtr();
    int remotePid = 1;
    std::string deviceId = "test";
    StubRefCountObject object(stub, remotePid, deviceId);
    int pid = object.GetRemotePid();
    EXPECT_EQ(pid, 1);
}

/**
 * @tc.name: GetDeviceIdTest003
 * @tc.desc: Verify the StubRefCountObject::GetDeviceId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetDeviceIdTest003, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObj = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remoteObj != nullptr);

    IRemoteObject *stub = remoteObj.GetRefPtr();
    int remotePid = 1;
    std::string deviceId = "test";
    StubRefCountObject object(stub, remotePid, deviceId);
    std::string res = object.GetDeviceId();
    EXPECT_STREQ(res.c_str(), deviceId.c_str());
}

/**
 * @tc.name: FlushCommandsTest001
 * @tc.desc: Verify the StubRefCountObject class
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, FlushCommandsTest001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObj = IPCSkeleton::GetContextObject();
    ASSERT_TRUE(remoteObj != nullptr);

    int ret = IPCSkeleton::FlushCommands(remoteObj);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: CommAuthInfoGetStubObjectTest001
 * @tc.desc: Verify the CommAuthInfo::GetStubObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfoGetStubObjectTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, deviceId, rpcFeatureSet);
    ASSERT_TRUE(commAuthInfo.GetStubObject() != nullptr);
}

/**
 * @tc.name: CommAuthInfoGetRemotePidTest001
 * @tc.desc: Verify the CommAuthInfo::GetRemotePid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfoGetRemotePidTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, deviceId, rpcFeatureSet);
    EXPECT_EQ(commAuthInfo.GetRemotePid(), 1);
}

/**
 * @tc.name: CommAuthInfoGetRemoteUidTest001
 * @tc.desc: Verify the CommAuthInfo::GetRemoteUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfoGetRemoteUidTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, deviceId, rpcFeatureSet);
    EXPECT_EQ(commAuthInfo.GetRemoteUid(), 1);
}

/**
 * @tc.name: CommAuthInfoGetRemoteDeviceIdTest001
 * @tc.desc: Verify the CommAuthInfo::GetRemoteDeviceId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfoGetRemoteDeviceIdTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, deviceId, rpcFeatureSet);
    EXPECT_STREQ(commAuthInfo.GetRemoteDeviceId().c_str(), deviceId.c_str());
}

/**
 * @tc.name: CommAuthInfoGetFeatureSetTest001
 * @tc.desc: Verify the CommAuthInfo::GetFeatureSet function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfoGetFeatureSetTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, deviceId, rpcFeatureSet);
    EXPECT_NE(commAuthInfo.GetFeatureSet(), nullptr);
}

#ifndef CONFIG_IPC_SINGLE
/**
 * @tc.name: WriteDBinderProxyTest001
 * @tc.desc: Verify the MessageParcel::WriteDBinderProxy function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, WriteDBinderProxyTest001, TestSize.Level1)
{
    MessageParcel parcel;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    auto dbinderSessionObject =
        std::make_shared<DBinderSessionObject>(sessionMock, "testserviceName", "testpeerID");
    std::shared_ptr<FeatureSetData> rpcFeatureSet = std::make_shared<FeatureSetData>();
    dbinderSessionObject->rpcFeatureSet_ = rpcFeatureSet;

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    current->proxyToSession_[handle] = dbinderSessionObject;
    auto ret = parcel.WriteDBinderProxy(object, handle, stubIndex);
    EXPECT_EQ(ret, true);
    current->proxyToSession_.erase(handle);
}

/**
 * @tc.name: WriteDBinderProxyTest002
 * @tc.desc: Verify the MessageParcel::WriteDBinderProxy function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, WriteDBinderProxyTest002, TestSize.Level1)
{
    MessageParcel parcel;
    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    uint32_t handle = 1;
    uint64_t stubIndex = 1;

    auto ret = parcel.WriteDBinderProxy(object, handle, stubIndex);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: WriteDBinderProxyTest003
 * @tc.desc: Verify the MessageParcel::WriteDBinderProxy function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, WriteDBinderProxyTest003, TestSize.Level1)
{
    MessageParcel parcel;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    auto dbinderSessionObject =
        std::make_shared<DBinderSessionObject>(sessionMock, "testserviceName", "testpeerID");

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    current->proxyToSession_[handle] = dbinderSessionObject;
    auto ret = parcel.WriteDBinderProxy(object, handle, stubIndex);
    EXPECT_EQ(ret, false);
    current->proxyToSession_.erase(handle);
}

/**
 * @tc.name: WriteRemoteObjectTest001
 * @tc.desc: Verify the MessageParcel::WriteRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, WriteRemoteObjectTest001, TestSize.Level1)
{
    MessageParcel parcel;
    uint32_t handle = IPCProcessSkeleton::DBINDER_HANDLE_BASE + 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(handle, u"test");

    current->handleToStubIndex_[handle] = 1;
    auto ret = parcel.WriteRemoteObject(objectProxy);
    EXPECT_EQ(ret, false);
    current->handleToStubIndex_.erase(handle);
}

/**
 * @tc.name: WriteRemoteObjectTest002
 * @tc.desc: Verify the MessageParcel::WriteRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, WriteRemoteObjectTest002, TestSize.Level1)
{
    MessageParcel parcel;
    uint32_t handle = IPCProcessSkeleton::DBINDER_HANDLE_BASE + 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(handle, u"test");

    current->handleToStubIndex_[handle] = 0;
    auto ret = parcel.WriteRemoteObject(objectProxy);
    EXPECT_EQ(ret, true);
    current->handleToStubIndex_.erase(handle);
}

/**
 * @tc.name: WriteFileDescriptorTest001
 * @tc.desc: Verify the MessageParcel::WriteFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, WriteFileDescriptorTest001, TestSize.Level1)
{
    MessageParcel parcel;
    int fd = 1;
    auto ret = parcel.WriteFileDescriptor(fd);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: WriteFileDescriptorTest002
 * @tc.desc: Verify the MessageParcel::WriteFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, WriteFileDescriptorTest002, TestSize.Level1)
{
    MessageParcel parcel;
    int fd = -1;
    auto ret = parcel.WriteFileDescriptor(fd);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ClearFileDescriptorTest001
 * @tc.desc: Verify the MessageParcel::ClearFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, ClearFileDescriptorTest001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.ClearFileDescriptor();
    ASSERT_TRUE(parcel.rawDataSize_ == 0);
}

/**
 * @tc.name: ContainFileDescriptorsTest001
 * @tc.desc: Verify the MessageParcel::ContainFileDescriptors function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, ContainFileDescriptorsTest001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.ContainFileDescriptors();
    ASSERT_TRUE(parcel.rawDataSize_ == 0);
}

/**
 * @tc.name: RestoreRawDataTest001
 * @tc.desc: Verify the MessageParcel::RestoreRawData function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, RestoreRawDataTest001, TestSize.Level1)
{
    MessageParcel parcel;
    std::shared_ptr<char> rawData = std::make_shared<char>();
    size_t size = 1;
    auto ret = parcel.RestoreRawData(rawData, size);
    ASSERT_TRUE(ret);

    ret = parcel.RestoreRawData(nullptr, size);
    ASSERT_FALSE(ret);

    parcel.rawData_= rawData;
    ret = parcel.RestoreRawData(rawData, size);
    ASSERT_FALSE(ret);
}
#endif

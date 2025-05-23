/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "comm_auth_info.h"
#include "dbinder_databus_invoker.h"
#include "dbinder_session_object.h"
#include "binder_invoker.h"
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "dbinder_session_object.h"
#include "message_option.h"
#include "mock_iremote_invoker.h"
#include "stub_refcount_object.h"
#include "system_ability_definition.h"
#include "log_tags.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace {
constexpr uint32_t INVAL_TOKEN_ID = 0x0;
constexpr int MAX_WAIT_TIME = 3000;
constexpr int INVALID_LEN = 9999;
}

class IPCNativeUnitTest : public testing::Test {
public:
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IPCUnitTest" };
};

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
 * @tc.name: GetCallingFullTokenIDTest001
 * @tc.desc: Verify the GetCallingFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetCallingFullTokenIDTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint64_t token1 = testStub->GetCallingFullTokenID();
    uint64_t token2 = static_cast<uint64_t>(testStub->GetCallingTokenID());
    EXPECT_NE(token1, INVAL_TOKEN_ID);
    EXPECT_EQ(token1, token2);
}

/**
 * @tc.name: GetCallingFullTokenIDTest002
 * @tc.desc: Verify the GetCallingFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetCallingFullTokenIDTest002, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint64_t token1 = testStub->GetCallingFullTokenID();
    uint64_t token2 = IPCSkeleton::GetSelfTokenID();
    EXPECT_NE(token1, INVAL_TOKEN_ID);
    EXPECT_EQ(token1, token2);
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
 * @tc.name: GetFirstFullTokenIDTest001
 * @tc.desc: Verify the GetFirstFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, GetFirstFullTokenIDTest001, TestSize.Level1)
{
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    uint64_t token = testStub->GetFirstFullTokenID();
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

    BinderInvoker *invoker = new BinderInvoker();
    invoker->status_ = IRemoteInvoker::ACTIVE_INVOKER;
    invoker->callerTokenID_ = 1;
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    auto ret = testStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_INVALID_DATA_ERR);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
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
 * @tc.name: CommAuthInfo_GetStubObjectTest001
 * @tc.desc: Verify the CommAuthInfo::GetStubObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfo_GetStubObjectTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, 1, deviceId);
    ASSERT_TRUE(commAuthInfo.GetStubObject() != nullptr);
}

/**
 * @tc.name: CommAuthInfo_GetRemotePidTest001
 * @tc.desc: Verify the CommAuthInfo::GetRemotePid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfo_GetRemotePidTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, 1, deviceId);
    EXPECT_EQ(commAuthInfo.GetRemotePid(), 1);
}

/**
 * @tc.name: CommAuthInfo_GetRemoteUidTest001
 * @tc.desc: Verify the CommAuthInfo::GetRemoteUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfo_GetRemoteUidTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, 1, deviceId);
    EXPECT_EQ(commAuthInfo.GetRemoteUid(), 1);
}

/**
 * @tc.name: CommAuthInfo_GetRemoteDeviceIdTest001
 * @tc.desc: Verify the CommAuthInfo::GetRemoteDeviceId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfo_GetRemoteDeviceIdTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, 1, deviceId);
    EXPECT_STREQ(commAuthInfo.GetRemoteDeviceId().c_str(), deviceId.c_str());
}

/**
 * @tc.name: CommAuthInfo_GetRemoteSocketIdTest001
 * @tc.desc: Verify the CommAuthInfo::GetRemoteSocketId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfo_GetRemoteSocketIdTest001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, 1, deviceId, 1);
    EXPECT_EQ(commAuthInfo.GetRemoteSocketId(), 1);
}

/**
 * @tc.name: CommAuthInfo_SetRemoteSocketIdTest001
 * @tc.desc: Verify the CommAuthInfo::GetRemoteSocketId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfo_SetRemoteSocketIdTest001, TestSize.Level1)
{
    int32_t expectedSocketId = 12345;
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, 1, deviceId, 1);
    commAuthInfo.SetRemoteSocketId(expectedSocketId);
    ASSERT_EQ(commAuthInfo.socketId_, expectedSocketId);
}

/**
 * @tc.name: CommAuthInfo_SetRemoteSocketIdTest002
 * @tc.desc: Verify the CommAuthInfo::GetRemoteSocketId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfo_SetRemoteSocketIdTest002, TestSize.Level1)
{
    int32_t expectedSocketId = -12345;
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, 1, deviceId, 1);
    commAuthInfo.SetRemoteSocketId(expectedSocketId);
    ASSERT_EQ(commAuthInfo.socketId_, expectedSocketId);
}

/**
 * @tc.name: CommAuthInfo_SetRemoteSocketIdTest003
 * @tc.desc: Verify the CommAuthInfo::GetRemoteSocketId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCNativeUnitTest, CommAuthInfo_SetRemoteSocketIdTest003, TestSize.Level1)
{
    int32_t expectedSocketId = 0;
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = saMgr->AsObject();

    std::string deviceId = "testdeviceId";
    CommAuthInfo commAuthInfo(object, 1, 1, 1, deviceId, 1);
    commAuthInfo.SetRemoteSocketId(expectedSocketId);
    ASSERT_EQ(commAuthInfo.socketId_, expectedSocketId);
}
} // namespace OHOS
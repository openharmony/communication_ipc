/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "access_token_adapter.h"
#define private public
#define protected public
#include "binder_invoker.h"
#include "binder_connector.h"
#undef protected
#undef private
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "sys_binder.h"

using namespace testing::ext;
using namespace OHOS;

class BinderInvokerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BinderInvokerUnitTest::SetUpTestCase()
{}

void BinderInvokerUnitTest::TearDownTestCase()
{}

void BinderInvokerUnitTest::SetUp()
{}

void BinderInvokerUnitTest::TearDown()
{}

/**
 * @tc.name: SetCallingIdentityTest001
 * @tc.desc: Verify the SetCallingIdentityTest001 function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, SetCallingIdentityTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity;
    bool ret = binderInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(ret, false);
    identity = "aaa";
    ret = binderInvoker.SetCallingIdentity(identity, false);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetCallingIdentityTest002
 * @tc.desc: Override SetCallingIdentity branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, SetCallingIdentityTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string token = binderInvoker.ResetCallingIdentity();
    EXPECT_FALSE(token.empty());
    bool ret = binderInvoker.SetCallingIdentity(token, false);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ReadFileDescriptor001
 * @tc.desc: Verify the ReadFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, ReadFileDescriptor001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    Parcel parcel;
    int ret = binderInvoker.ReadFileDescriptor(parcel);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ReadFileDescriptor002
 * @tc.desc: Verify the ReadFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, ReadFileDescriptor002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    Parcel parcel;
    flat_binder_object tr {};
    tr.flags = 1;
    tr.hdr.type = -1;
    parcel.WriteBuffer(&tr, sizeof(flat_binder_object));
    int ret = binderInvoker.ReadFileDescriptor(parcel);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: UnflattenObject001
 * @tc.desc: Verify the UnflattenObject function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, UnflattenObject001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    Parcel parcel;
    sptr<IRemoteObject> ret = binderInvoker.UnflattenObject(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: UnflattenObject002
 * @tc.desc: Verify the UnflattenObject function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, UnflattenObject002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    Parcel parcel;
    flat_binder_object tr {};
    tr.flags = 1;
    tr.hdr.type = -1;
    parcel.WriteBuffer(&tr, sizeof(flat_binder_object));
    sptr<IRemoteObject> ret = binderInvoker.UnflattenObject(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: SetRegistryObject001
 * @tc.desc: Verify the SetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, SetRegistryObject001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_->driverFD_ = 0;
    sptr<IRemoteObject> testStub = new IPCObjectStub(u"testStub");
    bool ret = binderInvoker.SetRegistryObject(testStub);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetRegistryObject002
 * @tc.desc: Verify the SetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, SetRegistryObject002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    sptr<IRemoteObject> testStub = new IPCObjectStub(u"testStub");
    bool ret = binderInvoker.SetRegistryObject(testStub);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetRegistryObject003
 * @tc.desc: Verify the SetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, SetRegistryObject003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    sptr<IRemoteObject> testProxy = new IPCObjectProxy(5, u"testproxy");
    bool ret = binderInvoker.SetRegistryObject(testProxy);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetRegistryObject004
 * @tc.desc: Verify the SetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, SetRegistryObject004, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    sptr<IRemoteObject> testProxy = nullptr;
    bool ret = binderInvoker.SetRegistryObject(testProxy);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetSAMgrObjectTest001
 * @tc.desc: Verify the GetSAMgrObject function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetSAMgrObjectTest001, TestSize.Level1)
{
#ifndef CONFIG_IPC_SINGLE
    BinderInvoker binderInvoker;
    IPCProcessSkeleton* current = IPCProcessSkeleton::GetCurrent();
    if (current != nullptr) {
        EXPECT_EQ(binderInvoker.GetSAMgrObject(), current->GetRegistryObject());
    } else {
        EXPECT_EQ(binderInvoker.GetSAMgrObject(), nullptr);
    }
#endif
}

/**
 * @tc.name: SetMaxWorkThreadTest001
 * @tc.desc: Verify the SetMaxWorkThread function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, SetMaxWorkThreadTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    EXPECT_EQ(binderInvoker.SetMaxWorkThread(10), false);
}

/**
 * @tc.name: FlushCommandsTest001
 * @tc.desc: Verify the FlushCommands function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, FlushCommandsTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    EXPECT_EQ(binderInvoker.FlushCommands(nullptr), IPC_INVOKER_CONNECT_ERR);
}

/**
 * @tc.name: ExitCurrentThreadTest001
 * @tc.desc: Verify the ExitCurrentThread function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, ExitCurrentThreadTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    binderInvoker.ExitCurrentThread();
    EXPECT_EQ(binderInvoker.binderConnector_, nullptr);
}

/**
 * @tc.name: OnAttemptAcquireTest001
 * @tc.desc: Verify the OnAttemptAcquire function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, OnAttemptAcquireTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    sptr<IPCObjectStub> testStub = new IPCObjectStub(u"testStub");
    binderInvoker.input_.WritePointer((uintptr_t)testStub->GetRefCounter());
    binderInvoker.OnAttemptAcquire();
    EXPECT_NE(reinterpret_cast<RefCounter *>(testStub->GetRefCounter()), nullptr);
}

/**
 * @tc.name: OnAttemptAcquireTest002
 * @tc.desc: Verify the OnAttemptAcquire function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, OnAttemptAcquireTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    void* test = nullptr;
    binderInvoker.input_.WritePointer((uintptr_t)test);
    binderInvoker.OnAttemptAcquire();

    uintptr_t refsPtr = binderInvoker.input_.WritePointer((uintptr_t)test);
    auto *refs = reinterpret_cast<RefCounter *>(refsPtr);
    EXPECT_TRUE(refs != nullptr);
}

/**
 * @tc.name: HandleReplyTest001
 * @tc.desc: Verify the HandleReply function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleReplyTest001, TestSize.Level1)
{
    bool isStubRet = false;
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.HandleReply(nullptr, isStubRet), IPC_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: HandleReplyTest002
 * @tc.desc: Verify the HandleReply function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleReplyTest002, TestSize.Level1)
{
    bool isStubRet = false;
    binder_transaction_data transactionData;
    BinderInvoker binderInvoker;
    binderInvoker.input_.WriteBuffer(&transactionData, sizeof(binder_transaction_data));
    EXPECT_EQ(binderInvoker.HandleReply(nullptr, isStubRet), IPC_INVOKER_INVALID_REPLY_ERR);
}

/**
 * @tc.name: HandleCommandsInnerTest001
 * @tc.desc: Verify the HandleCommandsInner function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleCommandsInnerTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.HandleCommandsInner(BR_ERROR), ERR_NONE);
}

/**
 * @tc.name: HandleCommandsInnerTest002
 * @tc.desc: Verify the HandleCommandsInner function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleCommandsInnerTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.HandleCommandsInner(BR_ATTEMPT_ACQUIRE), ERR_NONE);
}

/**
 * @tc.name: HandleCommandsInnerTest003
 * @tc.desc: Verify the HandleCommandsInner function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleCommandsInnerTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.HandleCommandsInner(BR_TRANSACTION), IPC_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: HandleCommandsInnerTest004
 * @tc.desc: Verify the HandleCommandsInner function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleCommandsInnerTest004, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.HandleCommandsInner(BR_SPAWN_LOOPER), ERR_NONE);
}

/**
 * @tc.name: HandleCommandsInnerTest005
 * @tc.desc: Verify the HandleCommandsInner function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleCommandsInnerTest005, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.HandleCommandsInner(BR_FINISHED), -ERR_TIMED_OUT);
}

/**
 * @tc.name: HandleCommandsInnerTest006
 * @tc.desc: Verify the HandleCommandsInner function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleCommandsInnerTest006, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    uint32_t cmd = BR_DEAD_BINDER;
    EXPECT_EQ(binderInvoker.HandleCommandsInner(cmd), ERR_NONE);
}

/**
 * @tc.name: HandleCommandsInnerTest007
 * @tc.desc: Verify the HandleCommandsInner function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleCommandsInnerTest007, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    uint32_t cmd = -1;
    EXPECT_EQ(binderInvoker.HandleCommandsInner(cmd), IPC_INVOKER_ON_TRANSACT_ERR);
}

/**
 * @tc.name: TransactWithDriverTest001
 * @tc.desc: Verify the TransactWithDriver function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, TransactWithDriverTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    EXPECT_EQ(binderInvoker.TransactWithDriver(true), IPC_INVOKER_CONNECT_ERR);
}

/**
 * @tc.name: StartWorkLoopTest001
 * @tc.desc: Override StartWorkLoop branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, StartWorkLoopTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.input_.WriteUint32(BR_TRANSACTION);
    binderInvoker.isMainWorkThread = false;
    binderInvoker.StartWorkLoop();

    EXPECT_TRUE(binderInvoker.HandleCommands(BR_TRANSACTION) == IPC_INVOKER_INVALID_DATA_ERR);
    EXPECT_TRUE(binderInvoker.isMainWorkThread == false);
}

/**
 * @tc.name: HandleCommandsTest001
 * @tc.desc: Override HandleCommands branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleCommandsTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    uint32_t cmd = BR_FINISHED;
    int error = binderInvoker.HandleCommands(cmd);
    EXPECT_EQ(error, -ERR_TIMED_OUT);
}

/**
 * @tc.name: JoinProcessThreadTest001
 * @tc.desc: Override JoinProcessThread branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, JoinProcessThreadTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    bool initiative = false;
    binderInvoker.JoinProcessThread(initiative);
    EXPECT_TRUE(initiative == false);
}

/**
 * @tc.name: WaitForCompletionTest001
 * @tc.desc: Override WaitForCompletion branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, WaitForCompletionTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.input_.WriteUint32(BR_FAILED_REPLY);
    MessageParcel reply;
    int32_t acquireResult = 1;
    int error = binderInvoker.WaitForCompletion(&reply, &acquireResult);
    EXPECT_EQ(error, static_cast<int>(BR_FAILED_REPLY));
}

/**
 * @tc.name: WaitForCompletionTest002
 * @tc.desc: Override WaitForCompletion branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, WaitForCompletionTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.input_.WriteUint32(BR_ACQUIRE_RESULT);
    MessageParcel reply;
    int32_t acquireResult;
    int error = binderInvoker.WaitForCompletion(&reply, &acquireResult);
    EXPECT_EQ(error, ERR_NONE);
}

/**
 * @tc.name: WaitForCompletionTest003
 * @tc.desc: Override WaitForCompletion branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, WaitForCompletionTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.input_.WriteUint32(BR_TRANSLATION_COMPLETE);
    MessageParcel reply;
    int32_t acquireResult;
    int error = binderInvoker.WaitForCompletion(&reply, &acquireResult);
    EXPECT_EQ(error, ERR_NONE);
}

/**
 * @tc.name: GetCallerPidTest001
 * @tc.desc: Override GetCallerPid branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetCallerPidTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerPid_ = 1;
    EXPECT_EQ(binderInvoker.GetCallerPid(), 1);
}

/**
 * @tc.name: GetCallerRealPidTest001
 * @tc.desc: Override GetCallerRealPid branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetCallerRealPidTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerRealPid_ = 1;
    EXPECT_EQ(binderInvoker.GetCallerRealPid(), 1);
}

/**
 * @tc.name: GetCallerUidTest001
 * @tc.desc: Override GetCallerUid branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetCallerUidTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerUid_ = 1;
    EXPECT_EQ(binderInvoker.GetCallerUid(), 1);
}

/**
 * @tc.name: GetCallerTokenIDTest001
 * @tc.desc: Override GetCallerTokenID branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetCallerTokenIDTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerTokenID_ = 1;
    EXPECT_EQ(binderInvoker.GetCallerTokenID(), 1);
}

/**
 * @tc.name: GetLocalDeviceIDTest001
 * @tc.desc: Override GetLocalDeviceID branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetLocalDeviceIDTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.GetLocalDeviceID(), "");
}

/**
 * @tc.name: GetCallerDeviceIDTest001
 * @tc.desc: Override GetCallerDeviceID branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetCallerDeviceIDTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.GetCallerDeviceID(), "");
}

/**
 * @tc.name: IsLocalCallingTest001
 * @tc.desc: Override IsLocalCalling branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, IsLocalCallingTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.IsLocalCalling(), true);
}

/**
 * @tc.name: FlattenObjectTest001
 * @tc.desc: Override FlattenObject branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, FlattenObjectTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    OHOS::Parcel parcel;
    const IRemoteObject* object = nullptr;
    EXPECT_EQ(binderInvoker.FlattenObject(parcel, object), false);
}

#ifndef CONFIG_IPC_SINGLE
/**
 * @tc.name: TranslateIRemoteObjectTest001
 * @tc.desc: Override TranslateIRemoteObject branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, TranslateIRemoteObjectTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    int32_t cmd = 1;
    sptr<IRemoteObject> testStub = new IPCObjectStub(u"testStub");
    BinderConnector *binderConnector = BinderConnector::GetInstance();
    binderConnector->driverFD_ = 1;
    auto ret = binderInvoker.TranslateIRemoteObject(cmd, testStub);
    EXPECT_EQ(ret, -IPC_INVOKER_TRANSLATE_ERR);
}

/**
 * @tc.name: TranslateIRemoteObjectTest002
 * @tc.desc: Override TranslateIRemoteObject branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, TranslateIRemoteObjectTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    int32_t cmd = 1;
    binderInvoker.binderConnector_ = nullptr;
    sptr<IRemoteObject> testStub = new IPCObjectStub(u"testStub");
    auto ret = binderInvoker.TranslateIRemoteObject(cmd, testStub);
    EXPECT_EQ(ret, -IPC_INVOKER_CONNECT_ERR);
}

/**
 * @tc.name: TranslateIRemoteObjectTest003
 * @tc.desc: Override TranslateIRemoteObject branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, TranslateIRemoteObjectTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    int32_t cmd = 1;
    BinderConnector *binderConnector = BinderConnector::GetInstance();
    binderConnector->driverFD_ = -1;
    sptr<IRemoteObject> testStub = new IPCObjectStub(u"testStub");
    auto ret = binderInvoker.TranslateIRemoteObject(cmd, testStub);
    EXPECT_EQ(ret, -IPC_INVOKER_CONNECT_ERR);
}
#endif

/**
 * @tc.name: GetSelfTokenIDTest002
 * @tc.desc: Override GetSelfTokenID branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetSelfTokenIDTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    auto ret = binderInvoker.GetSelfTokenID();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetSelfTokenIDTest003
 * @tc.desc: Override GetSelfTokenID branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetSelfTokenIDTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    BinderConnector *binderConnector = BinderConnector::GetInstance();
    binderConnector->driverFD_ = -1;
    auto ret = binderInvoker.GetSelfTokenID();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetCallerTokenIDTest003
 * @tc.desc: Override GetCallerTokenID branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetCallerTokenIDTest003, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.callerTokenID_ = 0;
    binderInvoker.callerUid_ = 1;
    auto ret = binderInvoker.GetCallerTokenID();
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: GetStrongRefCountForStubTest001
 * @tc.desc: Override GetStrongRefCountForStub branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetStrongRefCountForStubTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    uint32_t count = binderInvoker.GetStrongRefCountForStub(0);
    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: GetStrongRefCountForStubTest002
 * @tc.desc: Override GetStrongRefCountForStub branch
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetStrongRefCountForStubTest002, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    BinderConnector *binderConnector = BinderConnector::GetInstance();
    binderInvoker.binderConnector_ = binderConnector;
    uint32_t count = binderInvoker.GetStrongRefCountForStub(0);
    EXPECT_EQ(count, 0);
}
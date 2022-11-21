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
#undef protected
#undef private
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"

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
 * @tc.name: SetCallingIdentity001
 * @tc.desc: Verify the ReadFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, SetCallingIdentity001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    std::string identity;
    bool ret = binderInvoker.SetCallingIdentity(identity);
    EXPECT_EQ(ret, false);
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
 * @tc.name: GetCallerTokenID001
 * @tc.desc: Verify the GetCallerTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, GetCallerTokenID001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    binderInvoker.firstTokenID_ = 0;
    uint32_t ret = binderInvoker.GetFirstTokenID();
    EXPECT_EQ((uint64_t)ret, RpcGetFirstCallerTokenID());
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
 * @tc.name: TranslateProxyTest001
 * @tc.desc: Verify the TranslateProxy function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, TranslateProxyTest001, TestSize.Level1)
{
#ifndef CONFIG_IPC_SINGLE
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    EXPECT_EQ(binderInvoker.TranslateProxy(0, 0), -IPC_INVOKER_CONNECT_ERR);
#endif
}

/**
 * @tc.name: TranslateProxyTest002
 * @tc.desc: Verify the TranslateProxy function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, TranslateProxyTest002, TestSize.Level1)
{
#ifndef CONFIG_IPC_SINGLE
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.TranslateProxy(1, 0), -IPC_INVOKER_TRANSLATE_ERR);
#endif
}

/**
 * @tc.name: TranslateStubTest001
 * @tc.desc: Verify the TranslateStub function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, TranslateStubTest001, TestSize.Level1)
{
#ifndef CONFIG_IPC_SINGLE
    BinderInvoker binderInvoker;
    binderInvoker.binderConnector_ = nullptr;
    EXPECT_EQ(binderInvoker.TranslateStub(0, 0, 0, 0), -IPC_INVOKER_CONNECT_ERR);
#endif
}

/**
 * @tc.name: TranslateStubTest002
 * @tc.desc: Verify the TranslateStub function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, TranslateStubTest002, TestSize.Level1)
{
#ifndef CONFIG_IPC_SINGLE
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.TranslateStub(60, 90, 0, 0), -IPC_INVOKER_TRANSLATE_ERR);
#endif
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
    binderInvoker.input_.WritePointer((uintptr_t)testStub.GetRefPtr());
    binderInvoker.OnAttemptAcquire();
    EXPECT_NE(reinterpret_cast<RefCounter *>(testStub.GetRefPtr()), nullptr);
}

/**
 * @tc.name: HandleReplyTest001
 * @tc.desc: Verify the HandleReply function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleReplyTest001, TestSize.Level1)
{
    BinderInvoker binderInvoker;
    EXPECT_EQ(binderInvoker.HandleReply(nullptr), IPC_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: HandleReplyTest002
 * @tc.desc: Verify the HandleReply function
 * @tc.type: FUNC
 */
HWTEST_F(BinderInvokerUnitTest, HandleReplyTest002, TestSize.Level1)
{
    binder_transaction_data transactionData;
    BinderInvoker binderInvoker;
    binderInvoker.input_.WriteBuffer(&transactionData, sizeof(binder_transaction_data));
    EXPECT_EQ(binderInvoker.HandleReply(nullptr), IPC_INVOKER_INVALID_REPLY_ERR);
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
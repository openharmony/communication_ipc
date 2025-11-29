/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

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
#include "dbinder_session_object.h"
#include "message_option.h"
#include "mock_iremote_invoker.h"
#undef protected
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class IPCSkeletonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void IPCSkeletonTest::SetUpTestCase()
{
}

void IPCSkeletonTest::TearDownTestCase()
{
}

void IPCSkeletonTest::SetUp()
{
}

void IPCSkeletonTest::TearDown()
{
}

/**
 * @tc.name: JoinWorkThreadTest001
 * @tc.desc: Verify the JoinWorkThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, JoinWorkThreadTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    skeleton.JoinWorkThread();
    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    delete invoker;
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

/**
 * @tc.name: StopWorkThreadTest001
 * @tc.desc: Verify the StopWorkThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, StopWorkThreadTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    skeleton.StopWorkThread();
    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingSidTest001
 * @tc.desc: Verify the GetCallingSidTest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingSidTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, GetCallerSid())
        .WillRepeatedly(testing::Return(""));

    auto result = skeleton.GetCallingSid();
    EXPECT_EQ(result, "");
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingTokenIDTest001
 * @tc.desc: Verify the GetCallingTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingTokenIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*invoker, GetCallerTokenID())
        .WillRepeatedly(testing::Return(1));

    auto result = skeleton.GetCallingTokenID();
    EXPECT_EQ(result, 1);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingFullTokenIDTest001
 * @tc.desc: Verify the GetCallingFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingFullTokenIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*invoker, GetCallerTokenID())
        .WillRepeatedly(testing::Return(1));
    EXPECT_CALL(*invoker, GetSelfTokenID())
        .WillRepeatedly(testing::Return(1));

    auto result = skeleton.GetCallingFullTokenID();
    EXPECT_EQ(result, 1);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetFirstTokenIDTest001
 * @tc.desc: Verify the GetFirstTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstTokenIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;

    auto result = skeleton.GetFirstTokenID();
    EXPECT_EQ(result, 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

/**
 * @tc.name: GetFirstFullTokenIDTest001
 * @tc.desc: Verify the GetFirstFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;

    auto result = skeleton.GetFirstFullTokenID();
    EXPECT_EQ(result, 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

/**
 * @tc.name: GetFirstFullTokenIDTest002
 * @tc.desc: Verify the GetFirstFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenIDTest002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*invoker, GetCallerTokenID())
        .WillRepeatedly(testing::Return(1));
    EXPECT_CALL(*invoker, GetFirstCallerTokenID())
        .WillRepeatedly(testing::Return(1));

    auto result = skeleton.GetFirstFullTokenID();
    EXPECT_EQ(result, 1);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetFirstFullTokenIDTest003
 * @tc.desc: Verify the GetFirstFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenIDTest003, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = nullptr;

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*invoker, GetFirstCallerTokenID())
        .WillRepeatedly(testing::Return(123));

    EXPECT_CALL(*invoker, GetSelfFirstCallerTokenID())
        .WillRepeatedly(testing::Return(111));

    auto result = skeleton.GetFirstFullTokenID();
    EXPECT_EQ(result, 111);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetLocalDeviceIDTest001
 * @tc.desc: Verify the GetLocalDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetLocalDeviceIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    std::string testID = "testID";
    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, GetLocalDeviceID())
        .WillRepeatedly(testing::Return(testID));

    auto result = skeleton.GetLocalDeviceID();
    EXPECT_STREQ(result.c_str(), testID.c_str());
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingDeviceIDTest001
 * @tc.desc: Verify the GetCallingDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingDeviceIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    std::string testDeviceID = "testDeviceID";
    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, GetCallerDeviceID())
        .WillRepeatedly(testing::Return(testDeviceID));

    auto result = skeleton.GetCallingDeviceID();
    EXPECT_STREQ(result.c_str(), testDeviceID.c_str());
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: IsLocalCallingTest001
 * @tc.desc: Verify the IsLocalCalling function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, IsLocalCallingTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));

    auto result = skeleton.IsLocalCalling();
    ASSERT_TRUE(!result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: FlushCommandsTest001
 * @tc.desc: Verify the FlushCommands function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, FlushCommandsTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, FlushCommands(testing::_))
        .WillRepeatedly(testing::Return(111));

    IPCObjectProxy *object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->proto_ = IRemoteObject::IF_PROT_BINDER;

    auto result = skeleton.FlushCommands(object);
    EXPECT_EQ(result, 111);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
    delete object;
}

/**
 * @tc.name: ResetCallingIdentityTest001
 * @tc.desc: Verify the ResetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, ResetCallingIdentityTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    std::string testStr = "testStr";
    EXPECT_CALL(*invoker, ResetCallingIdentity())
        .WillRepeatedly(testing::Return(testStr));

    auto result = skeleton.ResetCallingIdentity();
    EXPECT_STREQ(result.c_str(), testStr.c_str());
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: ResetCallingIdentityTest002
 * @tc.desc: Verify the ResetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, ResetCallingIdentityTest002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    std::string testStr = "";

    auto result = skeleton.ResetCallingIdentity();
    EXPECT_STREQ(result.c_str(), testStr.c_str());
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: SetCallingIdentityTest001
 * @tc.desc: Verify the SetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetCallingIdentityTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    std::string testStr = "testStr";
    EXPECT_CALL(*invoker, SetCallingIdentity(testStr, false))
        .WillRepeatedly(testing::Return(false));

    auto result = skeleton.SetCallingIdentity(testStr);
    ASSERT_TRUE(!result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: SetCallingIdentityTest002
 * @tc.desc: Verify the SetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetCallingIdentityTest002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    std::string testStr = "";

    auto result = skeleton.SetCallingIdentity(testStr);
    ASSERT_TRUE(result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: TriggerThreadReclaim001
 * @tc.desc: Verify the TriggerSystemIPCThreadReclaim function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, TriggerThreadReclaim001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, TriggerSystemIPCThreadReclaim())
        .WillRepeatedly(testing::Return(true));

    auto result = skeleton.TriggerSystemIPCThreadReclaim();
    ASSERT_TRUE(result);

    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: EnableIPCThreadReclaim001
 * @tc.desc: Verify the EnableIPCThreadReclaim function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, EnableIPCThreadReclaim001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, EnableIPCThreadReclaim(false))
        .WillRepeatedly(testing::Return(true));

    auto result = skeleton.EnableIPCThreadReclaim(false);
    ASSERT_TRUE(result);

    EXPECT_CALL(*invoker, EnableIPCThreadReclaim(true))
        .WillRepeatedly(testing::Return(true));

    result = skeleton.EnableIPCThreadReclaim(true);
    ASSERT_TRUE(result);

    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingUidInRPC
 * @tc.desc: Verify the GetCallingUid function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingUidInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    pid_t uid = IPCSkeleton::GetCallingUid();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(uid, -1);
}

/**
 * @tc.name: GetCallingPidInRPC
 * @tc.desc: Verify the GetCallingPid function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingPidInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    pid_t pid = IPCSkeleton::GetCallingPid();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(pid, -1);
}

/**
 * @tc.name: GetCallingRealPidInRPC
 * @tc.desc: Verify the GetCallingRealPid function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingRealPidInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    pid_t pid = IPCSkeleton::GetCallingRealPid();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(pid, -1);
}

/**
 * @tc.name: GetCallingTokenIDInRPC
 * @tc.desc: Verify the GetCallingTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetCallingFullTokenIDInRPC
 * @tc.desc: Verify the GetCallingFullTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingFullTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    uint64_t tokenId = IPCSkeleton::GetCallingFullTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetFirstTokenIDInRPC
 * @tc.desc: Verify the GetFirstTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    uint32_t tokenId = IPCSkeleton::GetFirstTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetFirstFullTokenIDInRPC
 * @tc.desc: Verify the GetFirstFullTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    uint64_t tokenId = IPCSkeleton::GetFirstFullTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetDCallingTokenIDInIPC
 * @tc.desc: Verify the GetDCallingTokenID function in IPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetDCallingTokenIDInIPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*binderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    uint32_t tokenId = IPCSkeleton::GetDCallingTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetDCallingTokenIDInRPC
 * @tc.desc: Verify the GetDCallingTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetDCallingTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));

    // The initial value of DBinderDatabusInvoker's callerTokenID_ is 0
    uint32_t tokenId = IPCSkeleton::GetDCallingTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

#ifdef FREEZE_PROCESS_ENABLED
/**
 * @tc.name: FreezeProcessTest
 * @tc.desc: Verify the Freeze function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, FreezeProcessTest, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;

    EXPECT_CALL(*binderInvoker, Freeze(_, _, _))
        .WillRepeatedly(testing::Return(ERR_NONE));

    ASSERT_EQ(IPCSkeleton::Freeze(0, true, 0), ERR_NONE);
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;
    delete binderInvoker;
}

/**
 * @tc.name: CheckFreezeTest
 * @tc.desc: Verify the GetProcessFreezeInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, CheckFreezeTest, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;

    EXPECT_CALL(*binderInvoker, GetProcessFreezeInfo(_, _))
        .WillRepeatedly(testing::Return(ERR_NONE));

    bool isFrozen = false;
    ASSERT_EQ(IPCSkeleton::GetProcessFreezeInfo(0, isFrozen), ERR_NONE);
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;
    delete binderInvoker;
}
#endif // FREEZE_PROCESS_ENABLED
} // namespace OHOS
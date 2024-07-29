/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

using namespace testing::ext;
using namespace OHOS;

class IPCSkeletonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
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

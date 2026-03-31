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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>

#include "ffrt.h"
#include "ipc_thread_skeleton.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
constexpr int32_t ZERO = 0;
constexpr uint32_t INVOKER_IDLE_EXCEPTION = 0xA5A5A5AC;
constexpr int32_t SEND_REQUEST_COUNT_PLUS = 0x1;
constexpr int32_t SEND_REQUEST_COUNT_NEGATIVE = -0x1;
constexpr int PROTO_NEGATIVE = -1;
constexpr int PROTO_POSITIVE = 1;
constexpr int GREATER_INVOKER_MAX_COUNT = 3;
const std::string THREAD_NAME_TEST = "test_thread_name";

class IPCThreadSkeletonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void IPCThreadSkeletonTest::SetUpTestCase()
{
}

void IPCThreadSkeletonTest::TearDownTestCase()
{
}

void IPCThreadSkeletonTest::SetUp()
{
}

void IPCThreadSkeletonTest::TearDown()
{
}

/**
 * @tc.name: GetRemoteInvokerTest001
 * @tc.desc: Verify the GetRemoteInvoker function when proto is negative number
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, GetRemoteInvokerTest001, TestSize.Level1)
{
    IRemoteInvoker* invoker = IPCThreadSkeleton::GetRemoteInvoker(PROTO_NEGATIVE);
    EXPECT_EQ(invoker, nullptr);
}

/**
 * @tc.name: GetRemoteInvokerTest002
 * @tc.desc: Verify the GetRemoteInvoker function when proto is Greater than 2
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, GetRemoteInvokerTest002, TestSize.Level1)
{
    IRemoteInvoker* invoker = IPCThreadSkeleton::GetRemoteInvoker(GREATER_INVOKER_MAX_COUNT);
    EXPECT_EQ(invoker, nullptr);
}

/**
 * @tc.name: GetRemoteInvokerTest003
 * @tc.desc: Verify the GetRemoteInvoker function when proto is positive number but GetCurrent return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, GetRemoteInvokerTest003, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    current->exitFlag_ = INVOKER_IDLE_EXCEPTION;
    IRemoteInvoker* invoker = IPCThreadSkeleton::GetRemoteInvoker(PROTO_POSITIVE);
    EXPECT_EQ(invoker, nullptr);
    current->exitFlag_ = IPCThreadSkeleton::INVOKER_USE_MAGIC;
}

/**
 * @tc.name: GetRemoteInvokerTest004
 * @tc.desc: Verify the GetRemoteInvoker function when to access invokers_[1] is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, GetRemoteInvokerTest004, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    current->invokers_[PROTO_POSITIVE] = nullptr;
    IRemoteInvoker* invoker = IPCThreadSkeleton::GetRemoteInvoker(PROTO_POSITIVE);
    EXPECT_NE(invoker, nullptr);
}

/**
 * @tc.name: GetRemoteInvokerTest005
 * @tc.desc: Verify the GetRemoteInvoker function when proto is positive number
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, GetRemoteInvokerTest005, TestSize.Level1)
{
    IRemoteInvoker* invoker = IPCThreadSkeleton::GetRemoteInvoker(PROTO_POSITIVE);
    EXPECT_NE(invoker, nullptr);
}

/**
 * @tc.name: IsInstanceExceptionTest001
 * @tc.desc: Verify the IsInstanceException function when the input parameter is INVOKER_USE_MAGIC
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, IsInstanceExceptionTest001, TestSize.Level1)
{
    std::atomic<uint32_t> atomicFlag(IPCThreadSkeleton::INVOKER_USE_MAGIC);
    bool statue = IPCThreadSkeleton::IsInstanceException(atomicFlag);
    EXPECT_FALSE(statue);
}

/**
 * @tc.name: IsInstanceExceptionTest002
 * @tc.desc: Verify the IsInstanceException function when the input parameter is INVOKER_IDLE_MAGIC
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, IsInstanceExceptionTest002, TestSize.Level1)
{
    std::atomic<uint32_t> atomicFlag(IPCThreadSkeleton::INVOKER_IDLE_MAGIC);
    bool statue = IPCThreadSkeleton::IsInstanceException(atomicFlag);
    EXPECT_TRUE(statue);
}

/**
 * @tc.name: IsInstanceExceptionTest003
 * @tc.desc: Verify the IsInstanceException function when the input parameter is exception
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, IsInstanceExceptionTest003, TestSize.Level1)
{
    std::atomic<uint32_t> atomicFlag(INVOKER_IDLE_EXCEPTION);
    bool statue = IPCThreadSkeleton::IsInstanceException(atomicFlag);
    EXPECT_TRUE(statue);
}

/**
 * @tc.name: IsSendRequestingTest001
 * @tc.desc: Verify the IsSendRequesting function when sendRequestCount is positive number
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, IsSendRequestingTest001, TestSize.Level1)
{
    IPCThreadSkeleton skeleton;
    skeleton.sendRequestCount_ = SEND_REQUEST_COUNT_PLUS;
    bool statue = skeleton.IsSendRequesting();
    EXPECT_TRUE(statue);
}

/**
 * @tc.name: IsSendRequestingTest002
 * @tc.desc: Verify the IsSendRequesting function when sendRequestCount is negative number
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, IsSendRequestingTest002, TestSize.Level1)
{
    IPCThreadSkeleton skeleton;
    skeleton.sendRequestCount_ = SEND_REQUEST_COUNT_NEGATIVE;
    bool statue = skeleton.IsSendRequesting();
    EXPECT_FALSE(statue);
    skeleton.sendRequestCount_ = ZERO;
    statue = skeleton.IsSendRequesting();
    EXPECT_FALSE(statue);
}

/**
 * @tc.name: SetThreadTypeTest001
 * @tc.desc: Verify the SetThreadType function when GetCurrent return null
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, SetThreadTypeTest001, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->exitFlag_ = INVOKER_IDLE_EXCEPTION;
    bool result = IPCThreadSkeleton::SetThreadType(ThreadType::IPC_THREAD);
    EXPECT_FALSE(result);
    current->exitFlag_ = IPCThreadSkeleton::INVOKER_USE_MAGIC;
}

/**
 * @tc.name: SetThreadTypeTest002
 * @tc.desc: Verify the SetThreadType function set IPC_THREAD
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, SetThreadTypeTest002, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    bool result = IPCThreadSkeleton::SetThreadType(ThreadType::IPC_THREAD);
    EXPECT_NE(current, nullptr);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SetThreadTypeTest003
 * @tc.desc: Verify the SetThreadType function set NORMAL_THREAD
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, SetThreadTypeTest003, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    bool result = IPCThreadSkeleton::SetThreadType(ThreadType::NORMAL_THREAD);
    EXPECT_NE(current, nullptr);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetVaildInstanceTest001
 * @tc.desc: Verify the GetVaildInstance function when tid != instance->tid_ && taskId != instance->ffrtTaskId_
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, GetVaildInstanceTest001, TestSize.Level1)
{
    IPCThreadSkeleton *skeleton = IPCThreadSkeleton::GetCurrent();
    auto tid = gettid() + 1;
    auto taskId = ffrt_this_task_get_id() + 1;
    pid_t &tidSkeleton = const_cast<pid_t&>(skeleton->tid_);
    tidSkeleton = tid;
    skeleton->ffrtTaskId_ = taskId;
    ASSERT_NO_FATAL_FAILURE(IPCThreadSkeleton::GetVaildInstance(skeleton));
    tidSkeleton = gettid();
    skeleton->ffrtTaskId_ = ffrt_this_task_get_id();
}

/**
 * @tc.name: GetVaildInstanceTest002
 * @tc.desc: Verify the GetVaildInstance function when tid == instance->tid_ and taskId == instance->ffrtTaskId_
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, GetVaildInstanceTest002, TestSize.Level1)
{
    IPCThreadSkeleton *skeleton = IPCThreadSkeleton::GetCurrent();
    auto tid = gettid();
    auto taskId = ffrt_this_task_get_id();
    pid_t &tidSkeleton = const_cast<pid_t&>(skeleton->tid_);
    tidSkeleton = tid;
    skeleton->ffrtTaskId_ = taskId;
    ASSERT_NO_FATAL_FAILURE(IPCThreadSkeleton::GetVaildInstance(skeleton));
}

/**
 * @tc.name: GetVaildInstanceTest003
 * @tc.desc: Verify the GetVaildInstance function when instance is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, GetVaildInstanceTest003, TestSize.Level1)
{
    IPCThreadSkeleton* ptr = nullptr;
    ASSERT_NO_FATAL_FAILURE(IPCThreadSkeleton::GetVaildInstance(ptr));
}

/**
 * @tc.name: SaveThreadNameTest001
 * @tc.desc: Verify the SaveThreadName function use GetCurrent
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonTest, SaveThreadNameTest001, TestSize.Level1)
{
    IPCThreadSkeleton *skeleton = IPCThreadSkeleton::GetCurrent();
    skeleton->exitFlag_ = INVOKER_IDLE_EXCEPTION;
    ASSERT_NO_FATAL_FAILURE(IPCThreadSkeleton::SaveThreadName(THREAD_NAME_TEST));
}

/**
 * @tc.name: RemoveDeathRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function when recipient nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    bool ret = object.RemoveDeathRecipient(nullptr);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: RemoveDeathRecipientTest002
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function when IsObjectDead return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    object.SetObjectDied(true);
    bool ret = object.RemoveDeathRecipient(death.GetRefPtr());
    object.SetObjectDied(false);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: RemoveDeathRecipientTest003
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function when handle_ >= DBINDER_HANDLE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    uint32_t tmp = object.handle_;
    object.handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE;
    object.AddDeathRecipient(death.GetRefPtr());
    bool ret = object.RemoveDeathRecipient(death.GetRefPtr());
    object.handle_ = tmp;
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: AddRefreshRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::AddRefreshRecipient function when recipient nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddRefreshRecipientTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    bool ret = object.AddRefreshRecipient(nullptr);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: AddRefreshRecipientTest002
 * @tc.desc: Verify the IPCObjectProxy::AddRefreshRecipient function when IsObjectDead return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddRefreshRecipientTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::RefreshRecipient> refresh(new MockRefreshRecipient());
    object.SetObjectDied(true);
    bool ret = object.AddRefreshRecipient(refresh.GetRefPtr());
    object.SetObjectDied(false);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: AddRefreshRecipientTest003
 * @tc.desc: Verify the IPCObjectProxy::AddRefreshRecipient function when IsObjectDead return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddRefreshRecipientTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::RefreshRecipient> recipient1 = new MockRefreshRecipient();
    ASSERT_NE(recipient1, nullptr);
    EXPECT_FALSE(object.AddRefreshRecipient(recipient1));
}

/**
 * @tc.name: AddRefreshRecipientTest004
 * @tc.desc: Verify the IPCObjectProxy::AddRefreshRecipient function when recipients_.size() > 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddRefreshRecipientTest004, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    ASSERT_NE(death, nullptr);
    
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, RegisterBinderDeathRecipient()).WillOnce(Return(true));
    EXPECT_CALL(mock, RegisterBinderRefreshRecipient()).WillOnce(Return(true));
    EXPECT_TRUE(object.AddDeathRecipient(death));
    sptr<IRemoteObject::RefreshRecipient> recipient1 = new MockRefreshRecipient();
    ASSERT_NE(recipient1, nullptr);
    EXPECT_TRUE(object.AddRefreshRecipient(recipient1));
    sptr<IRemoteObject::RefreshRecipient> recipient2 = new MockRefreshRecipient();
    ASSERT_NE(recipient2, nullptr);
    EXPECT_TRUE(object.AddRefreshRecipient(recipient2));
}

/**
 * @tc.name: AddRefreshRecipientTest005
 * @tc.desc: Verify the IPCObjectProxy::AddRefreshRecipient function when handle_ >= DBINDER_HANDLE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddRefreshRecipientTest005, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    object.handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE;
    bool ret = object.AddDeathRecipient(death.GetRefPtr());
    ASSERT_EQ(ret, true);
    sptr<IRemoteObject::RefreshRecipient> refresh(new MockRefreshRecipient());
    ret = object.AddRefreshRecipient(refresh.GetRefPtr());
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: AddRefreshRecipientTest006
 * @tc.desc: Verify the IPCObjectProxy::AddRefreshRecipient function when RegisterBinderDeathRecipient return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddRefreshRecipientTest006, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_DATABUS;
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, RegisterBinderDeathRecipient()).WillOnce(Return(true));
    bool ret = object.AddDeathRecipient(death.GetRefPtr());
    ASSERT_EQ(ret, true);
    sptr<IRemoteObject::RefreshRecipient> refresh(new MockRefreshRecipient());
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(testing::Return(nullptr));
    EXPECT_CALL(mock, RegisterBinderRefreshRecipient()).WillOnce(Return(true));
    ret = object.AddRefreshRecipient(refresh.GetRefPtr());
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: RemoveRefreshRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::RemoveRefreshRecipient function when recipient nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveRefreshRecipientTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    bool ret = object.RemoveRefreshRecipient(nullptr);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: RemoveRefreshRecipientTest002
 * @tc.desc: Verify the IPCObjectProxy::RemoveRefreshRecipient function when IsObjectDead return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveRefreshRecipientTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::RefreshRecipient> refresh(new MockRefreshRecipient());
    object.SetObjectDied(true);
    bool ret = object.RemoveRefreshRecipient(refresh.GetRefPtr());
    object.SetObjectDied(false);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: RemoveRefreshRecipientTest003
 * @tc.desc: Verify the IPCObjectProxy::RemoveRefreshRecipient function when handle_ >= DBINDER_HANDLE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveRefreshRecipientTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    object.handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE;
    bool ret = object.AddDeathRecipient(death.GetRefPtr());
    ASSERT_EQ(ret, true);
    sptr<IRemoteObject::RefreshRecipient> refresh(new MockRefreshRecipient());
    uint32_t tmp = object.handle_;
    object.AddRefreshRecipient(refresh.GetRefPtr());
    ret = object.RemoveRefreshRecipient(refresh.GetRefPtr());
    object.handle_ = tmp;

    ASSERT_TRUE(ret);
}

/**
 * @tc.name: ClearRefreshRecipientsTest001
 * @tc.desc: Verify the IPCObjectProxy::ClearRefreshRecipients function
 * when refreshRecipients_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, ClearRefreshRecipientsTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    EXPECT_NO_FATAL_FAILURE(object.ClearRefreshRecipients());
}

/**
 * @tc.name: ClearRefreshRecipientsTest002
 * @tc.desc: Verify the IPCObjectProxy::ClearRefreshRecipients function
 * when handle_ >= DBINDER_HANDLE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, ClearRefreshRecipientsTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_DATABUS;
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, RegisterBinderDeathRecipient()).WillOnce(Return(true));
    bool ret = object.AddDeathRecipient(death.GetRefPtr());
    ASSERT_EQ(ret, true);
    sptr<IRemoteObject::RefreshRecipient> refresh(new MockRefreshRecipient());
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(testing::Return(nullptr));
    EXPECT_CALL(mock, RegisterBinderRefreshRecipient()).WillOnce(Return(true));
    ret = object.AddRefreshRecipient(refresh.GetRefPtr());
    ASSERT_EQ(ret, true);

    object.handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE;
    EXPECT_NO_FATAL_FAILURE(object.ClearRefreshRecipients());
}

/**
 * @tc.name: ClearRefreshRecipientsTest003
 * @tc.desc: Verify the IPCObjectProxy::ClearRefreshRecipients function
 * when handle_ < DBINDER_HANDLE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, ClearRefreshRecipientsTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_DATABUS;
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, RegisterBinderDeathRecipient()).WillOnce(Return(true));
    bool ret = object.AddDeathRecipient(death.GetRefPtr());
    ASSERT_EQ(ret, true);
    sptr<IRemoteObject::RefreshRecipient> refresh(new MockRefreshRecipient());
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(testing::Return(nullptr));
    EXPECT_CALL(mock, RegisterBinderRefreshRecipient()).WillOnce(Return(true));
    ret = object.AddRefreshRecipient(refresh.GetRefPtr());
    ASSERT_EQ(ret, true);

    object.handle_ = IPCProcessSkeleton::DBINDER_HANDLE_RANG;
    EXPECT_NO_FATAL_FAILURE(object.ClearRefreshRecipients());
}

/**
 * @tc.name: RegisterBinderRefreshRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::RegisterBinderRefreshRecipient function
 * when IPCThreadSkeleton::GetDefaultInvoker() return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RegisterBinderRefreshRecipientTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    EXPECT_FALSE(object.RegisterBinderRefreshRecipient());
}

/**
 * @tc.name: UnRegisterBinderRefreshRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::UnRegisterBinderRefreshRecipient function
 * when IPCThreadSkeleton::GetDefaultInvoker() return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UnRegisterBinderRefreshRecipientTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    EXPECT_FALSE(object.UnRegisterBinderRefreshRecipient());
}

/**
 * @tc.name: UnRegisterBinderRefreshRecipientTest002
 * @tc.desc: Verify the IPCObjectProxy::UnRegisterBinderRefreshRecipient function
 * when RemoveRefreshRecipient return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UnRegisterBinderRefreshRecipientTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(testing::Return(invoker));
    EXPECT_CALL(*invoker, RemoveRefreshRecipient(_, _)).WillOnce(Return(false));
    EXPECT_FALSE(object.UnRegisterBinderRefreshRecipient());
    delete invoker;
}

/**
 * @tc.name: UnRegisterBinderRefreshRecipientTest003
 * @tc.desc: Verify the IPCObjectProxy::UnRegisterBinderRefreshRecipient function
 * when RemoveRefreshRecipient return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UnRegisterBinderRefreshRecipientTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(testing::Return(invoker));
    EXPECT_CALL(*invoker, RemoveRefreshRecipient(_, _)).WillOnce(Return(true));
    EXPECT_TRUE(object.UnRegisterBinderRefreshRecipient());
    delete invoker;
}

/**
 * @tc.name: RefreshRecipientAddrInfoTest001
 * @tc.desc: Verify the IPCObjectProxy::RefreshRecipientAddrInfo function
 * when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RefreshRecipientAddrInfoTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<OHOS::IRemoteObject::RefreshRecipient> nullRecipient = nullptr;
    IPCObjectProxy::RefreshRecipientAddrInfo info(nullRecipient);
    EXPECT_EQ(info.recipient_, nullptr);
}

/**
 * @tc.name: RefreshRecipientAddrInfoTest002
 * @tc.desc: Verify the IPCObjectProxy::RefreshRecipientAddrInfo function
 * when recipient is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RefreshRecipientAddrInfoTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<MockRefreshRecipient> recipient = new MockRefreshRecipient();
    IPCObjectProxy::RefreshRecipientAddrInfo info(recipient);
    EXPECT_NE(info.recipient_, nullptr);
}

/**
 * @tc.name: SendRefreshObituaryTest001
 * @tc.desc: Verify the IPCObjectProxy::SendRefreshObituary function
 * when refreshRecipients_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, SendRefreshObituaryTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    EXPECT_NO_FATAL_FAILURE(object.SendRefreshObituary());
}

/**
 * @tc.name: UpdateProtoTest001
 * @tc.desc: Verify the IPCObjectProxy::UpdateProto function when CheckHaveSession return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateProtoTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = "test";
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    auto ret = object.UpdateProto(nullptr);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UpdateProtoTest002
 * @tc.desc: Verify the IPCObjectProxy::UpdateProto function when dbinderData_ nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateProtoTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = "test";
    std::unique_ptr<uint8_t[]> temp = std::move(object.dbinderData_);
    dbinder_negotiation_data dbinderData = {
        .proto = IRemoteObject::IF_PROT_DATABUS,
        .tokenid = 0,
        .stub_index = 0,
        .target_name = "target_name",
        .local_name = "local_name",
        .target_device = "target_device",
        .local_device = "local_device",
        .desc = {},
        .reserved = {0, 0, 0}
    };

    auto ret = object.UpdateProto(&dbinderData);
    ASSERT_FALSE(ret);
    object.dbinderData_ = std::move(temp);
}

/**
 * @tc.name: UpdateProtoTest003
 * @tc.desc: Verify the IPCObjectProxy::UpdateProto function when UpdateDatabusClientSession return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateProtoTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = "test";
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(nullptr));
    dbinder_negotiation_data dbinderData = {
        .proto = IRemoteObject::IF_PROT_DATABUS,
        .tokenid = 0,
        .stub_index = 0,
        .target_name = "target_name",
        .local_name = "local_name",
        .target_device = "target_device",
        .local_device = "local_device",
        .desc = {},
        .reserved = {0, 0, 0}
    };

    auto ret = object.UpdateProto(&dbinderData);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetStrongRefCountForStubTest001
 * @tc.desc: Verify the GetStrongRefCountForStub function when invoker nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetStrongRefCountForStubTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;
    uint32_t count = object->GetStrongRefCountForStub();
    ASSERT_TRUE(count == 0);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest001
 * @tc.desc: Verify the AddDbinderDeathRecipient function when function GetCurrent nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDbinderDeathRecipientTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    auto ret = object->AddDbinderDeathRecipient();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: MakeDBinderTransSessionTest001
 * @tc.desc: Verify the MakeDBinderTransSession function when GetRemoteInvoker return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, MakeDBinderTransSessionTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));
    DBinderNegotiationData data = {
        .peerPid = 0,
        .peerUid = 0,
        .peerTokenId = 0,
        .stubIndex = 0,
        .peerServiceName = "test",
        .peerDeviceId = "test",
        .localServiceName = "test",
        .localDeviceId = "test"
    };
    auto ret = object->MakeDBinderTransSession(data);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: MakeDBinderTransSessionTest002
 * @tc.desc: Verify the MakeDBinderTransSession function when GetCurrent return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, MakeDBinderTransSessionTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    DBinderNegotiationData data = {
        .peerPid = 0,
        .peerUid = 0,
        .peerTokenId = 0,
        .stubIndex = 0,
        .peerServiceName = "test",
        .peerDeviceId = "test",
        .localServiceName = "test",
        .localDeviceId = "test"
    };
    auto ret = object->MakeDBinderTransSession(data);
    delete invoker;
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: MakeDBinderTransSessionTest003
 * @tc.desc: Verify the MakeDBinderTransSession function when peerServiceName is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, MakeDBinderTransSessionTest003, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCProcessSkeleton *current = new IPCProcessSkeleton();
    IPCThreadSkeleton *currentptr = IPCThreadSkeleton::GetCurrent();
    currentptr->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(current));
    DBinderNegotiationData data = {
        .peerPid = 0,
        .peerUid = 0,
        .peerTokenId = 0,
        .stubIndex = 0,
        .peerServiceName = "",
        .peerDeviceId = "test",
        .localServiceName = "test",
        .localDeviceId = "test"
    };
    auto ret = object->MakeDBinderTransSession(data);
    delete current;
    delete invoker;
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: MakeDBinderTransSessionTest004
 * @tc.desc: Verify the MakeDBinderTransSession function when CreateSoftbusServer return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, MakeDBinderTransSessionTest004, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCProcessSkeleton *current = new IPCProcessSkeleton();
    IPCThreadSkeleton *currentptr = IPCThreadSkeleton::GetCurrent();
    currentptr->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(current));
    EXPECT_CALL(mock, CreateSoftbusServer(testing::_)).WillOnce(Return(false));
    DBinderNegotiationData data = {
        .peerPid = 0,
        .peerUid = 0,
        .peerTokenId = 0,
        .stubIndex = 0,
        .peerServiceName = "test",
        .peerDeviceId = "test",
        .localServiceName = "test",
        .localDeviceId = "test"
    };
    auto ret = object->MakeDBinderTransSession(data);
    delete current;
    delete invoker;
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: DeathRecipientAddrInfoTest001
 * @tc.desc: Verify the DeathRecipientAddrInfo function when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, DeathRecipientAddrInfoTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<OHOS::IRemoteObject::DeathRecipient> nullRecipient = nullptr;
    IPCObjectProxy::DeathRecipientAddrInfo info(nullRecipient);
    EXPECT_EQ(info.recipient_, nullptr);
}

/**
 * @tc.name: DeathRecipientAddrInfoTest002
 * @tc.desc: Verify the DeathRecipientAddrInfo function when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, DeathRecipientAddrInfoTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<MockDeathRecipient> recipient = new MockDeathRecipient();
    IPCObjectProxy::DeathRecipientAddrInfo info(recipient);
    EXPECT_NE(info.recipient_, nullptr);
}

#ifndef __linux__
/**
 * @tc.name: PrintErrorDetailedInfoTest001
 * @tc.desc: Verify the PrintErrorDetailedInfo function when invoker is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, PrintErrorDetailedInfoTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;

    int err = BR_FAILED_REPLY;
    std::string desc = "desc";
    ASSERT_NO_FATAL_FAILURE(object.PrintErrorDetailedInfo(err, desc));
}
} // namespace OHOS
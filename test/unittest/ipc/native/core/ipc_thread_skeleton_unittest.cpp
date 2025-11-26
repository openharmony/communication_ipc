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
} // namespace OHOS
/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <cstring>
#include <securec.h>
#include "ipc_cparcel.h"
#include "ipc_cremote_object.h"
#include "ipc_cskeleton.h"
#include "ipc_test_helper.h"
#include "test_service_command.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ipc_inner_object.h"
#include "ipc_skeleton.h"
#include "ipc_error_code.h"
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
#include <iostream>
#include <thread>

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;
using namespace testing::ext;

static constexpr int MAX_MEMORY_SIZE = 204800;

class IpcCApiSkeletonUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_CAPI, "IpcCApiUnitTest" };
};

void IpcCApiSkeletonUnitTest::SetUpTestCase()
{}

void IpcCApiSkeletonUnitTest::TearDownTestCase()
{}

void IpcCApiSkeletonUnitTest::SetUp()
{}

void IpcCApiSkeletonUnitTest::TearDown()
{}

static void* LocalMemAllocator(int32_t len)
{
    if (len < 0 || len > MAX_MEMORY_SIZE) {
        return nullptr;
    }
    void *buffer = malloc(len);
    if (buffer == nullptr) {
        return nullptr;
    }
    (void)memset_s(buffer, len, 0, len);
    return buffer;
}

static void* LocalMemAllocatorErr(int32_t len)
{
    return nullptr;
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_JoinWorkThread_001, TestSize.Level1)
{
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));
    OH_IPCSkeleton_JoinWorkThread();
    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_StopWorkThread_001, TestSize.Level1)
{
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    OH_IPCSkeleton_StopWorkThread();
    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_GetCallingTokenId_001, TestSize.Level1)
{
    uint64_t tokenId = 1213;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, GetCallerTokenID())
        .WillRepeatedly(testing::Return(tokenId));
    auto result = OH_IPCSkeleton_GetCallingTokenId();

    EXPECT_EQ(result, tokenId);

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_GetFirstTokenId_001, TestSize.Level1)
{
    auto id = OH_IPCSkeleton_GetFirstTokenId();
    EXPECT_EQ(id, 0);
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_GetSelfTokenId_001, TestSize.Level1)
{
    auto id = OH_IPCSkeleton_GetSelfTokenId();
    EXPECT_GT(id, 0);
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_GetCallingPid_001, TestSize.Level1)
{
    auto id = OH_IPCSkeleton_GetCallingPid();
    EXPECT_NE(id, 0);
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_GetCallingUid_001, TestSize.Level1)
{
    auto uid = OH_IPCSkeleton_GetCallingUid();
    EXPECT_EQ(uid, 0);
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_IsLocalCalling_001, TestSize.Level1)
{
    EXPECT_EQ(OH_IPCSkeleton_IsLocalCalling(), true);
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));

    EXPECT_EQ(OH_IPCSkeleton_IsLocalCalling(), false);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_SetCallingIdentity_001, TestSize.Level1)
{
    EXPECT_NE(OH_IPCSkeleton_SetCallingIdentity(nullptr), OH_IPC_SUCCESS);

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    std::string testStr = "hello, world.";
    EXPECT_CALL(*invoker, SetCallingIdentity(testStr, false))
        .WillRepeatedly(testing::Return(true));

    auto ret = OH_IPCSkeleton_SetCallingIdentity(testStr.c_str());
    EXPECT_EQ(ret, OH_IPC_SUCCESS);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_ResetCallingIdentity_001, TestSize.Level1)
{
    char *identity = nullptr;
    int32_t len = sizeof(identity);
    EXPECT_EQ(OH_IPCSkeleton_ResetCallingIdentity(nullptr, &len, LocalMemAllocator), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCSkeleton_ResetCallingIdentity(&identity, nullptr, LocalMemAllocator), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCSkeleton_ResetCallingIdentity(&identity, &len, nullptr), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCSkeleton_ResetCallingIdentity(&identity, &len, LocalMemAllocatorErr), OH_IPC_MEM_ALLOCATOR_ERROR);

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    std::string testStr = "testStr";
    EXPECT_CALL(*invoker, ResetCallingIdentity())
        .WillRepeatedly(testing::Return(testStr));

    EXPECT_EQ(OH_IPCSkeleton_ResetCallingIdentity(&identity, &len, LocalMemAllocator), OH_IPC_SUCCESS);
    ZLOGE(LOG_LABEL, "identity is %{public}s, len is %{public}d", identity, len);
    EXPECT_STREQ(identity, testStr.c_str());
    EXPECT_EQ(len, strlen(testStr.c_str()) + 1);
    if (identity != nullptr) {
        delete identity;
    }
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_IsHandlingTransaction_001, TestSize.Level1)
{
    EXPECT_EQ(OH_IPCSkeleton_IsHandlingTransaction(), false);

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_EQ(OH_IPCSkeleton_IsHandlingTransaction(), true);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

HWTEST_F(IpcCApiSkeletonUnitTest, Skeleton_SetMaxWorkThreadNum_001, TestSize.Level1)
{
    int normalCount = 4;
    int negativeCount = -1;
    int maxCount = 33;
    EXPECT_EQ(OH_IPCSkeleton_SetMaxWorkThreadNum(normalCount), OH_IPC_SUCCESS);
    EXPECT_EQ(OH_IPCSkeleton_SetMaxWorkThreadNum(negativeCount), OH_IPC_CHECK_PARAM_ERROR);
    EXPECT_EQ(OH_IPCSkeleton_SetMaxWorkThreadNum(maxCount), OH_IPC_CHECK_PARAM_ERROR);
}
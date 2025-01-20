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

#include <algorithm>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include <securec.h>
#include <mutex>
#include <condition_variable>

#define private public
#include "ipc_cskeleton.h"
#include "ipc_error_code.h"
#include "ipc_cparcel.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "ipc_thread_skeleton.h"
#undef private

using namespace testing::ext;

static constexpr int MIN_THREAD_NUM = 1;
static constexpr int MAX_THREAD_NUM = 32;
static constexpr int MAX_MEMORY_SIZE = 204800;

using TEST_OH_IPC_MemAllocator = void* (*)(int);
testing::MockFunction<void*(int)> mockAllocator;

class MockIPCSkeleton {
public:
    MOCK_METHOD1(SetMaxWorkThreadNum, bool(int));
    MOCK_METHOD1(SetCallingIdentity, bool(const std::string&));
    MOCK_METHOD0(ResetCallingIdentity, std::string());
    MOCK_METHOD0(GetCallingFullTokenID, uint64_t());
    MOCK_METHOD0(GetFirstFullTokenID, uint64_t());
    MOCK_METHOD0(GetSelfTokenID, uint64_t());
    MOCK_METHOD0(GetCallingPid, pid_t());
    MOCK_METHOD0(GetCallingUid, pid_t());
    MOCK_METHOD0(IsLocalCalling, bool());
};

namespace OHOS {
namespace IPCSkeleton {
    MockIPCSkeleton mock;
    bool SetMaxWorkThreadNum(int maxThreadNum) {
        return mock.SetMaxWorkThreadNum(maxThreadNum);
    }
    bool SetCallingIdentity(const std::string& identity) {
        return mock.SetCallingIdentity(identity);
    }
    std::string ResetCallingIdentity() {
        return mock.ResetCallingIdentity();
    }
    uint64_t GetCallingFullTokenID() {
        return mock.GetCallingFullTokenID();
    }
    uint64_t GetFirstFullTokenID() {
        return mock.GetFirstFullTokenID();
    }
    uint64_t GetSelfTokenID() {
        return mock.GetSelfTokenID();
    }
    pid_t GetCallingPid() {
        return mock.GetCallingPid();
    }
    pid_t GetCallingUid() {
        return mock.GetCallingUid();
    }
    bool IsLocalCalling() {
        return mock.IsLocalCalling();
    }
}
}


class IPCCskeletonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCCskeletonTest::SetUpTestCase()
{
}

void IPCCskeletonTest::TearDownTestCase()
{
}

void IPCCskeletonTest::SetUp()
{
}

void IPCCskeletonTest::TearDown()
{
}

static void* CSkeletonMemAllocator(int32_t len)
{
    if (len < 0 || len > MAX_MEMORY_SIZE) {
        return nullptr;
    }
    void *buffer = malloc(len);
    if (buffer != nullptr) {
        if (memset_s(buffer, len, 0, len) != EOK) {
            return nullptr;
        }
    }
    return buffer;
}

/**
 * @tc.name:OH_IPCSkeleton_SetMaxWorkThreadNumTest001
 * @tc.desc: Verify the OH_IPCSkeleton_SetMaxWorkThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_SetMaxWorkThreadNumTest001, TestSize.Level1)
{
    int invalidThreadNum = MIN_THREAD_NUM - 1;
    int result = OH_IPCSkeleton_SetMaxWorkThreadNum(invalidThreadNum);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name:OH_IPCSkeleton_SetMaxWorkThreadNumTest002
 * @tc.desc: Verify the OH_IPCSkeleton_SetMaxWorkThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_SetMaxWorkThreadNumTest002, TestSize.Level1)
{
    int invalidThreadNum = MAX_THREAD_NUM + 1;
    int result = OH_IPCSkeleton_SetMaxWorkThreadNum(invalidThreadNum);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name:OH_IPCSkeleton_SetMaxWorkThreadNumTest003
 * @tc.desc: Verify the OH_IPCSkeleton_SetMaxWorkThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_SetMaxWorkThreadNumTest003, TestSize.Level1)
{
    int validThreadNum = (MIN_THREAD_NUM + MAX_THREAD_NUM) / 2;
    EXPECT_CALL(OHOS::IPCSkeleton::mock, SetMaxWorkThreadNum(validThreadNum))
        .WillOnce(testing::Return(true));
    int result = OH_IPCSkeleton_SetMaxWorkThreadNum(validThreadNum);
    EXPECT_EQ(result, OH_IPC_SUCCESS);
}

/**
 * @tc.name:OH_IPCSkeleton_SetMaxWorkThreadNumTest004
 * @tc.desc: Verify the OH_IPCSkeleton_SetMaxWorkThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_SetMaxWorkThreadNumTest004, TestSize.Level1)
{
    int validThreadNum = (MIN_THREAD_NUM + MAX_THREAD_NUM) / 2;
    EXPECT_CALL(OHOS::IPCSkeleton::mock, SetMaxWorkThreadNum(validThreadNum))
     .WillOnce(testing::Return(false));
    int result = OH_IPCSkeleton_SetMaxWorkThreadNum(validThreadNum);
    EXPECT_EQ(result, OH_IPC_INNER_ERROR);
}

/**
 * @tc.name: OH_IPCSkeleton_SetCallingIdentityTest001
 * @tc.desc: Verify the OH_IPCSkeleton_SetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_SetCallingIdentityTest001, TestSize.Level1)
{
    const char *invalidIdentity = nullptr;
    int result = OH_IPCSkeleton_SetCallingIdentity(invalidIdentity);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCSkeleton_SetCallingIdentityTest002
 * @tc.desc: Verify the OH_IPCSkeleton_SetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_SetCallingIdentityTest002, TestSize.Level1)
{
    const char *validIdentity = "valid_identity";
    EXPECT_CALL(OHOS::IPCSkeleton::mock, SetCallingIdentity(std::string(validIdentity)))
    .WillOnce(testing::Return(true));
    int result = OH_IPCSkeleton_SetCallingIdentity(validIdentity);
    EXPECT_EQ(result, OH_IPC_SUCCESS);
}

/**
 * @tc.name: OH_IPCSkeleton_SetCallingIdentityTest003
 * @tc.desc: Verify the OH_IPCSkeleton_SetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_SetCallingIdentityTest003, TestSize.Level1)
{
    const char *validIdentity = "valid_identity";
    EXPECT_CALL(OHOS::IPCSkeleton::mock, SetCallingIdentity(std::string(validIdentity)))
    .WillOnce(testing::Return(false));
    int result = OH_IPCSkeleton_SetCallingIdentity(validIdentity);
    EXPECT_EQ(result, OH_IPC_INNER_ERROR);
}

/**
 * @tc.name: OH_IPCSkeleton_ResetCallingIdentityTest001
 * @tc.desc: Verify the OH_IPCSkeleton_ResetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_ResetCallingIdentityTest001, TestSize.Level1) {
    char* identity = nullptr;
    int32_t len = 0;
    int result = OH_IPCSkeleton_ResetCallingIdentity(&identity, &len, CSkeletonMemAllocator);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);

    result = OH_IPCSkeleton_ResetCallingIdentity(&identity, nullptr, CSkeletonMemAllocator);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);

    result = OH_IPCSkeleton_ResetCallingIdentity(&identity, &len, nullptr);
    EXPECT_EQ(result, OH_IPC_CHECK_PARAM_ERROR);
}

/**
 * @tc.name: OH_IPCSkeleton_ResetCallingIdentityTest002
 * @tc.desc: Verify the OH_IPCSkeleton_ResetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_ResetCallingIdentityTest002, TestSize.Level1) {
    char* identity = nullptr;
    int32_t len = 0;
    EXPECT_CALL(mockAllocator, Call(testing::_))
     .WillOnce(testing::Return(nullptr));

    int result = OH_IPCSkeleton_ResetCallingIdentity(&identity, &len, CSkeletonMemAllocator);
    EXPECT_EQ(result, OH_IPC_MEM_ALLOCATOR_ERROR);
}

/**
 * @tc.name: OH_IPCSkeleton_ResetCallingIdentityTest003
 * @tc.desc: Verify the OH_IPCSkeleton_ResetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_ResetCallingIdentityTest003, TestSize.Level1) {
    char* identity = nullptr;
    int32_t len = 0;
    EXPECT_CALL(OHOS::IPCSkeleton::mock, ResetCallingIdentity())
     .WillOnce(testing::Return("test_string"));

    EXPECT_CALL(mockAllocator, Call(testing::_))
     .WillOnce(testing::Invoke([](int size) -> void* {
            char* ptr = new char[size];
            errno = EINVAL;
            return ptr;
        }));

    int result = OH_IPCSkeleton_ResetCallingIdentity(&identity, &len, CSkeletonMemAllocator);
    EXPECT_EQ(result, OH_IPC_INNER_ERROR);
    delete[] identity;
}

/**
 * @tc.name: OH_IPCSkeleton_ResetCallingIdentityTest004
 * @tc.desc: Verify the OH_IPCSkeleton_ResetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_ResetCallingIdentityTest004, TestSize.Level1) {
    char* identity = nullptr;
    int32_t len = 0;
    EXPECT_CALL(OHOS::IPCSkeleton::mock, ResetCallingIdentity())
     .WillOnce(testing::Return("test_string"));
    EXPECT_CALL(mockAllocator, Call(testing::_))
     .WillOnce(testing::Return(new char[100]));

    int result = OH_IPCSkeleton_ResetCallingIdentity(&identity, &len, CSkeletonMemAllocator);
    EXPECT_EQ(result, OH_IPC_SUCCESS);

    std::string expectedStr = "test_string";
    std::string actualStr(identity);
    EXPECT_EQ(actualStr, expectedStr);

    EXPECT_EQ(len, static_cast<int32_t>(expectedStr.length() + 1));
    delete[] identity;
}

/**
 * @tc.name: OH_IPCSkeleton_GetCallingTokenIdTest001
 * @tc.desc: Verify the OH_IPCSkeleton_GetCallingTokenId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_GetCallingTokenIdTest001, TestSize.Level1)
{
    EXPECT_CALL(OHOS::IPCSkeleton::mock, GetCallingFullTokenID())
    .WillOnce(testing::Return(9876543210));

    uint64_t result2 = OH_IPCSkeleton_GetCallingTokenId();
    EXPECT_EQ(result2, 9876543210);
}

/**
 * @tc.name: OH_IPCSkeleton_GetFirstTokenIdTest001
 * @tc.desc: Verify the OH_IPCSkeleton_GetFirstTokenId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_GetFirstTokenIdTest001, TestSize.Level1)
{
    EXPECT_CALL(OHOS::IPCSkeleton::mock, GetFirstFullTokenID())
    .WillOnce(testing::Return(9876543210));

    uint64_t result2 = OH_IPCSkeleton_GetFirstTokenId();
    EXPECT_EQ(result2, 9876543210);
}

/**
 * @tc.name: OH_IPCSkeleton_GetSelfTokenIdTest001
 * @tc.desc: Verify the OH_IPCSkeleton_GetSelfTokenId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_GetSelfTokenIdTest001, TestSize.Level1)
{
    EXPECT_CALL(OHOS::IPCSkeleton::mock, GetSelfTokenID())
    .WillOnce(testing::Return(9876543210));

    uint64_t result2 = OH_IPCSkeleton_GetSelfTokenId();
    EXPECT_EQ(result2, 9876543210);
}

/**
 * @tc.name: OH_IPCSkeleton_GetCallingPidTest001
 * @tc.desc: Verify the OH_IPCSkeleton_GetCallingPid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_GetCallingPidTest001, TestSize.Level1)
{
    EXPECT_CALL(OHOS::IPCSkeleton::mock, GetCallingPid())
    .WillOnce(testing::Return(9876543210));

    uint64_t result2 = OH_IPCSkeleton_GetCallingPid();
    EXPECT_EQ(result2, 9876543210);
}

/**
 * @tc.name: OH_IPCSkeleton_GetCallingUidTest001
 * @tc.desc: Verify the OH_IPCSkeleton_GetCallingUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_GetCallingUidTest001, TestSize.Level1)
{
    EXPECT_CALL(OHOS::IPCSkeleton::mock, GetCallingUid())
   .WillOnce(testing::Return(1234));
    uint64_t result1 = OH_IPCSkeleton_GetCallingUid();
    EXPECT_EQ(result1, static_cast<uint64_t>(1234));
}

/**
 * @tc.name: OH_IPCSkeleton_IsLocalCallingTest001
 * @tc.desc: Verify the OH_IPCSkeleton_IsLocalCalling function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_IsLocalCallingTest001, TestSize.Level1)
{
    EXPECT_CALL(OHOS::IPCSkeleton::mock, IsLocalCalling())
    .WillOnce(testing::Return(true));

    int result = OH_IPCSkeleton_IsLocalCalling();
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: OH_IPCSkeleton_IsLocalCallingTest002
 * @tc.desc: Verify the OH_IPCSkeleton_IsLocalCalling function
 * @tc.type: FUNC
 */
HWTEST_F(IPCCskeletonTest, OH_IPCSkeleton_IsLocalCallingTest002, TestSize.Level1)
{
    EXPECT_CALL(OHOS::IPCSkeleton::mock, IsLocalCalling())
    .WillOnce(testing::Return(false));

    int result = OH_IPCSkeleton_IsLocalCalling();
    EXPECT_EQ(result, 0);
}

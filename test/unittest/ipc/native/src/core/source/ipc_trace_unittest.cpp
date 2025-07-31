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

#include <dlfcn.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ipc_trace.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {

namespace {
const std::string VALUE_TEST = "value";
const int32_t TASK_ID_TEST = 1;
}

class IPCTraceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCTraceTest::SetUpTestCase()
{
}

void IPCTraceTest::TearDownTestCase()
{
}

void IPCTraceTest::SetUp()
{
}

void IPCTraceTest::TearDown()
{
}

/**
 * @tc.name: IsEnabled001
 * @tc.desc: Verify the IsEnabled function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceTest, IsEnabled001, TestSize.Level1)
{
    IPCTrace &instance = IPCTrace::GetInstance();
    instance.isTagEnabledFunc_ = nullptr;
    EXPECT_FALSE(instance.IsEnabled());
}

/**
 * @tc.name: Start001
 * @tc.desc: Verify the Start function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceTest, Start001, TestSize.Level1)
{
    IPCTrace &instance = IPCTrace::GetInstance();
    EXPECT_NE(instance.startFunc_, nullptr);
    instance.startFunc_ = nullptr;
    instance.Start(VALUE_TEST);
    EXPECT_EQ(instance.startFunc_, nullptr);
}

/**
 * @tc.name: Finish001
 * @tc.desc: Verify the Finish function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceTest, Finish001, TestSize.Level1)
{
    IPCTrace &instance = IPCTrace::GetInstance();
    EXPECT_NE(instance.finishFunc_, nullptr);
    instance.finishFunc_ = nullptr;
    instance.Finish();
    EXPECT_EQ(instance.finishFunc_, nullptr);
}

/**
 * @tc.name: StartAsync001
 * @tc.desc: Verify the StartAsync function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceTest, StartAsync001, TestSize.Level1)
{
    IPCTrace &instance = IPCTrace::GetInstance();
    EXPECT_NE(instance.startAsyncFunc_, nullptr);
    instance.startAsyncFunc_ = nullptr;
    instance.StartAsync(VALUE_TEST, TASK_ID_TEST);
    EXPECT_EQ(instance.startAsyncFunc_, nullptr);
}

/**
 * @tc.name: FinishAsync001
 * @tc.desc: Verify the FinishAsync function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceTest, FinishAsync001, TestSize.Level1)
{
    IPCTrace &instance = IPCTrace::GetInstance();
    EXPECT_NE(instance.finishAsyncFunc_, nullptr);
    instance.finishAsyncFunc_ = nullptr;
    instance.FinishAsync(VALUE_TEST, TASK_ID_TEST);
    EXPECT_EQ(instance.finishAsyncFunc_, nullptr);
}

/**
 * @tc.name: Unload001
 * @tc.desc: Verify the Unload function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceTest, Unload001, TestSize.Level1)
{
    IPCTrace &instance = IPCTrace::GetInstance();
    EXPECT_NE(instance.traceSoHandler_, nullptr);
    dlclose(instance.traceSoHandler_);
    instance.Unload();
    EXPECT_EQ(instance.traceSoHandler_, nullptr);
}
} // namespace OHOS
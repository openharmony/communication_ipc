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

#include <gtest/gtest.h>
#define private public
#include "ipc_trace.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class IPCTraceUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() const {}
    void TearDown() const {}
};

/**
 * @tc.name: IPCTraceUnitTest001
 * @tc.desc: Verify the IPCTrace::Start and IPCTrace::Finish function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceUnitTest, IPCTraceUnitTest001, TestSize.Level1)
{
    IPCTrace::Start("1");
    IPCTrace::Finish();

    ASSERT_NE(IPCTrace::GetInstance().traceSoHandler_, nullptr);
    ASSERT_NE(IPCTrace::GetInstance().startFunc_, nullptr);
    ASSERT_NE(IPCTrace::GetInstance().finishFunc_, nullptr);
    ASSERT_NE(IPCTrace::GetInstance().startAsyncFunc_, nullptr);
    ASSERT_NE(IPCTrace::GetInstance().finishAsyncFunc_, nullptr);
}

/**
 * @tc.name: IPCTraceUnitTest002
 * @tc.desc: Verify the IPCTrace::StartAsync and IPCTrace::FinishAsync function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceUnitTest, IPCTraceUnitTest002, TestSize.Level1)
{
    IPCTrace::StartAsync("1", 1);
    IPCTrace::FinishAsync("1", 1);

    ASSERT_NE(IPCTrace::GetInstance().traceSoHandler_, nullptr);
    ASSERT_NE(IPCTrace::GetInstance().startFunc_, nullptr);
    ASSERT_NE(IPCTrace::GetInstance().finishFunc_, nullptr);
    ASSERT_NE(IPCTrace::GetInstance().startAsyncFunc_, nullptr);
    ASSERT_NE(IPCTrace::GetInstance().finishAsyncFunc_, nullptr);
}

/**
 * @tc.name: IPCTraceUnitTest003
 * @tc.desc: Verify the Unload function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceUnitTest, IPCTraceUnitTest003, TestSize.Level1)
{
    IPCTrace::GetInstance().Unload();

    EXPECT_EQ(IPCTrace::GetInstance().traceSoHandler_, nullptr);
    EXPECT_EQ(IPCTrace::GetInstance().startFunc_, nullptr);
    EXPECT_EQ(IPCTrace::GetInstance().finishFunc_, nullptr);
    EXPECT_EQ(IPCTrace::GetInstance().startAsyncFunc_, nullptr);
    EXPECT_EQ(IPCTrace::GetInstance().finishAsyncFunc_, nullptr);
}

/**
 * @tc.name: IPCTraceUnitTest004
 * @tc.desc: Verify the Load function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceUnitTest, IPCTraceUnitTest004, TestSize.Level1)
{
    IPCTrace::GetInstance().Load();

    EXPECT_NE(IPCTrace::GetInstance().traceSoHandler_, nullptr);
    EXPECT_NE(IPCTrace::GetInstance().startFunc_, nullptr);
    EXPECT_NE(IPCTrace::GetInstance().finishFunc_, nullptr);
    EXPECT_NE(IPCTrace::GetInstance().startAsyncFunc_, nullptr);
    EXPECT_NE(IPCTrace::GetInstance().finishAsyncFunc_, nullptr);
}

/**
 * @tc.name: IPCTraceUnitTest005
 * @tc.desc: Verify the IsEnabled function
 * @tc.type: FUNC
 */
HWTEST_F(IPCTraceUnitTest, IPCTraceUnitTest005, TestSize.Level1)
{
    bool isEnable = IPCTrace::IsEnabled();
    EXPECT_FALSE(isEnable);
}
} // namespace OHOS
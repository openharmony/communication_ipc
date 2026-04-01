/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "message_option.h"

using namespace testing::ext;

namespace OHOS {
namespace {
constexpr int MAX_WAIT_TIME = 3000;
}

class MessageOptionUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ConstructorTest001
 * @tc.desc: Verify constructor preserves composite flags
 * @tc.type: FUNC
 */
HWTEST_F(MessageOptionUnitTest, ConstructorTest001, TestSize.Level1)
{
    MessageOption option(MessageOption::TF_ASYNC | MessageOption::TF_STATUS_CODE | MessageOption::TF_IMAGE, 1);

    EXPECT_EQ(option.GetFlags(), MessageOption::TF_ASYNC | MessageOption::TF_STATUS_CODE | MessageOption::TF_IMAGE);
    EXPECT_EQ(option.GetWaitTime(), 1);
}

/**
 * @tc.name: SetFlagsTest001
 * @tc.desc: Verify SetFlags preserves existing bits when appending status code
 * @tc.type: FUNC
 */
HWTEST_F(MessageOptionUnitTest, SetFlagsTest001, TestSize.Level1)
{
    MessageOption option(MessageOption::TF_ACCEPT_FDS);
    option.SetFlags(MessageOption::TF_STATUS_CODE);

    EXPECT_EQ(option.GetFlags(), MessageOption::TF_ACCEPT_FDS | MessageOption::TF_STATUS_CODE);
}

/**
 * @tc.name: SetWaitTimeTest001
 * @tc.desc: Verify max wait time is preserved without clamping
 * @tc.type: FUNC
 */
HWTEST_F(MessageOptionUnitTest, SetWaitTimeTest001, TestSize.Level1)
{
    MessageOption option;
    option.SetWaitTime(MAX_WAIT_TIME);

    EXPECT_EQ(option.GetWaitTime(), MAX_WAIT_TIME);
}

/**
 * @tc.name: SetWaitTimeTest002
 * @tc.desc: Verify negative wait time falls back to default
 * @tc.type: FUNC
 */
HWTEST_F(MessageOptionUnitTest, SetWaitTimeTest002, TestSize.Level1)
{
    MessageOption option(MessageOption::TF_SYNC, 123);
    option.SetWaitTime(-100);

    EXPECT_EQ(option.GetWaitTime(), MessageOption::TF_WAIT_TIME);
}
} // namespace OHOS

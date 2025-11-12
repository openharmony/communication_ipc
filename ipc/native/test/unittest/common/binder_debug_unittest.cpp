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
#include <gtest/gtest.h>
#include "binder_debug.h"
#include "sys_binder.h"
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class BinderDebugUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void BinderDebugUnitTest::SetUpTestCase()
{}

void BinderDebugUnitTest::TearDownTestCase()
{}

void BinderDebugUnitTest::SetUp() const
{}

void BinderDebugUnitTest::TearDown() const
{}

/**
 * @tc.name: ToStringTest001
 * @tc.desc: Verify the ToString function
 * @tc.type: FUNC
 */
HWTEST_F(BinderDebugUnitTest, ToStringTest001, TestSize.Level1)
{
    BinderDebug debug;
    std::string ret = debug.ToString(BR_ERROR);
    EXPECT_EQ(ret, "BR_ERROR");
}

/**
 * @tc.name: ToStringTest002
 * @tc.desc: Verify the ToString function
 * @tc.type: FUNC
 */
HWTEST_F(BinderDebugUnitTest, ToStringTest002, TestSize.Level1)
{
    BinderDebug debug;
    std::string ret = debug.ToString(BC_DEAD_BINDER_DONE + 1);
    EXPECT_EQ(ret, "UNKNOWN COMMAND");
}
} // namespace OHOS
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

#include "access_token_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace {
constexpr uint32_t INVAL_TOKEN_ID = 0x0;
}
class AccessTokenAdapterTest : public ::testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AccessTokenAdapterTest::SetUpTestCase()
{
}

void AccessTokenAdapterTest::TearDownTestCase()
{
}

void AccessTokenAdapterTest::SetUp()
{
}

void AccessTokenAdapterTest::TearDown()
{
}

/**
 * @tc.name: RpcGetSelfTokenIDTest001
 * @tc.desc: Verify the RpcGetSelfTokenID function return not INVAL_TOKEN_ID
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenAdapterTest, RpcGetSelfTokenIDTest001, TestSize.Level1)
{
    int32_t tokenID = RpcGetSelfTokenID();
    EXPECT_NE(tokenID, INVAL_TOKEN_ID);
}

/**
 * @tc.name: RpcGetFirstCallerTokenID001
 * @tc.desc: Verify the RpcGetFirstCallerTokenID function return INVAL_TOKEN_ID
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenAdapterTest, RpcGetFirstCallerTokenID001, TestSize.Level1)
{
    int32_t tokenID = RpcGetFirstCallerTokenID();
    EXPECT_EQ(tokenID, INVAL_TOKEN_ID);
}
} // namespace OHOS
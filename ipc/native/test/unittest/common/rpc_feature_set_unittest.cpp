/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "string_ex.h"

#include "rpc_feature_set.h"

using namespace testing::ext;
using namespace OHOS;

namespace {
    constexpr uint32_t RPC_FEATURE_ACK = 0x80000000;
    constexpr uint32_t INVAL_TOKEN_ID = 0x0;
    constexpr uint32_t EXTRA_SIZE = 10;
    constexpr uint32_t EXPECTED_TOKEN_ID = 123789;
    constexpr uint32_t MAGIC_NUMBER = 123456;
    constexpr uint32_t RPC_ACCESS_TOKEN_TAG = 0;
    constexpr uint32_t ACCESS_TOKEN_FLAG = 0x1;
    // Magic number for correct flat session
    constexpr uint32_t FLAT_SESSION_MAGIC_NUMBER = ('R' << 24) | ('F' << 16) | ('S' << 8) | 43;
    // Magic number for flat session with an error case
    constexpr uint32_t FLAT_SESSION_MAGIC_NUMBER_42 = ('R' << 24) | ('F' << 16) | ('S' << 8) | 42;
    constexpr uint32_t UNKNOWN_TAG_1 = 1;
}

class RpcFeatureSetTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RpcFeatureSetTest::SetUpTestCase()
{
}

void RpcFeatureSetTest::TearDownTestCase()
{
}

void RpcFeatureSetTest::SetUp()
{
}

void RpcFeatureSetTest::TearDown()
{
}

/**
 * @tc.name: SetFeatureTransData001
 * @tc.desc: Verify the IPCObjectProxy::SetFeatureTransData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, SetFeatureTransData001, TestSize.Level1)
{
    FeatureTransData *data = nullptr;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    bool res = SetFeatureTransData(data, size);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetFeatureTransData002
 * @tc.desc: Verify the IPCObjectProxy::SetFeatureTransData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, SetFeatureTransData002, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = MAGIC_NUMBER;
    uint32_t size = 0;
    bool res = SetFeatureTransData(&data, size);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetFeatureTransData003
 * @tc.desc: Verify the IPCObjectProxy::SetFeatureTransData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, SetFeatureTransData003, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = MAGIC_NUMBER;
    data.tag = UNKNOWN_TAG_1;
    data.tokenId = 54321;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    bool res = SetFeatureTransData(&data, size);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: SetFeatureTransData004
 * @tc.desc: Verify the IPCObjectProxy::SetFeatureTransData function when size is greater than the required size
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, SetFeatureTransData004, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = MAGIC_NUMBER;
    uint32_t size = (uint32_t)sizeof(FeatureTransData) + EXTRA_SIZE;
    bool res = SetFeatureTransData(&data, size);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: SetFeatureTransData005
 * @tc.desc: Verify the SetFeatureTransData function when size is less than the required size
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, SetFeatureTransData005, TestSize.Level1)
{
    FeatureTransData data;
    uint32_t size = (uint32_t)sizeof(FeatureTransData) - 1;
    bool res = SetFeatureTransData(&data, size);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: GetTokenFromData001
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData001, TestSize.Level1)
{
    FeatureTransData *data = nullptr;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(data, size);
    EXPECT_EQ(ret, INVAL_TOKEN_ID);
}

/**
 * @tc.name: GetTokenFromData001
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData002, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = MAGIC_NUMBER;
    uint32_t size = 0;
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, INVAL_TOKEN_ID);
}

/**
 * @tc.name: GetTokenFromData001
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData003, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = MAGIC_NUMBER;
    data.tag = RPC_ACCESS_TOKEN_TAG;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, INVAL_TOKEN_ID);
}

/**
 * @tc.name: GetTokenFromData004
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData004, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = FLAT_SESSION_MAGIC_NUMBER;
    data.tag = 3;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, INVAL_TOKEN_ID);
}

/**
 * @tc.name: GetTokenFromData005
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData005, TestSize.Level1)
{
    FeatureTransData data;
    data.tokenId = EXPECTED_TOKEN_ID;
    data.magicNum = FLAT_SESSION_MAGIC_NUMBER;
    data.tag = RPC_ACCESS_TOKEN_TAG;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, EXPECTED_TOKEN_ID);
}

/**
 * @tc.name: GetTokenFromData006
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function when size is greater than the required size
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData006, TestSize.Level1)
{
    FeatureTransData data;
    data.tokenId = EXPECTED_TOKEN_ID;
    data.magicNum = FLAT_SESSION_MAGIC_NUMBER;
    data.tag = RPC_ACCESS_TOKEN_TAG;
    uint32_t size = (uint32_t)sizeof(FeatureTransData) + EXTRA_SIZE;
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, EXPECTED_TOKEN_ID);
}

/**
 * @tc.name: GetTokenFromData007
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function when magic number is incorrect
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData007, TestSize.Level1)
{
    FeatureTransData data;
    data.tokenId = EXPECTED_TOKEN_ID;
    data.magicNum = FLAT_SESSION_MAGIC_NUMBER_42;
    data.tag = RPC_ACCESS_TOKEN_TAG;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, INVAL_TOKEN_ID);
}

/**
 * @tc.name: GetTokenFromData008
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function when tag is incorrect
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData008, TestSize.Level1)
{
    FeatureTransData data;
    data.tokenId = EXPECTED_TOKEN_ID;
    data.magicNum = FLAT_SESSION_MAGIC_NUMBER;
    data.tag = UNKNOWN_TAG_1;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, INVAL_TOKEN_ID);
}

/**
 * @tc.name: GetTokenFromData009
 * @tc.desc: Verify the GetTokenFromData function when size is less than the required size
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData009, TestSize.Level1)
{
    FeatureTransData data;
    uint32_t size = (uint32_t)sizeof(FeatureTransData) - 1;
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, INVAL_TOKEN_ID);
}

/**
 * @tc.name: IsATEnable001
 * @tc.desc: Verify the IsATEnable function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, IsATEnable001, TestSize.Level1)
{
    uint32_t featureSet = ACCESS_TOKEN_FLAG;
    bool res = IsATEnable(featureSet);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsATEnable002
 * @tc.desc: Verify the IsATEnable function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, IsATEnable002, TestSize.Level1)
{
    uint32_t featureSet = 0;
    bool res = IsATEnable(featureSet);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: IsFeatureAck001
 * @tc.desc: Verify the IsFeatureAck function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, IsFeatureAck001, TestSize.Level1)
{
    uint32_t featureSet = RPC_FEATURE_ACK;
    bool res = IsFeatureAck(featureSet);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsFeatureAck002
 * @tc.desc: Verify the IsFeatureAck function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, IsFeatureAck002, TestSize.Level1)
{
    uint32_t featureSet = 0;
    bool res = IsFeatureAck(featureSet);
    EXPECT_EQ(res, false);
}
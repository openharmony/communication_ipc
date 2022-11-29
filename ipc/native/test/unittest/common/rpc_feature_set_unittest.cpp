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
#ifdef __cplusplus
extern "C" {
#include "rpc_feature_set.c"
}
#endif

using namespace testing::ext;
using namespace OHOS;

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
 * @tc.name: GetFeatureMagicNumber001
 * @tc.desc: Verify the IPCObjectProxy::GetFeatureMagicNumber function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetFeatureMagicNumber001, TestSize.Level1)
{
    uint32_t ret = GetFeatureMagicNumber();
    uint32_t testValue = ('R' << 24) | ('F' << 16) | ('S' << 8) | 43;
    EXPECT_EQ(ret, testValue);
}

/**
 * @tc.name: GetFeatureMagicNumber001
 * @tc.desc: Verify the IPCObjectProxy::GetFeatureMagicNumber function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetFeatureATTag001, TestSize.Level1)
{
    uint32_t ret = GetFeatureATTag();
    uint32_t testValue = 0;
    EXPECT_EQ(ret, testValue);
}

/**
 * @tc.name: GetLocalRpcFeature001
 * @tc.desc: Verify the IPCObjectProxy::GetLocalRpcFeature function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetLocalRpcFeature001, TestSize.Level1)
{
    uint32_t ret = GetLocalRpcFeature();
    uint32_t testValue = 0x1;
    EXPECT_EQ(ret, testValue);
}

/**
 * @tc.name: GetRpcFeatureAck001
 * @tc.desc: Verify the IPCObjectProxy::GetRpcFeatureAck function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetRpcFeatureAck001, TestSize.Level1)
{
    uint32_t ret = GetRpcFeatureAck();
    uint32_t testValue = 0x80000000;
    EXPECT_EQ(ret, testValue);
}

/**
 * @tc.name: GetRpcFeatureAck001
 * @tc.desc: Verify the IPCObjectProxy::GetRpcFeatureAck function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, IsATEnable001, TestSize.Level1)
{
    uint32_t featureSet = 0x0;
    bool res = IsATEnable(featureSet);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: GetRpcFeatureAck002
 * @tc.desc: Verify the IPCObjectProxy::GetRpcFeatureAck function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, IsATEnable002, TestSize.Level1)
{
    uint32_t featureSet = 0x1;
    bool res = IsATEnable(featureSet);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: GetRpcFeatureAck001
 * @tc.desc: Verify the IPCObjectProxy::GetRpcFeatureAck function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, IsFeatureAck001, TestSize.Level1)
{
    uint32_t featureSet = 0x0;
    bool res = IsFeatureAck(featureSet);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: GetRpcFeatureAck001
 * @tc.desc: Verify the IPCObjectProxy::GetRpcFeatureAck function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenIdSize001, TestSize.Level1)
{
    uint32_t ret = GetTokenIdSize();
    uint32_t testValue = 4;
    EXPECT_EQ(ret, testValue);
}

/**
 * @tc.name: GetFeatureSize001
 * @tc.desc: Verify the IPCObjectProxy::GetFeatureSize function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetFeatureSize001, TestSize.Level1)
{
    uint32_t ret = GetFeatureSize();
    uint32_t testValue = (uint32_t)sizeof(FeatureTransData);
    EXPECT_EQ(ret, testValue);
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
    data.magicNum = 123456;
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
    data.magicNum = 123456;
    data.tag = 1;
    data.tokenId = 54321;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    bool res = SetFeatureTransData(&data, size);
    EXPECT_EQ(res, true);
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
    EXPECT_EQ(ret, 0x0);
}

/**
 * @tc.name: GetTokenFromData001
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData002, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = 123456;
    uint32_t size = 0;
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, 0x0);
}

/**
 * @tc.name: GetTokenFromData001
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData003, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = 123456;
    data.tag = GetFeatureATTag();
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, 0x0);
}

/**
 * @tc.name: GetTokenFromData004
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData004, TestSize.Level1)
{
    FeatureTransData data;
    data.magicNum = GetFeatureMagicNumber();
    data.tag = 3;
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, 0x0);
}

/**
 * @tc.name: GetTokenFromData005
 * @tc.desc: Verify the IPCObjectProxy::GetTokenFromData function
 * @tc.type: FUNC
 */
HWTEST_F(RpcFeatureSetTest, GetTokenFromData005, TestSize.Level1)
{
    FeatureTransData data;
    data.tokenId = 123456;
    data.magicNum = GetFeatureMagicNumber();
    data.tag = GetFeatureATTag();
    uint32_t size = (uint32_t)sizeof(FeatureTransData);
    uint32_t ret = GetTokenFromData(&data, size);
    EXPECT_EQ(ret, 123456);
}
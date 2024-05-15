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
#include <gmock/gmock.h>

#include <ipc_payload_statistics.h>

using namespace testing::ext;
using namespace OHOS;

namespace {
    constexpr int32_t PID = 1;
    constexpr int32_t INVALID_PID = -1;
    constexpr int32_t CODE = 1;
    constexpr int32_t INVALID_CODE = -1;
}

class IPCPayloadStatisticsUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCPayloadStatisticsUnitTest::SetUpTestCase()
{
}

void IPCPayloadStatisticsUnitTest::TearDownTestCase()
{
}

void IPCPayloadStatisticsUnitTest::SetUp()
{
}

void IPCPayloadStatisticsUnitTest::TearDown()
{
}

/**
 * @tc.name: GetTotalCount001
 * @tc.desc: Verify the GetTotalCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetTotalCount001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetTotalCount(), 0);
}

/**
 * @tc.name: GetTotalCost001
 * @tc.desc: Verify the GetTotalCost function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetTotalCost001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetTotalCost(), 0);
}

/**
 * @tc.name: GetPids001
 * @tc.desc: Verify the GetPids function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetPids001, TestSize.Level1)
{
    std::vector<int32_t> result = IPCPayloadStatistics::GetPids();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: GetCount001
 * @tc.desc: Verify the GetCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetCount001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetCount(PID), 0);
}

/**
 * @tc.name: GetCount002
 * @tc.desc: Verify the GetCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetCount002, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetCount(INVALID_PID), 0);
}

/**
 * @tc.name: GetCost001
 * @tc.desc: Verify the GetCost function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetCost001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetCost(PID), 0);
}

/**
 * @tc.name: GetCost002
 * @tc.desc: Verify the GetCost function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetCost002, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetCost(INVALID_PID), 0);
}

/**
 * @tc.name: GetDescriptorCodes001
 * @tc.desc: Verify the GetDescriptorCodes function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodes001, TestSize.Level1)
{
    std::vector<IPCInterfaceInfo> info = IPCPayloadStatistics::GetDescriptorCodes(PID);
    EXPECT_EQ(info.size(), 0);
}

/**
 * @tc.name: GetDescriptorCodes002
 * @tc.desc: Verify the GetDescriptorCodes function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodes002, TestSize.Level1)
{
    std::vector<IPCInterfaceInfo> info = IPCPayloadStatistics::GetDescriptorCodes(INVALID_PID);
    EXPECT_EQ(info.size(), 0);
}

/**
 * @tc.name: GetDescriptorCodeCount001
 * @tc.desc: Verify the GetDescriptorCodeCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodeCount001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetDescriptorCodeCount(PID, u"string1", CODE), 0);
}

/**
 * @tc.name: GetDescriptorCodeCount002
 * @tc.desc: Verify the GetDescriptorCodeCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodeCount002, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetDescriptorCodeCount(INVALID_PID, u"string1", CODE), 0);
}

/**
 * @tc.name: GetDescriptorCodeCount003
 * @tc.desc: Verify the GetDescriptorCodeCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodeCount003, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetDescriptorCodeCount(PID, u"", CODE), 0);
}

/**
 * @tc.name: GetDescriptorCodeCount004
 * @tc.desc: Verify the GetDescriptorCodeCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodeCount004, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetDescriptorCodeCount(PID, u"string1", INVALID_CODE), 0);
}

/**
 * @tc.name: GetDescriptorCodeCost001
 * @tc.desc: Verify the GetDescriptorCodeCost function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodeCost001, TestSize.Level1)
{
    IPCPayloadCost cost = IPCPayloadStatistics::GetDescriptorCodeCost(PID, u"string1", CODE);
    EXPECT_EQ(cost.totalCost, 0);
    EXPECT_EQ(cost.maxCost, 0);
    EXPECT_EQ(cost.minCost, 0);
    EXPECT_EQ(cost.averCost, 0);
}

/**
 * @tc.name: GetDescriptorCodeCost002
 * @tc.desc: Verify the GetDescriptorCodeCost function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodeCost002, TestSize.Level1)
{
    IPCPayloadCost cost = IPCPayloadStatistics::GetDescriptorCodeCost(INVALID_PID, u"string1", CODE);
    EXPECT_EQ(cost.totalCost, 0);
    EXPECT_EQ(cost.maxCost, 0);
    EXPECT_EQ(cost.minCost, 0);
    EXPECT_EQ(cost.averCost, 0);
}

/**
 * @tc.name: GetDescriptorCodeCost003
 * @tc.desc: Verify the GetDescriptorCodeCost function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodeCost003, TestSize.Level1)
{
    IPCPayloadCost cost = IPCPayloadStatistics::GetDescriptorCodeCost(PID, u"", CODE);
    EXPECT_EQ(cost.totalCost, 0);
    EXPECT_EQ(cost.maxCost, 0);
    EXPECT_EQ(cost.minCost, 0);
    EXPECT_EQ(cost.averCost, 0);
}

/**
 * @tc.name: GetDescriptorCodeCost004
 * @tc.desc: Verify the GetDescriptorCodeCost function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetDescriptorCodeCost004, TestSize.Level1)
{
    IPCPayloadCost cost = IPCPayloadStatistics::GetDescriptorCodeCost(PID, u"string1", INVALID_CODE);
    EXPECT_EQ(cost.totalCost, 0);
    EXPECT_EQ(cost.maxCost, 0);
    EXPECT_EQ(cost.minCost, 0);
    EXPECT_EQ(cost.averCost, 0);
}

/**
 * @tc.name: GetStatisticsStatus001
 * @tc.desc: Verify the GetStatisticsStatus function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, GetStatisticsStatus001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::GetStatisticsStatus(), false);
}

/**
 * @tc.name: StartStatistics001
 * @tc.desc: Verify the StartStatistics function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, StartStatistics001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::StartStatistics(), true);
    EXPECT_EQ(IPCPayloadStatistics::GetStatisticsStatus(), true);
}

/**
 * @tc.name: StopStatistics001
 * @tc.desc: Verify the StopStatistics function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, StopStatistics001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::StopStatistics(), true);
    EXPECT_EQ(IPCPayloadStatistics::GetStatisticsStatus(), false);
}

/**
 * @tc.name: ClearStatisticsData001
 * @tc.desc: Verify the ClearStatisticsData function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsUnitTest, ClearStatisticsData001, TestSize.Level1)
{
    EXPECT_EQ(IPCPayloadStatistics::ClearStatisticsData(), true);
}
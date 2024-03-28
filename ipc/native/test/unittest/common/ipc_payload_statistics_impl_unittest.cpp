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

#include <ipc_payload_statistics_impl.h>
#include <climits>

using namespace testing::ext;
using namespace OHOS;

namespace {
    constexpr int32_t PID_1 = 1;
    constexpr int32_t PID_2 = 2;
    constexpr int32_t PID_3 = INT_MAX;
    constexpr int32_t DESC_CODE_1 = 1;
    constexpr int32_t DESC_CODE_2 = 2;
    constexpr int32_t DESC_CODE_3 = INT_MAX;
    constexpr uint64_t DEFAULT_COUNT = 100000;
    constexpr uint64_t DEFAULT_TOTAL_COST = 5000050000;
    constexpr uint64_t DEFAULT_MAX_COST = 100000;
    constexpr uint64_t DEFAULT_MIN_COST = 1;
    constexpr uint64_t DOUBLE_COEFFICIENT = 2;
    constexpr uint64_t TRIPLE_COEFFICIENT = 3;
}

class IPCPayloadStatisticsImplUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    bool InitIPCPayloadStatisticsData();
    bool ClearIPCPayloadStatisticsData();
};

void IPCPayloadStatisticsImplUnitTest::SetUpTestCase()
{
}

void IPCPayloadStatisticsImplUnitTest::TearDownTestCase()
{
}

void IPCPayloadStatisticsImplUnitTest::SetUp()
{
}

void IPCPayloadStatisticsImplUnitTest::TearDown()
{
}

bool IPCPayloadStatisticsImplUnitTest::InitIPCPayloadStatisticsData()
{
    bool ret = true;
    std::u16string descStr = u"string1";
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();

    instance.StartStatistics();
    for (int32_t i = 1; i <= DEFAULT_COUNT; i++) {
        ret = instance.UpdatePayloadInfo(PID_1, descStr, DESC_CODE_1, i);
        if (!ret) {
            return false;
        }
    }

    descStr = u"string2";
    for (int32_t i = 1; i <= DEFAULT_COUNT; i++) {
        ret = instance.UpdatePayloadInfo(PID_2, descStr, DESC_CODE_2, i * DOUBLE_COEFFICIENT);
        if (!ret) {
            return false;
        }
    }

    descStr = u"string3";
    for (int32_t i = 1; i <= DEFAULT_COUNT; i++) {
        ret = instance.UpdatePayloadInfo(PID_3, descStr, DESC_CODE_3, i * TRIPLE_COEFFICIENT);
        if (!ret) {
            return false;
        }
    }

    return ret;
}

/**
 * @tc.name: GetTotalCount001
 * @tc.desc: Verify the GetTotalCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetTotalCount001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(instance.GetTotalCount(), 0);
}

/**
 * @tc.name: GetTotalCount002
 * @tc.desc: Verify the GetTotalCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetTotalCount002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);

    uint64_t totalCount = DEFAULT_COUNT + DEFAULT_COUNT + DEFAULT_COUNT;
    EXPECT_EQ(instance.GetTotalCount(), totalCount);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: GetTotalCost001
 * @tc.desc: Verify the GetTotalCost function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetTotalCost001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(instance.GetTotalCost(), 0);
}

/**
 * @tc.name: GetTotalCost002
 * @tc.desc: Verify the GetTotalCost function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetTotalCost002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);
    uint64_t totalCost =
        DEFAULT_TOTAL_COST + DEFAULT_TOTAL_COST * DOUBLE_COEFFICIENT + DEFAULT_TOTAL_COST * TRIPLE_COEFFICIENT;
    EXPECT_EQ(instance.GetTotalCost(), totalCost);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: GetPids001
 * @tc.desc: Verify the GetPids function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetPids001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    std::vector<int32_t> result = instance.GetPids();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: GetPids002
 * @tc.desc: Verify the GetPids function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetPids002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);
    std::vector<int32_t> result = instance.GetPids();
    EXPECT_NE(result.size(), 0);
    EXPECT_EQ(result[0], PID_1);
    EXPECT_EQ(result[1], PID_2);
    EXPECT_EQ(result[2], PID_3);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: GetCount001
 * @tc.desc: Verify the GetCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetCount001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(instance.GetCount(PID_1), 0);
}

/**
 * @tc.name: GetCount002
 * @tc.desc: Verify the GetCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetCount002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);
    EXPECT_EQ(instance.GetCount(PID_1), DEFAULT_COUNT);
    EXPECT_EQ(instance.GetCount(PID_2), DEFAULT_COUNT);
    EXPECT_EQ(instance.GetCount(PID_3), DEFAULT_COUNT);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: GetCost001
 * @tc.desc: Verify the GetCost function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetCost001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(instance.GetCost(PID_1), 0);
}

/**
 * @tc.name: GetCost002
 * @tc.desc: Verify the GetCost function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetCost002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);
    EXPECT_EQ(instance.GetCost(PID_1), DEFAULT_TOTAL_COST);
    EXPECT_EQ(instance.GetCost(PID_2), DEFAULT_TOTAL_COST * DOUBLE_COEFFICIENT);
    EXPECT_EQ(instance.GetCost(PID_3), DEFAULT_TOTAL_COST * TRIPLE_COEFFICIENT);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: GetDescriptorCodes001
 * @tc.desc: Verify the GetDescriptorCodes function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetDescriptorCodes001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    std::vector<IPCInterfaceInfo> info = instance.GetDescriptorCodes(PID_1);
    EXPECT_EQ(info.size(), 0);
}

/**
 * @tc.name: GetDescriptorCodes002
 * @tc.desc: Verify the GetDescriptorCodes function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetDescriptorCodes002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);

    std::vector<IPCInterfaceInfo> info_1 = instance.GetDescriptorCodes(PID_1);
    EXPECT_NE(info_1.size(), 0);
    EXPECT_EQ(info_1[0].desc, u"string1");
    EXPECT_EQ(info_1[0].code, DESC_CODE_1);

    std::vector<IPCInterfaceInfo> info_2 = instance.GetDescriptorCodes(PID_2);
    EXPECT_NE(info_2.size(), 0);
    EXPECT_EQ(info_2[0].desc, u"string2");
    EXPECT_EQ(info_2[0].code, DESC_CODE_2);

    std::vector<IPCInterfaceInfo> info_3 = instance.GetDescriptorCodes(PID_3);
    EXPECT_NE(info_3.size(), 0);
    EXPECT_EQ(info_3[0].desc, u"string3");
    EXPECT_EQ(info_3[0].code, DESC_CODE_3);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: GetDescriptorCodeCount001
 * @tc.desc: Verify the GetDescriptorCodeCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetDescriptorCodeCount001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(instance.GetDescriptorCodeCount(PID_1, u"string1", DESC_CODE_1), 0);
}

/**
 * @tc.name: GetDescriptorCodeCount002
 * @tc.desc: Verify the GetDescriptorCodeCount function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetDescriptorCodeCount002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);

    int32_t count1 = instance.GetDescriptorCodeCount(PID_1, u"string1", DESC_CODE_1);
    int32_t count2 = instance.GetDescriptorCodeCount(PID_2, u"string2", DESC_CODE_2);
    int32_t count3 = instance.GetDescriptorCodeCount(PID_3, u"string3", DESC_CODE_3);
    EXPECT_EQ(count1, DEFAULT_COUNT);
    EXPECT_EQ(count2, DEFAULT_COUNT);
    EXPECT_EQ(count3, DEFAULT_COUNT);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: GetDescriptorCodeCost001
 * @tc.desc: Verify the GetDescriptorCodeCost function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetDescriptorCodeCost001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    IPCPayloadCost cost = instance.GetDescriptorCodeCost(PID_1, u"string1", DESC_CODE_1);
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
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetDescriptorCodeCost002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);
    IPCPayloadCost cost1 = instance.GetDescriptorCodeCost(PID_1, u"string1", DESC_CODE_1);
    EXPECT_EQ(cost1.totalCost, DEFAULT_TOTAL_COST);
    EXPECT_EQ(cost1.maxCost, DEFAULT_MAX_COST);
    EXPECT_EQ(cost1.minCost, DEFAULT_MIN_COST);
    EXPECT_EQ(cost1.averCost, DEFAULT_TOTAL_COST / DEFAULT_COUNT);

    IPCPayloadCost cost2 = instance.GetDescriptorCodeCost(PID_2, u"string2", DESC_CODE_2);
    EXPECT_EQ(cost2.totalCost, DEFAULT_TOTAL_COST * DOUBLE_COEFFICIENT);
    EXPECT_EQ(cost2.maxCost, DEFAULT_MAX_COST * DOUBLE_COEFFICIENT);
    EXPECT_EQ(cost2.minCost, DEFAULT_MIN_COST * DOUBLE_COEFFICIENT);
    EXPECT_EQ(cost2.averCost, DEFAULT_TOTAL_COST * DOUBLE_COEFFICIENT / DEFAULT_COUNT);

    IPCPayloadCost cost3 = instance.GetDescriptorCodeCost(PID_3, u"string3", DESC_CODE_3);
    EXPECT_EQ(cost3.totalCost, DEFAULT_TOTAL_COST * TRIPLE_COEFFICIENT);
    EXPECT_EQ(cost3.maxCost, DEFAULT_MAX_COST * TRIPLE_COEFFICIENT);
    EXPECT_EQ(cost3.minCost, DEFAULT_MIN_COST * TRIPLE_COEFFICIENT);
    EXPECT_EQ(cost3.averCost, DEFAULT_TOTAL_COST * TRIPLE_COEFFICIENT / DEFAULT_COUNT);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: GetStatisticsStatus001
 * @tc.desc: Verify the GetStatisticsStatus function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, GetStatisticsStatus001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(instance.GetStatisticsStatus(), false);
}


/**
 * @tc.name: StartStatistics001
 * @tc.desc: Verify the StartStatistics function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, StartStatistics001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(instance.StartStatistics(), true);
    EXPECT_EQ(instance.GetStatisticsStatus(), true);
}

/**
 * @tc.name: StopStatistics001
 * @tc.desc: Verify the StopStatistics function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, StopStatistics001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(instance.StopStatistics(), true);
    EXPECT_EQ(instance.GetStatisticsStatus(), false);
}

/**
 * @tc.name: ClearStatisticsData001
 * @tc.desc: Verify the ClearStatisticsData function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, ClearStatisticsData001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.GetTotalCost(), 0);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: UpdatePayloadInfo001
 * @tc.desc: Verify the UpdatePayloadInfo function
 * @tc.type: FUNC
  */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, UpdatePayloadInfo001, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);

    int32_t pid = 4;
    IPCInterfaceInfo interfaceInfo = { u"string4", 4 };
    uint32_t currentCost = 10;
    uint32_t currentCount = 1;

    bool ret = instance.UpdatePayloadInfo(pid, interfaceInfo.desc, interfaceInfo.code, currentCost);
    EXPECT_EQ(ret, true);

    uint64_t totalCount = currentCount + DEFAULT_COUNT + DEFAULT_COUNT + DEFAULT_COUNT;
    uint64_t totalCost = currentCost + DEFAULT_TOTAL_COST +
        DEFAULT_TOTAL_COST * DOUBLE_COEFFICIENT + DEFAULT_TOTAL_COST * TRIPLE_COEFFICIENT;
    EXPECT_EQ(instance.GetTotalCount(), totalCount);
    EXPECT_EQ(instance.GetTotalCost(), totalCost);

    std::vector<int32_t> result = instance.GetPids();
    EXPECT_NE(result.size(), 0);
    EXPECT_EQ(result[0], PID_1);
    EXPECT_EQ(result[1], PID_2);
    EXPECT_EQ(result[2], pid);
    EXPECT_EQ(result[3], PID_3);

    EXPECT_EQ(instance.GetCount(pid), currentCount);
    EXPECT_EQ(instance.GetCost(pid), currentCost);

    std::vector<IPCInterfaceInfo> res = instance.GetDescriptorCodes(pid);
    EXPECT_NE(res.size(), 0);
    EXPECT_EQ(res[0].desc, interfaceInfo.desc);
    EXPECT_EQ(res[0].code, interfaceInfo.code);

    EXPECT_EQ(instance.GetDescriptorCodeCount(pid, interfaceInfo.desc, interfaceInfo.code), currentCount);

    IPCPayloadCost cost = instance.GetDescriptorCodeCost(pid, interfaceInfo.desc, interfaceInfo.code);
    EXPECT_EQ(cost.totalCost, currentCost);
    EXPECT_EQ(cost.maxCost, currentCost);
    EXPECT_EQ(cost.minCost, currentCost);
    EXPECT_EQ(cost.averCost, currentCost / currentCount);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: UpdatePayloadInfo002
 * @tc.desc: Verify the UpdatePayloadInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, UpdatePayloadInfo002, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);

    int32_t pid = PID_1;
    IPCInterfaceInfo interfaceInfo = { u"string5", 5 };
    uint32_t currentCost = 5;
    uint32_t currentCount = 1;

    bool ret = instance.UpdatePayloadInfo(pid, interfaceInfo.desc, interfaceInfo.code, currentCost);
    EXPECT_EQ(ret, true);

    uint64_t totalCount = currentCount + DEFAULT_COUNT + DEFAULT_COUNT + DEFAULT_COUNT;
    uint64_t totalCost = currentCost + DEFAULT_TOTAL_COST +
        DEFAULT_TOTAL_COST * DOUBLE_COEFFICIENT + DEFAULT_TOTAL_COST * TRIPLE_COEFFICIENT;
    EXPECT_EQ(instance.GetTotalCount(), totalCount);
    EXPECT_EQ(instance.GetTotalCost(), totalCost);

    std::vector<int32_t> result = instance.GetPids();
    EXPECT_NE(result.size(), 0);
    EXPECT_EQ(result[0], pid);
    EXPECT_EQ(result[1], PID_2);
    EXPECT_EQ(result[2], PID_3);

    EXPECT_EQ(instance.GetCount(pid), DEFAULT_COUNT + currentCount);
    EXPECT_EQ(instance.GetCost(pid), DEFAULT_TOTAL_COST + currentCost);

    std::vector<IPCInterfaceInfo> res = instance.GetDescriptorCodes(pid);
    EXPECT_NE(res.size(), 0);
    EXPECT_EQ(res[1].desc, interfaceInfo.desc);
    EXPECT_EQ(res[1].code, interfaceInfo.code);

    EXPECT_EQ(instance.GetDescriptorCodeCount(pid, interfaceInfo.desc, interfaceInfo.code), currentCount);

    IPCPayloadCost cost = instance.GetDescriptorCodeCost(pid, interfaceInfo.desc, interfaceInfo.code);
    EXPECT_EQ(cost.totalCost, currentCost);
    EXPECT_EQ(cost.maxCost, currentCost);
    EXPECT_EQ(cost.minCost, currentCost);
    EXPECT_EQ(cost.averCost, currentCost / currentCount);
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

/**
 * @tc.name: UpdatePayloadInfo003
 * @tc.desc: Verify the UpdatePayloadInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCPayloadStatisticsImplUnitTest, UpdatePayloadInfo003, TestSize.Level1)
{
    IPCPayloadStatisticsImpl& instance = IPCPayloadStatisticsImpl::GetInstance();
    EXPECT_EQ(InitIPCPayloadStatisticsData(), true);

    int32_t pid = PID_1;
    IPCInterfaceInfo interfaceInfo = { u"string1", DESC_CODE_1 };
    uint32_t currentCost = 5;
    uint32_t currentCount = 1;

    bool ret = instance.UpdatePayloadInfo(pid, interfaceInfo.desc, interfaceInfo.code, currentCost);
    EXPECT_EQ(ret, true);

    uint64_t totalCount = currentCount + DEFAULT_COUNT + DEFAULT_COUNT + DEFAULT_COUNT;
    uint64_t totalCost = currentCost + DEFAULT_TOTAL_COST +
        DEFAULT_TOTAL_COST * DOUBLE_COEFFICIENT + DEFAULT_TOTAL_COST * TRIPLE_COEFFICIENT;
    EXPECT_EQ(instance.GetTotalCount(), totalCount);
    EXPECT_EQ(instance.GetTotalCost(), totalCost);

    std::vector<int32_t> result = instance.GetPids();
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], pid);
    EXPECT_EQ(result[1], PID_2);
    EXPECT_EQ(result[2], PID_3);
    EXPECT_EQ(instance.GetCount(pid), DEFAULT_COUNT + currentCount);
    EXPECT_EQ(instance.GetCost(pid), DEFAULT_TOTAL_COST + currentCost);

    std::vector<IPCInterfaceInfo> res = instance.GetDescriptorCodes(pid);
    EXPECT_NE(res.size(), 0);
    EXPECT_EQ(res[0].desc, interfaceInfo.desc);
    EXPECT_EQ(res[0].code, interfaceInfo.code);

    uint32_t count = instance.GetDescriptorCodeCount(pid, interfaceInfo.desc, interfaceInfo.code);
    EXPECT_EQ(count, DEFAULT_COUNT + currentCount);

    IPCPayloadCost cost = instance.GetDescriptorCodeCost(pid, interfaceInfo.desc, interfaceInfo.code);
    EXPECT_EQ(cost.totalCost, DEFAULT_TOTAL_COST + currentCost);
    EXPECT_EQ(cost.maxCost, DEFAULT_MAX_COST);
    EXPECT_EQ(cost.minCost, DEFAULT_MIN_COST);
    EXPECT_EQ(cost.averCost, (DEFAULT_TOTAL_COST + currentCost) / (DEFAULT_COUNT + currentCount));
    EXPECT_EQ(instance.ClearStatisticsData(), true);
    EXPECT_EQ(instance.StopStatistics(), true);
}

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
#include "sys_binder.h"
#define private public
#include "binder_connector.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

class BinderConnectorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BinderConnectorTest::SetUpTestCase()
{
}

void BinderConnectorTest::TearDownTestCase()
{
}

void BinderConnectorTest::SetUp()
{
}

void BinderConnectorTest::TearDown()
{
}

/**
 * @tc.name: OpenDriver001
 * @tc.desc: Verify the OpenDriver function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, OpenDriver001, TestSize.Level1)
{
    std::string deviceName("test");
    BinderConnector binderConnector(deviceName);
    bool res = binderConnector.OpenDriver();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ExitCurrentThread001
 * @tc.desc: Verify the ExitCurrentThread function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, ExitCurrentThread001, TestSize.Level1)
{
    BinderConnector* binderConnector = BinderConnector::GetInstance();
    binderConnector->ExitCurrentThread(BINDER_THREAD_EXIT);
    EXPECT_NE(binderConnector->driverFD_, 0);
    binderConnector->driverFD_ = 1;
    binderConnector->ExitCurrentThread(BINDER_THREAD_EXIT);
    EXPECT_TRUE(binderConnector->driverFD_ > 0);
}

/**
 * @tc.name: IsAccessTokenSupported001
 * @tc.desc: Verify the IsAccessTokenSupported function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, IsAccessTokenSupported001, TestSize.Level1)
{
    BinderConnector* binderConnector = BinderConnector::GetInstance();
    binderConnector->driverFD_ = -1;
    auto ret = binderConnector->IsAccessTokenSupported();
    ASSERT_TRUE(!ret);
}

/**
 * @tc.name: GetSelfTokenID001
 * @tc.desc: Verify the GetSelfTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, GetSelfTokenID001, TestSize.Level1)
{
    BinderConnector* binderConnector = BinderConnector::GetInstance();
    binderConnector->driverFD_ = -1;
    auto ret = binderConnector->GetSelfTokenID();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: GetSelfFirstCallerTokenID001
 * @tc.desc: Verify the GetSelfFirstCallerTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, GetSelfFirstCallerTokenID001, TestSize.Level1)
{
    BinderConnector* binderConnector = BinderConnector::GetInstance();
    binderConnector->driverFD_ = -1;
    auto ret = binderConnector->GetSelfFirstCallerTokenID();
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: MapMemory001
 * @tc.desc: Verify the MapMemory function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, MapMemory001, TestSize.Level1)
{
    BinderConnector* binderConnector = BinderConnector::GetInstance();
    binderConnector->driverFD_ = -1;
    bool res = binderConnector->MapMemory(0);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: IsRealPidSupported001
 * @tc.desc: Verify the IsRealPidSupported function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, IsRealPidSupported001, TestSize.Level1)
{
    BinderConnector* binderConnector = BinderConnector::GetInstance();
    binderConnector->featureSet_ = SENDER_INFO_FAETURE_MASK;
    bool res = binderConnector->IsRealPidSupported();
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: IsRealPidSupported002
 * @tc.desc: Verify the IsRealPidSupported function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, IsRealPidSupported002, TestSize.Level1)
{
    BinderConnector* binderConnector = BinderConnector::GetInstance();
    binderConnector->featureSet_ = 0;
    bool res = binderConnector->IsRealPidSupported();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: GetInstance001
 * @tc.desc: Verify the GetInstance function
 * @tc.type: FUNC
 */
HWTEST_F(BinderConnectorTest, GetInstance001, TestSize.Level1)
{
    BinderConnector* binderConnector1 = BinderConnector::GetInstance();
    BinderConnector* binderConnector2 = BinderConnector::GetInstance();
    EXPECT_EQ(binderConnector1, binderConnector2);
}
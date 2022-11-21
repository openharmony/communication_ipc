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

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
#include <memory>
#include <iostream>
#include "invoker_rawdata.h"
#include "ipc_debug.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class InvokerRawDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    size_t validSize_ = 1024;
    size_t invalidSize_ = 0;
    size_t maxSize_ = 128 * 1024 * 1024;
};

void InvokerRawDataTest::SetUpTestCase()
{
}

void InvokerRawDataTest::TearDownTestCase()
{
}

void InvokerRawDataTest::SetUp()
{
}

void InvokerRawDataTest::TearDown()
{
}

/**
 * @tc.name: InvokerRawData001
 * @tc.desc: Verify the InvokerRawData function
 * @tc.type: FUNC
 */
HWTEST_F(InvokerRawDataTest, InvokerRawData001, TestSize.Level1)
{
    InvokerRawData rawDataZero(invalidSize_);
    InvokerRawData rawDataMax(maxSize_ + 1);

    EXPECT_EQ(rawDataZero.GetData(), nullptr);
    EXPECT_EQ(rawDataMax.GetData(), nullptr);
}

/**
 * @tc.name: GetData001
 * @tc.desc: Verify the GetData function
 * @tc.type: FUNC
 */
HWTEST_F(InvokerRawDataTest, GetData001, TestSize.Level1)
{
    InvokerRawData rawData(validSize_);

    EXPECT_NE(rawData.GetData(), nullptr);

    std::shared_ptr<char> data = rawData.GetData();
    EXPECT_EQ(data.use_count(), 2);
}

/**
 * @tc.name: GetSize001
 * @tc.desc: Verify the GetSize function
 * @tc.type: FUNC
 */
HWTEST_F(InvokerRawDataTest, GetSize001, TestSize.Level1)
{
    InvokerRawData rawData(validSize_);
    EXPECT_EQ(rawData.GetSize(), validSize_);
}
} // namespace OHOS
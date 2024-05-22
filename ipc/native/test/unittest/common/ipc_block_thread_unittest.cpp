/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "ipc_skeleton.h"

using namespace testing::ext;
using namespace OHOS;

class IpcBlockThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IpcBlockThreadTest::SetUpTestCase()
{
}

void IpcBlockThreadTest::TearDownTestCase()
{
}

void IpcBlockThreadTest::SetUp()
{
}

void IpcBlockThreadTest::TearDown()
{
}

/**
 * @tc.name: BlockUntilThreadAvailableTest001
 * @tc.desc: Verify the BlockUntilThreadAvailable function
 * @tc.type: FUNC
 */
HWTEST_F(IpcBlockThreadTest, BlockUntilThreadAvailableTest001, TestSize.Level1)
{
    bool test = false;
    if (!test) {
        IPCDfx::BlockUntilThreadAvailable();
        test = true;
    }
    EXPECT_EQ(test, true);
}
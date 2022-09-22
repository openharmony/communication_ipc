/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dbinder_service.h"
#include "gtest/gtest.h"
#include "rpc_log.h"
#include "log_tags.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;
using Communication::SoftBus::Session;

class DBinderServiceUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderServiceUnitTest" };
};

void DBinderServiceUnitTest::SetUp() {}

void DBinderServiceUnitTest::TearDown() {}

void DBinderServiceUnitTest::SetUpTestCase() {}

void DBinderServiceUnitTest::TearDownTestCase() {}

HWTEST_F(DBinderServiceUnitTest, process_closesession_001, TestSize.Level1)
{
    sptr<DBinderService> dBinderService_;
    std::shared_ptr<Session> session = nullptr;
    EXPECT_EQ(dBinderService_->ProcessOnSessionClosed(session), false);
}
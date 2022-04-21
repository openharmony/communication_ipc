/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "system_ability_definition.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "rpc_test.h"
#include "log_tags.h"

namespace OHOS {
#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

static constexpr HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "RPCServerTest" };
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

class RPCServerTest : public testing::Test {
public:
    static constexpr int saId = RPC_TEST_SERVICE;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void RPCServerTest::SetUpTestCase() {}

void RPCServerTest::TearDownTestCase() {}

HWTEST_F(RPCServerTest, function_test_001, TestSize.Level1)
{
    DBINDER_LOGI("Start RPCServer Testcase001");
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(saMgr != nullptr);

    ISystemAbilityManager::SAExtraProp saExtra;
    saExtra.isDistributed = true; // 设置为分布式SA
    int result = saMgr->AddSystemAbility(saId, new FooStub(), saExtra);
    ASSERT_EQ(result, 0);

    IPCSkeleton::JoinWorkThread();
}
}
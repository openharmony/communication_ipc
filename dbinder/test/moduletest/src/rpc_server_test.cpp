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

namespace OHOS {
using namespace testing::ext;
using namespace OHOS;

class RpcServerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void RpcServerTest::SetUpTestCase() {}

void RpcServerTest::TearDownTestCase()
{
    IPCSkeleton::JoinWorkThread();
}

HWTEST_F(RpcServerTest, function_test_001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    ISystemAbilityManager::SAExtraProp saExtra;
    saExtra.isDistributed = true;
    int result = saMgr->AddSystemAbility(RPC_TEST_SERVICE, new RpcFooStub(), saExtra);
    ASSERT_EQ(result, 0);
}

HWTEST_F(RpcServerTest, function_test_002, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    int result = saMgr->AddSystemAbility(RPC_TEST_SERVICE2, new RpcFooStub());
    ASSERT_EQ(result, 0);
}
}
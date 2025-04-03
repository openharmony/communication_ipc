/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <nativetoken_kit.h>
#include <token_setproc.h>

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "dsoftbus_interface.h"
#include "ipc_skeleton.h"
#include "rpc_test_service_proxy.h"
#include "rpc_test_service_stub.h"

namespace OHOS {
using namespace testing::ext;

static void InitTokenId(void)
{
    uint64_t tokenId;
    const char *perms[] = {
        OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER,
        OHOS_PERMISSION_DISTRIBUTED_DATASYNC,
    };
    uint32_t permsSize = sizeof(perms) / sizeof(perms[0]);
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsSize,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "com.rpc.test",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}

class RpcServerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void RpcServerTest::SetUpTestCase()
{
    InitTokenId();
}

void RpcServerTest::TearDownTestCase()
{
    IPCSkeleton::JoinWorkThread();
}

/**
 * @tc.name: AddTestServices001
 * @tc.desc: Register distributed services to Samgr
 * @tc.type: FUNC
 */
HWTEST_F(RpcServerTest, add_test_services_001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saMgr != nullptr);

    sptr<RpcTestServiceStub> stub = new RpcTestServiceStub();
    ASSERT_TRUE(stub != nullptr);

    ISystemAbilityManager::SAExtraProp saExtra;
    saExtra.isDistributed = true;
    int result = saMgr->AddSystemAbility(RPC_TEST_SERVICE, stub, saExtra);
    ASSERT_EQ(result, ERR_NONE);
}
}
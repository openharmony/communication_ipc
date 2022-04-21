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
#include "softbus_bus_center.h"
#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"
#include "rpc_test.h"
#include "access_token_adapter.h"
#include "rpc_feature_set.h"

namespace OHOS {
using namespace testing::ext;
using namespace OHOS;

static std::string g_deviceId;
static sptr<IRpcFooTest> g_rpcTestProxy;
class RpcClientTest : public testing::Test {
public:
    static constexpr char DBINDER_PKG_NAME[] = "DBinderService";
    static constexpr int NODE_NUM = 4;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void RpcClientTest::SetUpTestCase()
{
    NodeBasicInfo *nodeInfo[NODE_NUM];
    int32_t infoNum = NODE_NUM;
    int32_t ret = GetAllNodeDeviceInfo(DBINDER_PKG_NAME, nodeInfo, &infoNum);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(infoNum, 0);

    g_deviceId = nodeInfo[0]->networkId;
}

void RpcClientTest::TearDownTestCase() {}

HWTEST_F(RpcClientTest, function_test_001, TestSize.Level1)
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_FALSE(saMgr == nullptr);

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(RPC_TEST_SERVICE, g_deviceId);
    ASSERT_TRUE(object != nullptr) << "deviceid is " << g_deviceId;

    g_rpcTestProxy = iface_cast<IRpcFooTest>(object);
    ASSERT_TRUE(g_rpcTestProxy != nullptr);
}

HWTEST_F(RpcClientTest, function_test_002, TestSize.Level1)
{
    std::string fooName = g_rpcTestProxy->TestGetFooName();
    std::string selfFooName = g_rpcTestProxy->GetFooName();
    ASSERT_TRUE(fooName == selfFooName) << "fooName: " << fooName << " fooName_: " << selfFooName;
}

HWTEST_F(RpcClientTest, function_test_003, TestSize.Level1)
{
    uint32_t tokenId = RpcGetSelfTokenID();
    uint32_t getTokenId = g_rpcTestProxy->TestAccessToken();
    if (IsATEnable(GetLocalRpcFeature()) == true) {
        ASSERT_EQ(tokenId, getTokenId) << "deviceid is " << g_deviceId;
    } else {
        ASSERT_EQ(getTokenId, 0) << "deviceid is " << g_deviceId;
    }
}
}
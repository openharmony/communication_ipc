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
#include "log_tags.h"

namespace OHOS {
#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

static constexpr HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "RPCClientTest" };
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

static std::string g_deviceId;
class RPCClientTest : public testing::Test {
public:
    static constexpr int saId = RPC_TEST_SERVICE;
    static constexpr char DBINDER_PKG_NAME[] = "DBinderService";
    static constexpr int NODE_NUM = 4;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void RPCClientTest::SetUpTestCase()
{
    NodeBasicInfo *nodeInfo[NODE_NUM];
    int32_t infoNum = NODE_NUM;
    int32_t ret = GetAllNodeDeviceInfo(DBINDER_PKG_NAME, nodeInfo, &infoNum);
    if (ret != 0) {
        DBINDER_LOGE("get local node ret %{public}d", ret);
        return;
    }
    if (infoNum == 0) {
        DBINDER_LOGE("get no online nodes");
        return;
    }
    g_deviceId = nodeInfo[0]->networkId;
    DBINDER_LOGI("get deviceid %{public}s", g_deviceId.c_str());
}

void RPCClientTest::TearDownTestCase() {}

HWTEST_F(RPCClientTest, function_test_001, TestSize.Level1)
{
    DBINDER_LOGI("Start RPCClient Testcase001");
    // service instance
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(saMgr != nullptr);

    sptr<IRemoteObject> object = saMgr->GetSystemAbility(IPC_TEST_SERVICE, g_deviceId);
    ASSERT_TRUE(object != nullptr);

    sptr<IFoo> testService = iface_cast<IFoo>(object);
    ASSERT_TRUE(testService != nullptr);

    uint32_t tokenId = RpcGetSelfTokenID();
    uint32_t getTokenId = testService->TestAccessToken();
    ASSERT_EQ(tokenId, getTokenId);
}
}
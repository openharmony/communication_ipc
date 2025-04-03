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

#include <iostream>
#include <thread>
#include <gtest/gtest.h>
#include <nativetoken_kit.h>
#include <token_setproc.h>

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "softbus_bus_center.h"

#include "ipc_object_proxy.h"
#include "ipc_skeleton.h"
#include "rpc_test_service_death_recipient.h"
#include "rpc_test_service_proxy.h"
#include "rpc_test_service_stub.h"

namespace OHOS {
using namespace testing::ext;

static std::string g_deviceId;

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

class RpcClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void RpcClientTest::SetUpTestCase()
{
    InitTokenId();
    std::string pkgName = "DBinderService";
    NodeBasicInfo* nodeBasicInfo = nullptr;
    int32_t devicesNumber = 0;
    if (GetAllNodeDeviceInfo(pkgName.c_str(), &nodeBasicInfo, &devicesNumber) != 0) {
        std::cout << "GetAllNodeDeviceInfo failed" << std::endl;
        return;
    }
    if (devicesNumber == 0) {
        std::cout << "The number of devices in the current device network is zero." << std::endl;
        return;
    }
    g_deviceId = nodeBasicInfo[0].networkId;
    FreeNodeInfo(nodeBasicInfo);
}

void RpcClientTest::TearDownTestCase()
{
}

sptr<RpcTestServiceProxy> GetRemoteProxyObject()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        std::cout << "Failed to obtain samgr proxy object." << std::endl;
        return nullptr;
    }

    sptr<IRemoteObject> remoteProxy = samgrProxy->GetSystemAbility(RPC_TEST_SERVICE, g_deviceId);
    if (remoteProxy == nullptr) {
        std::cout << "Failed to obtain remote proxy object." << std::endl;
        return nullptr;
    }

    sptr<RpcTestServiceProxy> proxy = iface_cast<RpcTestServiceProxy>(remoteProxy);
    if (proxy == nullptr) {
        std::cout << "Iface_cast is failed." << std::endl;
        return nullptr;
    }
    return proxy;
}

/**
 * @tc.name: TestGetProto001
 * @tc.desc: verify whether the obtained object is a remote proxy object across devices.
 * @tc.type: FUNC
 */
HWTEST_F(RpcClientTest, TestGetProto001, TestSize.Level1)
{
    sptr<RpcTestServiceProxy> proxyObject = GetRemoteProxyObject();
    ASSERT_TRUE(proxyObject != nullptr) << "GetRemoteProxyObject is failed";
    ASSERT_EQ(proxyObject->TestGetProto(), IRemoteObject::IF_PROT_DATABUS);
}

/**
 * @tc.name: TestGetServiceName001
 * @tc.desc: Verify if the remote service name and local end are the same.
 * @tc.type: FUNC
 */
HWTEST_F(RpcClientTest, TestGetServiceName001, TestSize.Level1)
{
    sptr<RpcTestServiceProxy> proxyObject = GetRemoteProxyObject();
    ASSERT_TRUE(proxyObject != nullptr) << "GetRemoteProxyObject is failed";

    MessageOption option;
    MessageParcel data, reply;
    int32_t ret = proxyObject->TestGetServiceName(data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);

    std::string remoteName = reply.ReadString();
    std::string localName = proxyObject->GetServiceName();
    EXPECT_TRUE(remoteName == localName) << "remoteName: " << remoteName << " localName: " << localName;
}

/**
 * @tc.name: TestAccessToken001
 * @tc.desc: Verify if the remote service name and local end are the same.
 * @tc.type: FUNC
 */
HWTEST_F(RpcClientTest, TestAccessToken001, TestSize.Level1)
{
    sptr<RpcTestServiceProxy> proxyObject = GetRemoteProxyObject();
    ASSERT_TRUE(proxyObject != nullptr) << "GetRemoteProxyObject is failed";

    MessageOption option;
    MessageParcel data, reply;
    int32_t ret = proxyObject->TestAccessToken(data, reply, option);
    ASSERT_EQ(ret, ERR_NONE);

    uint32_t tokenId = IPCSkeleton::GetSelfTokenID();
    uint32_t getTokenId = reply.ReadUint32();
    EXPECT_EQ(tokenId, getTokenId);
}

/**
 * @tc.name: TestAddDeathRecipient001
 * @tc.desc: Verify if the remote service name and local end are the same.
 * @tc.type: FUNC
 */
HWTEST_F(RpcClientTest, TestAddDeathRecipient001, TestSize.Level1)
{
    sptr<RpcTestServiceProxy> proxyObject = GetRemoteProxyObject();
    ASSERT_TRUE(proxyObject != nullptr) << "GetRemoteProxyObject is failed";

    sptr<IRemoteObject::DeathRecipient> death(new RpcTestServiceDeathRecipient());
    EXPECT_TRUE(proxyObject->TestAddDeathRecipient(death.GetRefPtr()));
}

/**
 * @tc.name: ConcurrentGetSystemAbility001
 * @tc.desc: Multi threaded concurrent retrieval of remote proxy objects
 * @tc.type: FUNC
 */
HWTEST_F(RpcClientTest, TestSyncAdd001, TestSize.Level1)
{
    sptr<RpcTestServiceProxy> proxyObject = GetRemoteProxyObject();
    ASSERT_TRUE(proxyObject != nullptr) << "GetRemoteProxyObject is failed";

    MessageOption option;
    MessageParcel data, reply;
    int32_t value1 = 100;
    int32_t value2 = 200;

    data.WriteInt32(value1);
    data.WriteInt32(value2);
    int32_t ret = proxyObject->TestSyncAdd(data, reply, option);
    ASSERT_EQ(ret, ERR_NONE);
    int32_t sum = reply.ReadInt32();
    EXPECT_EQ(sum, (value1 + value2));
}

/**
 * @tc.name: TestGetSystemAbility001
 * @tc.desc: Multi threaded concurrent retrieval of remote proxy objects
 * @tc.type: FUNC
 */
HWTEST_F(RpcClientTest, TestGetSystemAbility001, TestSize.Level1)
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(samgrProxy != nullptr) << "Failed to obtain samgr proxy object.";

    std::set<sptr<IRemoteObject>> objectSet;
    std::mutex objectVecMutex;
    int32_t expectSize = 1;

    for (int32_t i = 0; i < 50; i++) {
        std::thread t([&samgrProxy, &objectSet, &objectVecMutex] {
            sptr<IRemoteObject> object = samgrProxy->GetSystemAbility(RPC_TEST_SERVICE, g_deviceId);
            EXPECT_TRUE(object != nullptr) << "Failed to obtain remote proxy object.";
            std::unique_lock<std::mutex> lockGuard(objectVecMutex);
            objectSet.insert(object);
        });
        t.detach();
    }
    sleep(1);
    EXPECT_EQ(objectSet.size(), expectSize);
}
}
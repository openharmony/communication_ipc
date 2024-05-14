/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "rpc_test.h"

#include <cstring>

#include "rpc_log.h"
#include "rpc_errno.h"
#include "ipc_skeleton.h"
#include "serializer.h"
#include "utils_list.h"
#include "dbinder_service.h"

typedef struct {
    UTILS_DL_LIST list;
    int32_t saId;
    SvcIdentity *sid;
} SvcInfo;

namespace {
UTILS_DL_LIST *g_saList = nullptr;

int32_t AddSystemAbility(int32_t saId, SvcIdentity *sid)
{
    if (saId <= INVALID_SAID) {
        return ERR_FAILED;
    }
    RPC_LOG_INFO("AddSystemAbility called.... handle = %d", sid->handle);
    RPC_LOG_INFO("AddSystemAbility called.... cookie = %u", sid->cookie);
    if (g_saList == nullptr) {
        return ERR_FAILED;
    }

    SvcInfo* node = (SvcInfo *)calloc(1, sizeof(SvcInfo));
    if (node == nullptr) {
        RPC_LOG_ERROR("AddSystemAbility node calloc failed");
        return ERR_FAILED;
    }
    node->saId = saId;
    node->sid = sid;
    UtilsListAdd(g_saList, &node->list);
    return ERR_NONE;
}

int32_t GetSystemAbility(int32_t saId, const char* deviceId, SvcIdentity *sid)
{
    SvcInfo* node = nullptr;
    SvcInfo* next = nullptr;
    UTILS_DL_LIST_FOR_EACH_ENTRY_SAFE(node, next, g_saList, SvcInfo, list)
    {
        if (node->saId == saId) {
            sid->handle = node->sid->handle;
            sid->token = node->sid->token;
            sid->cookie = node->sid->cookie;
            RPC_LOG_INFO("find sa, said = %d, handle = %d, cookie = %u", saId, sid->handle, sid->cookie);
            return ERR_NONE;
        }
    }
    return ERR_FAILED;
}

int32_t AddRemoteSystemAbility(int32_t saId, SvcIdentity *sid)
{
    if (AddSystemAbility(saId, sid) == ERR_FAILED) {
        RPC_LOG_ERROR("AddSystemAbility failed");
        return ERR_FAILED;
    }

    const char *name = "16";
    if (RegisterRemoteProxy(name, strlen(name), saId) != ERR_NONE) {
        RPC_LOG_ERROR("RegisterRemoteProxy failed");
        return ERR_FAILED;
    }

    return ERR_NONE;
}

int32_t GetRemoteSystemAbility(IpcIo *data, SvcIdentity *sid)
{
    int32_t saId;
    ReadInt32(data, &saId);
    if (saId <= INVALID_SAID) {
        return ERR_FAILED;
    }
    size_t len;
    const char *deviceId = (const char *)ReadString(data, &len);

    const char *name = "16";
    uint32_t idLen = (uint32_t)strlen(deviceId);
    RPC_LOG_INFO("GetRemoteSystemAbility start");

    int32_t ret = MakeRemoteBinder(name, 2, deviceId, idLen, (uintptr_t)saId, 0, (void *)sid);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("MakeRemoteBinder failed");
    }
    RPC_LOG_INFO("GetRemoteSystemAbility handle=%d, cookie=%u", sid->handle, sid->cookie);

    return ret;
}

static int32_t GetSystemAbilityTransaction(IpcIo *data, IpcIo *reply)
{
    int32_t saId;
    ReadInt32(data, &saId);
    SvcIdentity sid;
    int32_t result = GetSystemAbility(saId, "", &sid);
    WriteRemoteObject(reply, &sid);
    return result;
}

static int32_t AddRemoteSystemAbilityTransaction(IpcIo *data, IpcIo *reply)
{
    int32_t saId;
    ReadInt32(data, &saId);
    SvcIdentity *sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
    if (sid == nullptr) {
        return ERR_FAILED;
    }
    ReadRemoteObject(data, sid);
    int32_t result = AddRemoteSystemAbility(saId, sid);
    if (result != ERR_NONE) {
        WriteInt32(reply, result);
    }
    return result;
}

int32_t RemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("OnRemoteRequest called.... code = %u", code);
    switch (code) {
        case GET_SYSTEM_ABILITY_TRANSACTION: {
            result = GetSystemAbilityTransaction(data, reply);
            break;
        }
        case ADD_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId;
            ReadInt32(data, &saId);
            SvcIdentity *sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
            if (sid == nullptr) {
                result = ERR_FAILED;
                break;
            }
            ReadRemoteObject(data, sid);
            result = AddSystemAbility(saId, sid);
            break;
        }
        case GET_REMOTE_SYSTEM_ABILITY_TRANSACTION: {
            SvcIdentity sid;
            result = GetRemoteSystemAbility(data, &sid);
            if (result != ERR_NONE) {
                WriteInt32(reply, result);
            } else {
                WriteRemoteObject(reply, &sid);
            }
            break;
        }
        case ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION: {
            result = AddRemoteSystemAbilityTransaction(data, reply);
            break;
        }
        default:
            RPC_LOG_ERROR("unknown code %u", code);
            break;
    }
    return result;
}

int32_t mainFunc(void)
{
    RPC_LOG_INFO("Enter System Ability Manager .... ");

    g_saList = (UTILS_DL_LIST *)calloc(1, sizeof(UTILS_DL_LIST));
    if (g_saList == nullptr) {
        RPC_LOG_ERROR("g_saList calloc failed");
        return ERR_FAILED;
    }
    UtilsListInit(g_saList);
    return ERR_NONE;
}
}

using namespace testing::ext;

namespace OHOS {
class RpcSamgrTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        RPC_LOG_INFO("----------test case for rpc samgr start-------------\n");
        mainFunc();
    }
    static void TearDownTestCase()
    {
        RPC_LOG_INFO("----------test case for rpc samgr end -------------\n");
    }
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: RPC_SendRequestNum_02
 * @tc.desc: start dbinder service failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcSamgrTest, RpcSamgrTest001, TestSize.Level1)
{
    IpcObjectStub objectStub = {
        .func = RemoteRequest,
        .isRemote = false
    };

    SvcIdentity target = {
        .handle = 0,
        .cookie = NULL
    };

    int32_t ret = SetContextObject(target);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    RPC_LOG_ERROR("SAMGR register samgr failed");

    return;
}

/**
 * @tc.name: RPC_SendRequestNum_01
 * @tc.desc: start dbinder service success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcSamgrTest, RpcSamgrTest002, TestSize.Level0)
{
    IpcObjectStub objectStub = {
        .func = RemoteRequest,
        .isRemote = false
    };

    SvcIdentity target = {
        .handle = 0,
        .cookie = (uintptr_t)&objectStub
    };

    if (SetContextObject(target) != ERR_NONE) {
        RPC_LOG_ERROR("SAMGR register samgr failed");
        return;
    }

    int32_t ret = StartDBinderService();
    EXPECT_EQ(ret, ERR_NONE);
    RPC_LOG_INFO("StartDBinderService finished");

    JoinWorkThread();
}
}  // namespace OHOS
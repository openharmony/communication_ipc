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

#include "gtest/gtest.h"

#include "ipc_proxy.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "serializer.h"
#include "utils_list.h"

typedef struct {
    UTILS_DL_LIST list;
    int32_t saId;
    SvcIdentity *sid;
} SvcInfo;

namespace {
UTILS_DL_LIST *g_saList = nullptr;
int32_t g_saSum = 0;

int32_t AddSystemAbility(int32_t saId, SvcIdentity *sid)
{
    if (g_saList == nullptr) {
        return ERR_FAILED;
    }

    SvcInfo* node = (SvcInfo *)calloc(1, sizeof(SvcInfo));
    if (node == nullptr) {
        return ERR_FAILED;
    }
    node->saId = saId;
    node->sid = sid;
    UtilsListAdd(g_saList, &node->list);
    g_saSum++;
    RPC_LOG_INFO("samgr sa count = %d", g_saSum);
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
            return ERR_NONE;
        }
    }
    return ERR_FAILED;
}

int32_t RemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("OnRemoteRequest called.... code = %u", code);
    RPC_LOG_INFO("calling pid = %d, uid = %d", GetCallingPid(), GetCallingUid());
    switch (code) {
        case ADD_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId;
            ReadInt32(data, &saId);
            RPC_LOG_INFO("samgr pop said = %d....", saId);
            SvcIdentity *sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
            ReadRemoteObject(data, sid);
            result = AddSystemAbility(saId, sid);
            if (result != ERR_NONE) {
                return result;
            }
            WriteInt32(reply, result);
            break;
        }
        case GET_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId;
            ReadInt32(data, &saId);
            SvcIdentity sid;
            result = GetSystemAbility(saId, "", &sid);
            if (result != ERR_NONE) {
                return result;
            }
            WriteRemoteObject(reply, &sid);
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
    pid_t pid = fork();
    if (pid != 0) {
        exit(0);
    }
    RPC_LOG_INFO("Enter System Ability Manager .... ");

    g_saList = (UTILS_DL_LIST *)calloc(1, sizeof(UTILS_DL_LIST));
    if (g_saList == nullptr) {
        return -1;
    }
    UtilsListInit(g_saList);
    return ERR_NONE;
}
}

using namespace testing::ext;

namespace OHOS {
class IpcSamgrTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        RPC_LOG_INFO("----------test case for samgr start-------------\n");
        mainFunc();
    }
    static void TearDownTestCase()
    {
        RPC_LOG_INFO("----------test case for samgr end -------------\n");
    }
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(IpcSamgrTest, IpcSamgrTest001, TestSize.Level0)
{
    IpcObjectStub objectStub = {
        .func = RemoteRequest,
        .isRemote = false
    };

    SvcIdentity target = {
        .handle = 0,
        .cookie = (uintptr_t)&objectStub
    };

    int ret = SetContextObject(target);
    EXPECT_EQ(ret, ERR_NONE);

    JoinWorkThread();
}
}  // namespace OHOS
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

#include <stdlib.h>
#include <string.h>

#include "rpc_log.h"
#include "rpc_errno.h"
#include "ipc_skeleton.h"
#include "serializer.h"
#include "utils_list.h"

typedef struct {
    UTILS_DL_LIST list;
    int32_t saId;
    SvcIdentity *sid;
} SvcInfo;

static UTILS_DL_LIST *g_saList = NULL;

enum {
    GET_SYSTEM_ABILITY_TRANSACTION = 1,
    ADD_SYSTEM_ABILITY_TRANSACTION = 2,
    GET_REMOTE_SYSTEM_ABILITY_TRANSACTION = 3,
    ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION = 4,
};

int32_t AddSystemAbility(int32_t saId, SvcIdentity *sid)
{
    if (g_saList == NULL) {
        return ERR_FAILED;
    }

    SvcInfo* node = (SvcInfo *)calloc(1, sizeof(SvcInfo));
    node->saId = saId;
    node->sid = sid;
    UtilsListAdd(g_saList, &node->list);
    return 23;
}

int32_t GetSystemAbility(int32_t saId, const char* deviceId, SvcIdentity *sid)
{
    SvcInfo* node = NULL;
    SvcInfo* next = NULL;
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
    RPC_LOG_INFO("OnRemoteRequest called.... code = %{public}d", code);
    switch (code) {
        case ADD_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId = IpcIoPopInt32(data);
            RPC_LOG_INFO("samgr pop said = %{public}d....", saId);
            SvcIdentity *sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
            IpcIoPopSvc(data, sid);
            result = AddSystemAbility(saId, sid);
            break;
        }
        case GET_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId = IpcIoPopInt32(data);
            SvcIdentity sid;
            result = GetSystemAbility(saId, "", &sid);
            if (result != ERR_NONE) {
                return result;
            }
            IpcIoPushSvc(reply, &sid);
            break;
        }
        default:
            RPC_LOG_ERROR("unknown code %{public}d", code);
            break;
    }
    return result;
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("Enter System Ability Manager .... ");

    g_saList = (UTILS_DL_LIST *)calloc(1, sizeof(UTILS_DL_LIST));
    UtilsListInit(g_saList);

    IpcObjectStub objectStub = {
        .func = RemoteRequest,
        .isRemote = false
    };

    SvcIdentity target = {
        .handle = 0,
        .cookie = &objectStub
    };

    if (SetContextObject(target) != ERR_NONE) {
        RPC_LOG_ERROR("SAMGR register samgr failed");
        return -1;
    }

    JoinWorkThread();
    return -1;
}
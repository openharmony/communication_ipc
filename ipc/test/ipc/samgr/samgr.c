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

#include "doubly_linked_list.h"
#include "ipc_proxy.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "serializer.h"

typedef struct {
    DL_LIST list;
    int32_t saId;
    SvcIdentity *sid;
} SvcInfo;

static DL_LIST *g_saList = NULL;

static int32_t AddSystemAbility(int32_t saId, SvcIdentity *sid)
{
    if (g_saList == NULL) {
        return ERR_FAILED;
    }

    SvcInfo* node = (SvcInfo *)calloc(1, sizeof(SvcInfo));
    if (node == NULL) {
        return ERR_FAILED;
    }
    node->saId = saId;
    node->sid = sid;
    DLListAdd(g_saList, &node->list);
    return ERR_NONE;
}

static int32_t GetSystemAbility(int32_t saId, const char* deviceId, SvcIdentity *sid)
{
    (void)deviceId;
    SvcInfo* node = NULL;
    SvcInfo* next = NULL;
    DL_LIST_FOR_EACH_ENTRY_SAFE(node, next, g_saList, SvcInfo, list)
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

static int32_t RemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("OnRemoteRequest called.... code = %u", code);
    switch (code) {
        case ADD_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId;
            ReadInt32(data, &saId);
            SvcIdentity *sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
            if (sid == NULL) {
                return ERR_FAILED;
            }
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

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("Enter System Ability Manager .... ");

    g_saList = (DL_LIST *)calloc(1, sizeof(DL_LIST));
    DLListInit(g_saList);

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
        return -1;
    }

    JoinWorkThread();
    return -1;
}
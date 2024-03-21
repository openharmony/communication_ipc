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

#include "dbinder_service.h"
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

static UTILS_DL_LIST *g_saList = NULL;

enum {
    GET_SYSTEM_ABILITY_TRANSACTION = 1,
    ADD_SYSTEM_ABILITY_TRANSACTION = 2,
    GET_REMOTE_SYSTEM_ABILITY_TRANSACTION = 3,
    ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION = 4,
};

static int32_t AddSystemAbility(int32_t saId, SvcIdentity *sid)
{
    RPC_LOG_INFO("AddSystemAbility called.... handle = %d", sid->handle);
    RPC_LOG_INFO("AddSystemAbility called.... cookie = %u", sid->cookie);
    if (g_saList == NULL) {
        return ERR_FAILED;
    }

    SvcInfo* node = (SvcInfo *)calloc(1, sizeof(SvcInfo));
    if (node == NULL) {
        RPC_LOG_ERROR("AddSystemAbility node calloc failed");
        return ERR_FAILED;
    }
    node->saId = saId;
    node->sid = sid;
    UtilsListAdd(g_saList, &node->list);
    return ERR_NONE;
}

static int32_t GetSystemAbility(int32_t saId, const char* deviceId, SvcIdentity *sid)
{
    SvcInfo* node = NULL;
    SvcInfo* next = NULL;
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

static int32_t AddRemoteSystemAbility(int32_t saId, SvcIdentity *sid)
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

static int32_t GetRemoteSystemAbility(IpcIo *data, SvcIdentity *sid)
{
    int32_t saId;
    ReadInt32(data, &saId);
    size_t len;
    const char *deviceId = (const char *)ReadString(data, &len);

    const char *name = "16";
    uint32_t nameLen = 2;
    uint32_t idLen = (uint32_t)strlen(deviceId);
    RPC_LOG_INFO("GetRemoteSystemAbility start");

    int32_t ret = MakeRemoteBinder(name, nameLen, deviceId, idLen, (uintptr_t)saId, 0, (void *)sid);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("MakeRemoteBinder failed");
    }
    RPC_LOG_INFO("GetRemoteSystemAbility handle=%d, cookie=%u", sid->handle, sid->cookie);

    return ret;
}

static int32_t RemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("OnRemoteRequest called.... code = %u", code);
    switch (code) {
        case GET_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId;
            ReadInt32(data, &saId);
            SvcIdentity sid;
            result = GetSystemAbility(saId, "", &sid);
            WriteRemoteObject(reply, &sid);
            break;
        }
        case ADD_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId;
            ReadInt32(data, &saId);
            SvcIdentity *sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
            if (sid == NULL) {
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
            WriteRemoteObject(reply, &sid);
            break;
        }
        case ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION: {
            int32_t saId;
            ReadInt32(data, &saId);
            SvcIdentity *sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
            if (sid == NULL) {
                result = ERR_FAILED;
                break;
            }
            ReadRemoteObject(data, sid);
            result = AddRemoteSystemAbility(saId, sid);
            break;
        }
        default:
            RPC_LOG_ERROR("unknown code %d", code);
            break;
    }
    return result;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    RPC_LOG_INFO("Enter System Ability Manager .... ");

    g_saList = (UTILS_DL_LIST *)calloc(1, sizeof(UTILS_DL_LIST));
    UtilsListInit(g_saList);

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

    StartDBinderService();
    RPC_LOG_INFO("StartDBinderService finished");

    JoinWorkThread();
    return -1;
}
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

#include "rpc_mini_samgr.h"

#include <stdlib.h>
#include <string.h>

#include "dbinder_service.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "securec.h"
#include "serializer.h"
#include "utils_list.h"

typedef struct {
    UTILS_DL_LIST list;
    int32_t saId;
    SvcIdentity *sid;
} SvcInfo;

static UTILS_DL_LIST *g_saList = NULL;
static pthread_mutex_t g_handleMutex = PTHREAD_MUTEX_INITIALIZER;
static int32_t g_handle = 0;

static int32_t GetNextHandle(void)
{
    pthread_mutex_lock(&g_handleMutex);
    int32_t handle = ++g_handle;
    pthread_mutex_unlock(&g_handleMutex);
    return handle;
}

int32_t AddSystemAbility(int32_t saId, SvcIdentity *sid)
{
    RPC_LOG_INFO("AddSystemAbility called.... handle = %d", sid->handle);
    RPC_LOG_INFO("AddSystemAbility called.... cookie = %u, said = %d", sid->cookie, saId);
    if (g_saList == NULL) {
        return ERR_FAILED;
    }

    SvcInfo* node = (SvcInfo *)calloc(1, sizeof(SvcInfo));
    if (node == NULL) {
        RPC_LOG_ERROR("AddSystemAbility node calloc failed");
        return ERR_FAILED;
    }
    node->saId = saId;
    node->sid = (SvcIdentity *)calloc(1, sizeof(SvcIdentity));
    if (memcpy_s(node->sid, sizeof(SvcIdentity), sid, sizeof(SvcIdentity)) != EOK) {
        RPC_LOG_INFO("AddSystemAbility memcpy failed");
        free(node->sid);
        free(node);
        return ERR_FAILED;
    }

    node->sid->handle = GetNextHandle();
    UtilsListAdd(g_saList, &node->list);
    return ERR_NONE;
}

int32_t GetSystemAbilityById(int32_t systemAbility, IpcIo *reply)
{
    SvcInfo* node = NULL;
    SvcInfo* next = NULL;
    UTILS_DL_LIST_FOR_EACH_ENTRY_SAFE(node, next, g_saList, SvcInfo, list)
    {
        RPC_LOG_INFO("GetSystemAbilityById %d", node->saId);
        if (node->saId == systemAbility) {
            WriteRemoteObject(reply, node->sid);
            reply->bufferCur = reply->bufferBase;
            reply->offsetsCur = reply->offsetsBase;
            return ERR_NONE;
        }
    }
    return ERR_FAILED;
}

int32_t AddRemoteSystemAbility(IpcIo *data)
{
    int32_t saId;
    ReadInt32(data, &saId);
    SvcIdentity sid;
    ReadRemoteObject(data, &sid);
    if (AddSystemAbility(saId, &sid) == ERR_FAILED) {
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

int32_t GetRemoteSystemAbility(int32_t saId, const char* deviceId, IpcIo *reply)
{
    RPC_LOG_INFO("GetRemoteSystemAbility start");
    const char *name = "16";
    uint32_t nameLen = 2;
    uint32_t idLen = (uint32_t)strlen(deviceId);

    SvcIdentity sid;
    int32_t ret = MakeRemoteBinder(name, nameLen, deviceId, idLen, (uintptr_t)saId, 0, &sid);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("MakeRemoteBinder failed");
    }
    sid.handle = GetNextHandle();
    RPC_LOG_INFO("GetRemoteSystemAbility sid handle=%d", sid.handle);
    WriteRemoteObject(reply, &sid);
    reply->bufferCur = reply->bufferBase;
    reply->offsetsCur = reply->offsetsBase;

    return ret;
}

void RpcStartSamgr(void)
{
    RPC_LOG_INFO("RpcStartSamgr start");
    g_saList = (UTILS_DL_LIST *)calloc(1, sizeof(UTILS_DL_LIST));
    UtilsListInit(g_saList);

    SvcIdentity target = {
        .cookie = 0
    };
    (void)SetContextObject(target);

    StartDBinderService();
    RPC_LOG_INFO("StartDBinderService finished");

    return;
}
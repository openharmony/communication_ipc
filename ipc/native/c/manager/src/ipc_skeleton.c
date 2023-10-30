/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "ipc_skeleton.h"

#include "ipc_process_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_types.h"
#include "securec.h"
#include "utils_list.h"

static const int COOKIE_NULL = 0;
static const int INVALID_HANDLE = 0;

// default is 4 max is 16
int32_t SetMaxWorkThreadNum(int32_t maxThreadNum)
{
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    if ((maxThreadNum < SET_MAX_THREADS_DEFAULT) || (maxThreadNum > SET_MAX_THREADS_MAX)) {
        RPC_LOG_ERROR("max thread num is invalid.");
        return ERR_INVALID_PARAM;
    }
    return SetMaxWorkThread(maxThreadNum);
}

// join current thread into work loop.
void JoinWorkThread(void)
{
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return;
    }
    return JoinMainWorkThread();
}

pid_t GetCallingPid(void)
{
    return ProcessGetCallingPid();
}

pid_t GetCallingUid(void)
{
    return ProcessGetCallingUid();
}

const SvcIdentity *GetContextObject(void)
{
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return NULL;
    }
    return GetRegistryObject();
}

int32_t SetContextObject(SvcIdentity target)
{
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    if (target.cookie == COOKIE_NULL) {
        RPC_LOG_ERROR("samgr stub func is NULL.");
        return ERR_INVALID_PARAM;
    }
    return SetRegistryObject(target);
}

int32_t SendRequest(SvcIdentity target, uint32_t code, IpcIo *data, IpcIo *reply,
    MessageOption option, uintptr_t *buffer)
{
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    return ProcessSendRequest(target, code, data, reply, option, buffer);
}

int32_t AddDeathRecipient(SvcIdentity target, OnRemoteDead deathFunc, void *args, uint32_t *cbId)
{
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    if (target.handle < INVALID_HANDLE) {
        RPC_LOG_ERROR("add death recipient is invalid handle.");
        return ERR_INVALID_PARAM;
    }
    return ProcessAddDeathRecipient(target.handle, deathFunc, args, cbId);
}

int32_t RemoveDeathRecipient(SvcIdentity target, uint32_t cbId)
{
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    if (target.handle < INVALID_HANDLE) {
        RPC_LOG_ERROR("add death recipient is invalid handle.");
        return ERR_INVALID_PARAM;
    }
    return ProcessRemoveDeathRecipient(target.handle, cbId);
}

int32_t FreeBuffer(void *ptr)
{
    if (ptr == NULL) {
        RPC_LOG_ERROR("ptr is null, no data to free");
        return ERR_INVALID_PARAM;
    }
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    return ProcessFreeBuffer(ptr);
}

int32_t MessageOptionInit(MessageOption *option)
{
    if (option == NULL) {
        RPC_LOG_ERROR("option is null");
        return ERR_INVALID_PARAM;
    }
    option->flags = TF_OP_SYNC;
    option->waitTime = RPC_DEFAULT_SEND_WAIT_TIME;
    option->args = NULL;
    return ERR_NONE;
}

int32_t ReleaseSvc(SvcIdentity target)
{
    if (GetCurrentSkeleton() == NULL) {
        RPC_LOG_ERROR("init ipc process skeleton failed.");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    if (target.handle <= INVALID_HANDLE) {
        RPC_LOG_ERROR("release svc is invalid handle.");
        return ERR_INVALID_PARAM;
    }
    return DeleteHandle(target.handle);
}
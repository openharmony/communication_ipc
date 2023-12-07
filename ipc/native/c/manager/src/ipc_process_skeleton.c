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

#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_skeleton_pri.h"
#include "ipc_thread_pool.h"
#include "iremote_invoker.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_os_adapter.h"
#include "rpc_process_skeleton.h"
#include "rpc_types.h"
#include "securec.h"
#include "utils_list.h"

static IpcSkeleton *g_ipcSkeleton = NULL;
static pthread_mutex_t g_ipcSkeletonMutex = PTHREAD_MUTEX_INITIALIZER;
static SvcIdentity g_samgrSvc = {
    .handle = 0,
    .token = 0,
    .cookie = 0
};

static void DeleteIpcSkeleton(IpcSkeleton *temp)
{
    if (temp == NULL) {
        return;
    }
    DeinitThreadPool(temp->threadPool);
    free(temp);
}

static IpcSkeleton* IpcProcessSkeleton()
{
    IpcSkeleton *temp = (IpcSkeleton *)calloc(1, sizeof(IpcSkeleton));
    if (temp == NULL) {
        RPC_LOG_ERROR("create ipc skeleton failed.");
        return NULL;
    }
    temp->threadPool = InitThreadPool(SET_MAX_THREADS_DEFAULT);
    if (temp->threadPool == NULL) {
        free(temp);
        RPC_LOG_ERROR("init thread pool failed.");
        return NULL;
    }
    RemoteInvoker *invoker = GetRemoteInvoker();
    if (invoker == NULL) {
        DeleteIpcSkeleton(temp);
        RPC_LOG_ERROR("get remote invoker failed.");
        return NULL;
    }
    if ((invoker->SetMaxWorkThread)(SET_MAX_THREADS_DEFAULT) != ERR_NONE) {
        DeleteIpcSkeleton(temp);
        RPC_LOG_ERROR("init thread context failed.");
        return NULL;
    }
    SpawnNewThread(temp->threadPool, SPAWN_ACTIVE, IF_PROT_BINDER);
    UtilsListInit(&temp->objects);
    pthread_mutex_init(&temp->lock, NULL);
    return temp;
}

IpcSkeleton *GetCurrentSkeleton(void)
{
    if (g_ipcSkeleton == NULL) {
        if (pthread_mutex_lock(&g_ipcSkeletonMutex) != 0) {
            RPC_LOG_ERROR("init ipc skeleton lock failed.");
            return NULL;
        }
        if (g_ipcSkeleton == NULL) {
            IpcSkeleton *temp = IpcProcessSkeleton();
            if (temp == NULL) {
                pthread_mutex_unlock(&g_ipcSkeletonMutex);
                RPC_LOG_ERROR("create binder connector failed.");
                return NULL;
            }
            g_ipcSkeleton = temp;
            int32_t ret = RpcProcessSkeleton();
            if (ret != ERR_NONE) {
                RPC_LOG_ERROR("rpc process skeleton init failed");
            }
        }
        pthread_mutex_unlock(&g_ipcSkeletonMutex);
    }
    return g_ipcSkeleton;
}

int32_t SpawnThread(int32_t policy, int32_t proto)
{
    if (g_ipcSkeleton == NULL || g_ipcSkeleton->threadPool == NULL) {
        RPC_LOG_ERROR("ipc skeleton not init");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    return SpawnNewThread(g_ipcSkeleton->threadPool, policy, proto);
}

int32_t SetMaxWorkThread(int32_t maxThreadNum)
{
    if (g_ipcSkeleton == NULL || g_ipcSkeleton->threadPool == NULL) {
        RPC_LOG_ERROR("ipc skeleton not init");
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    UpdateMaxThreadNum(g_ipcSkeleton->threadPool, maxThreadNum);

    RemoteInvoker *invoker = GetRemoteInvoker();
    if (invoker != NULL) {
        return (invoker->SetMaxWorkThread)(maxThreadNum);
    }
    RPC_LOG_ERROR("current thread context not init");
    return ERR_THREAD_INVOKER_NOT_INIT;
}

void JoinMainWorkThread(void)
{
    RemoteInvoker *invoker = GetRemoteInvoker();
    if (invoker != NULL) {
        (invoker->JoinThread)(true);
    }
}

pid_t ProcessGetCallingPid(void)
{
    if (g_ipcSkeleton != NULL) {
        ThreadContext *currentContext = GetCurrentThreadContext();
        if (currentContext != NULL) {
            return currentContext->callerPid;
        }
    }
    return RpcGetPid();
}

pid_t ProcessGetCallingUid(void)
{
    if (g_ipcSkeleton != NULL) {
        ThreadContext *currentContext = GetCurrentThreadContext();
        if (currentContext != NULL) {
            return currentContext->callerUid;
        }
    }
    return RpcGetUid();
}

const SvcIdentity *GetRegistryObject(void)
{
    return &g_samgrSvc;
}

int32_t SetRegistryObject(SvcIdentity target)
{
    int32_t ret = ERR_THREAD_INVOKER_NOT_INIT;
    RemoteInvoker *invoker = GetRemoteInvoker();
    if (invoker != NULL) {
        ret = (invoker->SetRegistryObject)(target, &g_samgrSvc);
    }
    return ret;
}

int32_t DeleteHandle(int32_t handle)
{
    if (pthread_mutex_lock(&g_ipcSkeleton->lock) != 0) {
        RPC_LOG_ERROR("Get ipc skeleton mutex failed.");
        return ERR_FAILED;
    }
    DeathCallback *node = NULL;
    DeathCallback *next = NULL;
    bool isValidHandle = false;
    int32_t ret = ERR_INVALID_PARAM;
    UTILS_DL_LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_ipcSkeleton->objects, DeathCallback, list)
    {
        if (node->handle == handle) {
            isValidHandle = true;
            pthread_mutex_destroy(&node->lock);
            UtilsListDelete(&node->list);
            free(node);
            break;
        }
    }
    pthread_mutex_unlock(&g_ipcSkeleton->lock);
    if (isValidHandle) {
        RemoteInvoker *invoker = GetRemoteInvoker();
        if (invoker != NULL) {
            (invoker->ReleaseHandle)(handle);
        }
        ret = ERR_NONE;
    }
    return ret;
}

int32_t ProcessSendRequest(SvcIdentity target, uint32_t code, IpcIo *data, IpcIo *reply,
    MessageOption option, uintptr_t *buffer)
{
    int32_t ret = ERR_THREAD_INVOKER_NOT_INIT;
    RemoteInvoker *invoker = GetRemoteInvoker();
    if (invoker != NULL) {
        ret = (invoker->SendRequest)(target, code, data, reply, option, buffer);
    }
    return ret;
}

int32_t ProcessFreeBuffer(void *ptr)
{
    RemoteInvoker *invoker = GetRemoteInvoker();
    if (invoker != NULL) {
        return (invoker->FreeBuffer)(ptr);
    }
    return ERR_THREAD_INVOKER_NOT_INIT;
}

static bool FirstAddObject(int32_t handle)
{
    if (pthread_mutex_lock(&g_ipcSkeleton->lock) != 0) {
        RPC_LOG_ERROR("Get ipc skeleton mutex failed.");
        return false;
    }
    DeathCallback *node = NULL;
    DeathCallback *next = NULL;
    UTILS_DL_LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_ipcSkeleton->objects, DeathCallback, list)
    {
        if (node->handle == handle) {
            RPC_LOG_INFO("current handle already exist");
            pthread_mutex_unlock(&g_ipcSkeleton->lock);
            return false;
        }
    }
    node = (DeathCallback*)calloc(1, sizeof(DeathCallback));
    if (node == NULL) {
        pthread_mutex_unlock(&g_ipcSkeleton->lock);
        return false;
    }

    node->handle = handle;
    node->deathNum = 0;
    node->isRemoteDead = false;
    node->isNewHandler = true;
    pthread_mutex_init(&node->lock, NULL);
    UtilsListAdd(&g_ipcSkeleton->objects, &node->list);
    pthread_mutex_unlock(&g_ipcSkeleton->lock);
    return true;
}

void OnFirstStrongRef(int32_t handle)
{
    if (handle <= 0) {
        RPC_LOG_ERROR("invalid handle.");
        return;
    }
    if (FirstAddObject(handle)) {
        RemoteInvoker *invoker = GetRemoteInvoker();
        if (invoker != NULL) {
            (invoker->AcquireHandle)(handle);
        }
    }
}

static uint32_t SetDeathHandlerPair(DeathCallback *node, uint32_t index, OnRemoteDead func, void* args)
{
    node->handler[index].usedFlag = true;
    node->handler[index].func = func;
    node->handler[index].args = args;
    node->deathNum++;
    return index;
}

int32_t ProcessAddDeathRecipient(int32_t handle, OnRemoteDead deathFunc, void *args, uint32_t *cbId)
{
    int32_t ret = ERR_INVALID_PARAM;
    if (g_ipcSkeleton == NULL) {
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    if (deathFunc == NULL || cbId == NULL) {
        return ERR_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_ipcSkeleton->lock) != 0) {
        return ERR_FAILED;
    }
    DeathCallback *node = NULL;
    DeathCallback *next = NULL;
    bool firstDeathNode = false;
    UTILS_DL_LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_ipcSkeleton->objects, DeathCallback, list)
    {
        if (node->handle != handle) {
            continue;
        }
        if (node->isRemoteDead) {
            pthread_mutex_unlock(&g_ipcSkeleton->lock);
            return ERR_DEAD_OBJECT;
        }
        if (node->deathNum == MAX_DEATH_CALLBACK_NUM) {
            pthread_mutex_unlock(&g_ipcSkeleton->lock);
            return ERR_INVALID_PARAM;
        }
        (void)pthread_mutex_lock(&node->lock);
        for (int i = 0; i < MAX_DEATH_CALLBACK_NUM; i++) {
            if (!node->handler[i].usedFlag) {
                *cbId = SetDeathHandlerPair(node, i, deathFunc, args);
                ret = ERR_NONE;
                break;
            }
        }
        pthread_mutex_unlock(&node->lock);
        if (node->deathNum == 1 && node->isNewHandler) {
            firstDeathNode = true;
            node->isNewHandler = false;
        }
        break;
    }
    pthread_mutex_unlock(&g_ipcSkeleton->lock);
    if (firstDeathNode) {
        RPC_LOG_ERROR("first add death callback for handle = %d.", handle);
        RemoteInvoker *invoker = GetRemoteInvoker();
        ret = ERR_INVALID_PARAM;
        if (invoker != NULL) {
            ret = (invoker->AddDeathRecipient)(handle, node);
        }
    }
    return ret;
}

int32_t ProcessRemoveDeathRecipient(int32_t handle, uint32_t cbId)
{
    int32_t ret = ERR_INVALID_PARAM;
    if (g_ipcSkeleton == NULL) {
        return ERR_IPC_SKELETON_NOT_INIT;
    }
    if (cbId >= MAX_DEATH_CALLBACK_NUM) {
        RPC_LOG_ERROR("invalid callback id.");
        return ERR_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_ipcSkeleton->lock) != 0) {
        return ERR_FAILED;
    }
    DeathCallback *node = NULL;
    DeathCallback *next = NULL;
    UTILS_DL_LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_ipcSkeleton->objects, DeathCallback, list)
    {
        if (node->handle != handle) {
            continue;
        }
        if (node->isRemoteDead) {
            RPC_LOG_ERROR("service is dead, delete it later.");
            pthread_mutex_unlock(&g_ipcSkeleton->lock);
            return ERR_DEAD_OBJECT;
        }
        (void)pthread_mutex_lock(&node->lock);
        if (node->handler[cbId].usedFlag) {
            node->handler[cbId].usedFlag = false;
            node->handler[cbId].func = NULL;
            node->deathNum--;
            ret = ERR_NONE;
        }
        (void)pthread_mutex_unlock(&node->lock);
        break;
    }
    pthread_mutex_unlock(&g_ipcSkeleton->lock);
    return ret;
}

int32_t OnRemoteRequestInner(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option, IpcObjectStub *objectStub)
{
    int32_t result = RpcOnRemoteRequestInner(code, data, reply, option, objectStub);
    if (result == ERR_NOT_RPC) {
        if (objectStub != NULL && objectStub->func != NULL) {
            result = (OnRemoteRequest)(objectStub->func)(code, data, reply, option);
        }
    }
    return result;
}

void SendObituary(DeathCallback *deathCallback)
{
    (void)pthread_mutex_lock(&deathCallback->lock);
    int32_t deathNum = deathCallback->deathNum;
    DeathHandler handler[deathNum];
    deathCallback->isRemoteDead = true;
    if (deathNum > 0) {
        int32_t index = 0;
        for (int32_t i = 0; i < MAX_DEATH_CALLBACK_NUM && index < deathNum; i++) {
            if (deathCallback->handler[i].usedFlag && deathCallback->handler[i].func != NULL) {
                handler[index].func = deathCallback->handler[i].func;
                handler[index].args = deathCallback->handler[i].args;
                ++index;
            }
        }
        RemoteInvoker *invoker = GetRemoteInvoker();
        if (invoker != NULL) {
            (invoker->RemoveDeathRecipient)(deathCallback->handle, deathCallback);
        }
    }
    pthread_mutex_unlock(&deathCallback->lock);
    for (int32_t i = 0; i < deathNum; i++) {
        handler[i].func(handler[i].args);
    }
}

void WaitForProxyInit(SvcIdentity *svc)
{
    if (svc == NULL) {
        RPC_LOG_ERROR("invalid svc.");
        return;
    }
    RPC_LOG_INFO("ipc skeleton wait for proxy init");
    OnFirstStrongRef(svc->handle);
    UpdateProtoIfNeed(svc);
}

void DeleteDeathCallback(DeathCallback *deathCallback)
{
    UtilsListDelete(&deathCallback->list);
    pthread_mutex_destroy(&deathCallback->lock);
    free(deathCallback);
}

static void DeleteAllNode(void)
{
    if (g_ipcSkeleton == NULL) {
        RPC_LOG_ERROR("invalid ipcSkeleton");
        return;
    }
    (void)pthread_mutex_lock(&g_ipcSkeleton->lock);
    DeathCallback *node = NULL;
    DeathCallback *next = NULL;
    UTILS_DL_LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_ipcSkeleton->objects, DeathCallback, list)
    {
        pthread_mutex_destroy(&node->lock);
        UtilsListDelete(&node->list);
        free(node);
    }
    pthread_mutex_unlock(&g_ipcSkeleton->lock);
}

void ResetIpc(void)
{
    RPC_LOG_INFO("ResetIpc called");
    RemoteInvoker *invoker = GetRemoteInvoker();
    if (invoker != NULL && invoker->InvokerResetIpc != NULL) {
        (invoker->InvokerResetIpc)();
    }
    DeleteAllNode();
#ifdef IPC_RESET_SKELETON
    DeleteIpcSkeleton(g_ipcSkeleton);
    g_ipcSkeleton = NULL;
    g_ipcSkeleton = IpcProcessSkeleton();
#endif
}
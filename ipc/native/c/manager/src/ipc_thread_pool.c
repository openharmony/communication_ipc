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

#include "ipc_thread_pool.h"

#include <unistd.h>

#include "ipc_process_skeleton.h"
#include "iremote_invoker.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_os_adapter.h"
#include "rpc_types.h"
#include "securec.h"

#define PROTO_NUM 2

static pthread_key_t g_localKey = -1;
static RemoteInvoker *g_invoker[PROTO_NUM];

ThreadContext *GetCurrentThreadContext(void)
{
    ThreadContext *current = NULL;
    void *curTLS = pthread_getspecific(g_localKey);
    if (curTLS != NULL) {
        current = (ThreadContext *)curTLS;
    } else {
        current = (ThreadContext *)calloc(1, sizeof(ThreadContext));
        if (current == NULL) {
            return NULL;
        }
        current->threadId = pthread_self();
        current->proto = IF_PROT_DEFAULT;
        current->callerPid = RpcGetPid();
        current->callerUid = RpcGetUid();
        pthread_setspecific(g_localKey, current);
    }
    return current;
}

static void TlsDestructor(void *args)
{
    ThreadContext *threadContext = (ThreadContext *)args;
    RemoteInvoker *invoker = g_invoker[threadContext->proto];
    free(threadContext);
    if (invoker != NULL && invoker->ExitCurrentThread != NULL) {
        (invoker->ExitCurrentThread)();
    }
}

static void ThreadContextDestructor(int32_t proto)
{
    ThreadPool *threadPool = GetCurrentSkeleton()->threadPool;
    pthread_mutex_lock(&threadPool->lock);
    if (proto == IF_PROT_BINDER) {
        ++threadPool->idleThreadNum;
    } else if (proto == IF_PROT_DATABUS) {
        ++threadPool->idleSocketThreadNum;
    }
    pthread_mutex_unlock(&threadPool->lock);
}

static RemoteInvoker *GetAndUpdateInvoker(int32_t proto)
{
    ThreadContext *threadContext = GetCurrentThreadContext();
    if (threadContext == NULL) {
        return NULL;
    }
    threadContext->proto = proto;
    return g_invoker[proto];
}

static void *ThreadHandler(void *args)
{
    ThreadContext *threadContext = (ThreadContext *)args;
    int32_t proto = threadContext->proto;
    int32_t policy = threadContext->policy;
    free(threadContext);
    threadContext = NULL;
    RemoteInvoker *invoker = GetAndUpdateInvoker(proto);
    if (invoker != NULL) {
        switch (policy) {
            case SPAWN_PASSIVE:
                invoker->JoinThread(false);
                break;
            case SPAWN_ACTIVE:
                invoker->JoinThread(true);
                break;
            default:
                break;
        }
    }
    ThreadContextDestructor(proto);
    return NULL;
}

ThreadPool *InitThreadPool(int32_t maxThreadNum)
{
    ThreadPool *threadPool = (ThreadPool*)calloc(1, sizeof(ThreadPool));
    if (threadPool == NULL) {
        return NULL;
    }
    threadPool->maxThreadNum = maxThreadNum + maxThreadNum;
    threadPool->idleThreadNum = maxThreadNum;
    threadPool->idleSocketThreadNum = maxThreadNum;
    pthread_mutex_init(&threadPool->lock, NULL);
    pthread_key_create(&g_localKey, TlsDestructor);
    for (int32_t index = 0; index < PROTO_NUM; ++index) {
        g_invoker[index] = InitRemoteInvoker(index);
    }
    return threadPool;
}

void DeinitThreadPool(ThreadPool *threadPool)
{
    if (threadPool == NULL) {
        return;
    }
    pthread_mutex_destroy(&threadPool->lock);
    pthread_key_delete(g_localKey);
    free(threadPool);
    threadPool = NULL;
    for (int32_t index = 0; index < PROTO_NUM; ++index) {
        DeinitRemoteInvoker(g_invoker[index], index);
        g_invoker[index] = NULL;
    }
}

int32_t SpawnNewThread(ThreadPool *threadPool, int32_t policy, int32_t proto)
{
    if (!(proto == IF_PROT_BINDER && threadPool->idleThreadNum > 0) &&
        !(proto == IF_PROT_DATABUS && threadPool->idleSocketThreadNum > 0)) {
        RPC_LOG_ERROR("thread pool is full.");
        return ERR_INVALID_PARAM;
    }
    pthread_t threadId;
    if (pthread_mutex_lock(&threadPool->lock) != 0) {
        RPC_LOG_ERROR("get thread pool lock failed.");
        return ERR_FAILED;
    }
    if (!(proto == IF_PROT_BINDER && threadPool->idleThreadNum > 0) &&
        !(proto == IF_PROT_DATABUS && threadPool->idleSocketThreadNum > 0)) {
        pthread_mutex_unlock(&threadPool->lock);
        RPC_LOG_ERROR("thread pool is full.");
        return ERR_INVALID_PARAM;
    }
    ThreadContext *threadContext = (ThreadContext *)calloc(1, sizeof(ThreadContext));
    if (threadContext == NULL) {
        pthread_mutex_unlock(&threadPool->lock);
        RPC_LOG_ERROR("create thread context failed.");
        return ERR_FAILED;
    }
    threadContext->proto = proto;
    threadContext->policy = policy;
    int ret = pthread_create(&threadId, NULL, ThreadHandler, threadContext);
    if (ret != 0) {
        pthread_mutex_unlock(&threadPool->lock);
        free(threadContext);
        RPC_LOG_ERROR("spawn new thread failed.");
        return ERR_FAILED;
    }
    pthread_detach(threadId);
    if (proto == IF_PROT_BINDER) {
        --threadPool->idleThreadNum;
    } else if (proto == IF_PROT_DATABUS) {
        --threadPool->idleSocketThreadNum;
    }
    pthread_mutex_unlock(&threadPool->lock);
    return ERR_NONE;
}

void UpdateMaxThreadNum(ThreadPool *threadPool, int32_t maxThreadNum)
{
    int32_t totalNum = maxThreadNum + maxThreadNum;
    if (pthread_mutex_lock(&threadPool->lock) != 0) {
        RPC_LOG_ERROR("get thread pool lock failed.");
        return;
    }
    int32_t oldThreadNum = threadPool->maxThreadNum;
    if (totalNum <= oldThreadNum) {
        pthread_mutex_unlock(&threadPool->lock);
        RPC_LOG_ERROR("not support set lower max thread num.");
        return;
    }
    int32_t diff = totalNum - oldThreadNum;
    threadPool->maxThreadNum = totalNum;
    threadPool->idleThreadNum += diff / PROTO_NUM;
    threadPool->idleSocketThreadNum += diff / PROTO_NUM;
    pthread_mutex_unlock(&threadPool->lock);
}

RemoteInvoker *GetRemoteInvoker(void)
{
    ThreadContext *threadContext = GetCurrentThreadContext();
    if (threadContext == NULL) {
        return NULL;
    }
    return g_invoker[threadContext->proto];
}
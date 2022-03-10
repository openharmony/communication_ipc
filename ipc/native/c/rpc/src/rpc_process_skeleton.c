/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "rpc_process_skeleton.h"

#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>

#include "dbinder_types.h"
#include "ipc_proxy_inner.h"
#include "ipc_stub_inner.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_session_handle.h"
#include "rpc_trans_callback.h"
#include "rpc_types.h"

static RpcSkeleton g_rpcSkeleton = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .isServerCreated = -1
};
static pthread_mutex_t g_rpcSkeletonMutex = PTHREAD_MUTEX_INITIALIZER;

// rpc data cache
static StubObjectList g_stubObjectList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static ThreadProcessInfoList g_processInfoList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static SocketThreadLockInfoList g_socketLockInfoList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static IdleDataThreadsList g_idleDataThreadsList = {.mutex = PTHREAD_MUTEX_INITIALIZER};
static HandleSessionList g_stubSessionList;
static pthread_mutex_t g_stubSessionMutex = PTHREAD_MUTEX_INITIALIZER;
static HandleSessionList g_proxySessionList;
static pthread_mutex_t g_proxySessionMutex = PTHREAD_MUTEX_INITIALIZER;
static HandleToIndexList g_handleToIndexList;
static pthread_mutex_t g_handleToIndexMutex = PTHREAD_MUTEX_INITIALIZER;
static ThreadMessageInfo g_seqNumberToThread;
static pthread_mutex_t g_seqNumberToThreadMutex = PTHREAD_MUTEX_INITIALIZER;
static SessionIdList g_sessionIdList = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .condition = PTHREAD_COND_INITIALIZER
};

int32_t RpcProcessSkeleton(void)
{
    pthread_mutex_lock(&g_rpcSkeletonMutex);

    g_rpcSkeleton.rpcTrans = GetRpcTrans();
    if (g_rpcSkeleton.rpcTrans == NULL) {
        RPC_LOG_ERROR("GetRpcTrans return null");
        pthread_mutex_unlock(&g_rpcSkeletonMutex);
        return ERR_FAILED;
    }
    g_rpcSkeleton.seqNumber = 0;

    UtilsListInit(&g_stubObjectList.stubObjects);
    UtilsListInit(&g_processInfoList.processInfo);
    UtilsListInit(&g_socketLockInfoList.socketLockInfo);
    UtilsListInit(&g_idleDataThreadsList.idleDataThread);
    UtilsListInit(&g_stubSessionList.list);
    UtilsListInit(&g_proxySessionList.list);
    UtilsListInit(&g_handleToIndexList.list);
    UtilsListInit(&g_seqNumberToThread.list);
    UtilsListInit(&g_sessionIdList.idList);

    pthread_mutex_unlock(&g_rpcSkeletonMutex);
    return ERR_NONE;
}

RpcSkeleton *GetCurrentRpcSkeleton(void)
{
    return &g_rpcSkeleton;
}

int32_t AddStubByIndex(StubObject *stubObject)
{
    pthread_mutex_lock(&g_stubObjectList.mutex);
    UtilsListAdd(&g_stubObjectList.stubObjects, &stubObject->list);
    pthread_mutex_unlock(&g_stubObjectList.mutex);
    return ERR_NONE;
}

StubObject *QueryStubByIndex(uint64_t stubIndex)
{
    StubObject *node = NULL;
    pthread_mutex_lock(&g_stubObjectList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_stubObjectList.stubObjects, StubObject, list)
    {
        if (node->stubIndex == stubIndex) {
            pthread_mutex_unlock(&g_stubObjectList.mutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_stubObjectList.mutex);
    return NULL;
}

static int32_t AttachThreadLockInfo(SocketThreadLockInfo *threadLockInfo)
{
    pthread_mutex_lock(&g_socketLockInfoList.mutex);
    UtilsListAdd(&g_socketLockInfoList.socketLockInfo, &threadLockInfo->list);
    pthread_mutex_unlock(&g_socketLockInfoList.mutex);
    return ERR_NONE;
}

static SocketThreadLockInfo *QueryThreadLockInfo(pthread_t threadId)
{
    SocketThreadLockInfo *node = NULL;
    pthread_mutex_lock(&g_socketLockInfoList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_socketLockInfoList.socketLockInfo, SocketThreadLockInfo, list)
    {
        if (pthread_equal(node->threadId, threadId) != 0) {
            pthread_mutex_unlock(&g_socketLockInfoList.mutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_socketLockInfoList.mutex);
    return NULL;
}

static int32_t AddDataThreadToIdle(IdleDataThread *idleDataThread)
{
    pthread_mutex_lock(&g_idleDataThreadsList.mutex);
    UtilsListAdd(&g_idleDataThreadsList.idleDataThread, &idleDataThread->list);
    pthread_mutex_unlock(&g_idleDataThreadsList.mutex);
    return ERR_NONE;
}

static void DeleteDataThreadFromIdle(IdleDataThread *idleDataThread)
{
    pthread_mutex_lock(&g_idleDataThreadsList.mutex);
    UtilsListDelete(&idleDataThread->list);
    pthread_mutex_unlock(&g_idleDataThreadsList.mutex);
}

void AddDataThreadInWait(pthread_t threadId)
{
    SocketThreadLockInfo *threadLockInfo = QueryThreadLockInfo(threadId);
    if (threadLockInfo == NULL) {
        threadLockInfo = (SocketThreadLockInfo *)malloc(sizeof(SocketThreadLockInfo));
        if (threadLockInfo == NULL) {
            RPC_LOG_ERROR("SocketThreadLockInfo malloc failed");
            return;
        }
        threadLockInfo->threadId = threadId;
        if (pthread_mutex_init(&threadLockInfo->mutex, NULL) != 0) {
            RPC_LOG_ERROR("SocketThreadLockInfo mutex init failed");
            free(threadLockInfo);
            return;
        }
        if (pthread_cond_init(&threadLockInfo->condition, NULL) != 0) {
            RPC_LOG_ERROR("SocketThreadLockInfo cond init failed");
            free(threadLockInfo);
            return;
        }
        if (AttachThreadLockInfo(threadLockInfo) != ERR_NONE) {
            free(threadLockInfo);
            return;
        }
    }

    pthread_mutex_lock(&threadLockInfo->mutex);
    IdleDataThread idleDataThread = {.threadId = threadId};
    if (AddDataThreadToIdle(&idleDataThread) != ERR_NONE) {
        RPC_LOG_ERROR("AddDataThreadToIdle failed");
        pthread_mutex_unlock(&threadLockInfo->mutex);
        return;
    }

    pthread_cond_wait(&threadLockInfo->condition, &threadLockInfo->mutex);
    DeleteDataThreadFromIdle(&idleDataThread);
    pthread_mutex_unlock(&threadLockInfo->mutex);
}

void WakeUpDataThread(pthread_t threadId)
{
    SocketThreadLockInfo *threadLockInfo = QueryThreadLockInfo(threadId);
    if (threadLockInfo != NULL) {
        pthread_mutex_lock(&threadLockInfo->mutex);
        pthread_cond_signal(&threadLockInfo->condition);
        pthread_mutex_unlock(&threadLockInfo->mutex);
    }
}

IdleDataThread *GetIdleDataThread(void)
{
    IdleDataThread *node = NULL;
    pthread_mutex_lock(&g_idleDataThreadsList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_idleDataThreadsList.idleDataThread, IdleDataThread, list)
    {
        pthread_mutex_unlock(&g_idleDataThreadsList.mutex);
        return node;
    }
    pthread_mutex_unlock(&g_idleDataThreadsList.mutex);
    return NULL;
}

void AddDataInfoToThread(ThreadProcessInfo *processInfo)
{
    pthread_mutex_lock(&g_processInfoList.mutex);
    UtilsListAdd(&g_processInfoList.processInfo, &processInfo->list);
    pthread_mutex_unlock(&g_processInfoList.mutex);
}

ThreadProcessInfo *PopDataInfoFromThread(pthread_t threadId)
{
    ThreadProcessInfo *node = NULL;
    pthread_mutex_lock(&g_processInfoList.mutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_processInfoList.processInfo, ThreadProcessInfo, list)
    {
        if (pthread_equal(node->threadId, threadId) != 0) {
            UtilsListDelete(&node->list);
            pthread_mutex_unlock(&g_processInfoList.mutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_processInfoList.mutex);
    return NULL;
}

int32_t AttachStubSession(HandleSessionList *handleSession)
{
    pthread_mutex_lock(&g_stubSessionMutex);
    UtilsListAdd(&g_stubSessionList.list, &handleSession->list);
    pthread_mutex_unlock(&g_stubSessionMutex);
    return ERR_NONE;
}

void DetachStubSession(HandleSessionList *handleSession)
{
    pthread_mutex_lock(&g_stubSessionMutex);
    UtilsListDelete(&handleSession->list);
    pthread_mutex_unlock(&g_stubSessionMutex);
}

HandleSessionList *QueryStubSession(uint32_t handle)
{
    HandleSessionList *node = NULL;
    pthread_mutex_lock(&g_stubSessionMutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_stubSessionList.list, HandleSessionList, list)
    {
        if (node->handle == handle) {
            pthread_mutex_unlock(&g_stubSessionMutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_stubSessionMutex);
    return NULL;
}

int32_t AttachProxySession(HandleSessionList *handleSession)
{
    pthread_mutex_lock(&g_proxySessionMutex);
    UtilsListAdd(&g_proxySessionList.list, &handleSession->list);
    pthread_mutex_unlock(&g_proxySessionMutex);
    return ERR_NONE;
}

void DetachProxySession(HandleSessionList *handleSession)
{
    pthread_mutex_lock(&g_proxySessionMutex);
    UtilsListDelete(&handleSession->list);
    pthread_mutex_unlock(&g_proxySessionMutex);
}

HandleSessionList *QueryProxySession(uint32_t handle)
{
    HandleSessionList *node = NULL;
    pthread_mutex_lock(&g_proxySessionMutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_proxySessionList.list, HandleSessionList, list)
    {
        if (node->handle == handle) {
            pthread_mutex_unlock(&g_proxySessionMutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_proxySessionMutex);
    return NULL;
}

HandleSessionList *QueryProxySessionBySessionId(uint32_t sessionId)
{
    HandleSessionList *node = NULL;
    pthread_mutex_lock(&g_proxySessionMutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_proxySessionList.list, HandleSessionList, list)
    {
        if (node->sessionId == sessionId) {
            pthread_mutex_unlock(&g_proxySessionMutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_proxySessionMutex);
    return NULL;
}

uint64_t ProcessGetSeqNumber()
{
    pthread_mutex_lock(&g_rpcSkeleton.lock);

    ++g_rpcSkeleton.seqNumber; // can be overflow, and seqNumber do not use 0
    if (g_rpcSkeleton.seqNumber == 0) {
        ++g_rpcSkeleton.seqNumber;
    }

    pthread_mutex_unlock(&g_rpcSkeleton.lock);
    return g_rpcSkeleton.seqNumber;
}

int32_t AttachHandleToIndex(HandleToIndexList *handleToIndex)
{
    pthread_mutex_lock(&g_handleToIndexMutex);
    UtilsListAdd(&g_handleToIndexList.list, &handleToIndex->list);
    pthread_mutex_unlock(&g_handleToIndexMutex);
    return ERR_NONE;
}

void DetachHandleToIndex(HandleToIndexList *handleToIndex)
{
    pthread_mutex_lock(&g_handleToIndexMutex);
    UtilsListDelete(&handleToIndex->list);
    pthread_mutex_unlock(&g_handleToIndexMutex);
}

HandleToIndexList *QueryHandleToIndex(uint32_t handle)
{
    HandleToIndexList *node = NULL;
    pthread_mutex_lock(&g_handleToIndexMutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_handleToIndexList.list, HandleToIndexList, list)
    {
        if (node->handle == handle) {
            pthread_mutex_unlock(&g_handleToIndexMutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_handleToIndexMutex);
    return NULL;
}

static int32_t AddThreadBySeqNumber(ThreadMessageInfo *messageInfo)
{
    pthread_mutex_lock(&g_seqNumberToThreadMutex);
    UtilsListAdd(&g_seqNumberToThread.list, &messageInfo->list);
    pthread_mutex_unlock(&g_seqNumberToThreadMutex);
    return ERR_NONE;
}

int32_t AddSendThreadInWait(uint64_t seqNumber, ThreadMessageInfo *messageInfo, uint32_t userWaitTime)
{
    if (AddThreadBySeqNumber(messageInfo) != ERR_NONE) {
        RPC_LOG_ERROR("add seqNumber = %llu failed", seqNumber);
        return ERR_FAILED;
    }

    SocketThreadLockInfo *threadLockInfo = QueryThreadLockInfo(messageInfo->threadId);
    if (threadLockInfo == NULL) {
        threadLockInfo = (SocketThreadLockInfo *)malloc(sizeof(SocketThreadLockInfo));
        if (threadLockInfo == NULL) {
            RPC_LOG_ERROR("threadLockInfo malloc failed");
            return ERR_FAILED;
        }

        pthread_mutex_init(&threadLockInfo->mutex, NULL);
        pthread_cond_init(&threadLockInfo->condition, NULL);
        threadLockInfo->threadId = messageInfo->threadId;

        int32_t ret = AttachThreadLockInfo(threadLockInfo);
        if (ret != ERR_NONE) {
            RPC_LOG_ERROR("AttachThreadLockInfo fail");
            free(threadLockInfo);
            return ERR_FAILED;
        }
    }

    pthread_mutex_lock(&threadLockInfo->mutex);

    struct timespec waitTime;
    struct timeval now;
    if (gettimeofday(&now, NULL) != 0) {
        RPC_LOG_ERROR("gettimeofday failed");
        pthread_mutex_unlock(&threadLockInfo->mutex);
        return ERR_FAILED;
    }

    waitTime.tv_sec = now.tv_sec + userWaitTime;
    waitTime.tv_nsec = now.tv_usec * USECTONSEC;
    int ret = pthread_cond_timedwait(&threadLockInfo->condition, &threadLockInfo->mutex, &waitTime);
    pthread_mutex_unlock(&threadLockInfo->mutex);
    if (ret == ETIMEDOUT) {
        RPC_LOG_ERROR("send thread wait for reply timeout");
        return ERR_FAILED;
    }

    return ERR_NONE;
}

void EraseThreadBySeqNumber(ThreadMessageInfo *messageInfo)
{
    pthread_mutex_lock(&g_seqNumberToThreadMutex);
    UtilsListDelete(&messageInfo->list);
    pthread_mutex_unlock(&g_seqNumberToThreadMutex);
}

ThreadMessageInfo *QueryThreadBySeqNumber(uint64_t seqNumber)
{
    ThreadMessageInfo *node = NULL;
    pthread_mutex_lock(&g_seqNumberToThreadMutex);
    UTILS_DL_LIST_FOR_EACH_ENTRY(node, &g_seqNumberToThread.list, ThreadMessageInfo, list)
    {
        if (node->seqNumber == seqNumber) {
            pthread_mutex_unlock(&g_seqNumberToThreadMutex);
            return node;
        }
    }
    pthread_mutex_unlock(&g_seqNumberToThreadMutex);
    return NULL;
}

void WakeUpThreadBySeqNumber(uint64_t seqNumber, uint32_t handle)
{
    ThreadMessageInfo *messageInfo = QueryThreadBySeqNumber(seqNumber);
    if (messageInfo == NULL) {
        RPC_LOG_ERROR("error! messageInfo is nullptr");
        return;
    }

    if (handle != messageInfo->sessionId) {
        RPC_LOG_ERROR("error! handle is not equal messageInfo, handle = %u, messageFd = %u", handle,
            messageInfo->sessionId);
        return;
    }
    if (pthread_equal(messageInfo->threadId, pthread_self()) == 0) {
        SocketThreadLockInfo *threadLockInfo = QueryThreadLockInfo(messageInfo->threadId);
        if (threadLockInfo != NULL) {
            /* wake up this IO thread to process socket stream
             * Wake up the client processing thread
             */
            pthread_mutex_lock(&threadLockInfo->mutex);
            pthread_cond_signal(&threadLockInfo->condition);
            pthread_mutex_unlock(&threadLockInfo->mutex);
        }
    }
}

int32_t RpcOnRemoteRequestInner(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option,
    IpcObjectStub *objectStub)
{
    int32_t result;
    switch (code) {
        case INVOKE_LISTEN_THREAD: {
            result = InvokerListenThreadStub(code, data, reply, option, objectStub->func);
            break;
            }
        case GET_UIDPID_INFO: {
            result = GetPidAndUidInfoStub(code, data, reply, option);
            break;
        }
        case GRANT_DATABUS_NAME: {
            result = GrantDataBusNameStub(code, data, reply, option);
            break;
        }
        default:
            result = ERR_NOT_RPC;
            break;
    }
    return result;
}

void UpdateProtoIfNeed(SvcIdentity *svc)
{
    RPC_LOG_INFO("rpc manager update proto, handle %d", svc->handle);
    UpdateProto(svc);
}

uint64_t GetNewStubIndex(void)
{
    pthread_mutex_lock(&g_rpcSkeleton.lock);
    uint64_t stubIndex = ++g_rpcSkeleton.stubIndex;
    pthread_mutex_unlock(&g_rpcSkeleton.lock);
    return stubIndex;
}

SessionIdList *RpcGetSessionIdList(void)
{
    return &g_sessionIdList;
}
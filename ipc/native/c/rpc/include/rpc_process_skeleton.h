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

#ifndef OHOS_RPC_PROCESS_SKELETON_H
#define OHOS_RPC_PROCESS_SKELETON_H

#include "ipc_skeleton.h"
#include "rpc_trans.h"
#include "rpc_session_handle.h"
#include "utils_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    pthread_mutex_t lock;
    uint64_t stubIndex;
    char *sessionName;
    uint64_t seqNumber;
    TransInterface *rpcTrans;
    int32_t isServerCreated;
} RpcSkeleton;

typedef struct {
    UTILS_DL_LIST list;
    uint64_t stubIndex;
    OnRemoteRequest func;
} StubObject;

typedef struct {
    UTILS_DL_LIST stubObjects;
    pthread_mutex_t mutex;
} StubObjectList;

typedef struct {
    UTILS_DL_LIST list;
    pthread_t threadId;
    uint32_t sessionId;
    uint32_t packageSize;
    char *buffer;
} ThreadProcessInfo;

typedef struct {
    UTILS_DL_LIST processInfo;
    pthread_mutex_t mutex;
} ThreadProcessInfoList;

typedef struct {
    UTILS_DL_LIST list;
    pthread_t threadId;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
} SocketThreadLockInfo;

typedef struct {
    UTILS_DL_LIST socketLockInfo;
    pthread_mutex_t mutex;
} SocketThreadLockInfoList;

typedef struct {
    UTILS_DL_LIST list;
    pthread_t threadId;
} IdleDataThread;

typedef struct {
    UTILS_DL_LIST idleDataThread;
    pthread_mutex_t mutex;
} IdleDataThreadsList;

typedef struct {
    UTILS_DL_LIST list;
    uint32_t handle;
    uint32_t sessionId;
    char *buffer;
    uint32_t len;
} HandleSessionList;

typedef struct {
    UTILS_DL_LIST list;
    uint32_t handle;
    uint64_t index;
} HandleToIndexList;

typedef struct {
    UTILS_DL_LIST list;
    pthread_t threadId;
    uint64_t seqNumber;
    uint32_t flags;
    size_t bufferSize;
    size_t offsetsSize;
    uintptr_t offsets;
    uint32_t sessionId;
    void *buffer;
} ThreadMessageInfo;

int32_t RpcProcessSkeleton(void);
RpcSkeleton *GetCurrentRpcSkeleton(void);
int32_t AddStubByIndex(StubObject *stubObject);
StubObject *QueryStubByIndex(uint64_t stubIndex);
void AddDataThreadInWait(pthread_t threadId);
IdleDataThread *GetIdleDataThread(void);
void AddDataInfoToThread(ThreadProcessInfo *processInfo);
ThreadProcessInfo *PopDataInfoFromThread(pthread_t threadId);
int32_t AttachStubSession(HandleSessionList *handleSession);
void DetachStubSession(HandleSessionList *handleSession);
HandleSessionList *QueryStubSession(uint32_t handle);
int32_t AttachProxySession(HandleSessionList *handleSession);
void DetachProxySession(HandleSessionList *handleSession);
HandleSessionList *QueryProxySession(uint32_t handle);
HandleSessionList *QueryProxySessionBySessionId(uint32_t sessionId);
uint64_t ProcessGetSeqNumber(void);
int32_t AttachHandleToIndex(HandleToIndexList *handleToIndex);
void DetachHandleToIndex(HandleToIndexList *handleToIndex);
HandleToIndexList *QueryHandleToIndex(uint32_t handle);
int32_t AddSendThreadInWait(uint64_t seqNumber, ThreadMessageInfo *messageInfo, uint32_t userWaitTime);
void EraseThreadBySeqNumber(ThreadMessageInfo *messageInfo);
ThreadMessageInfo *QueryThreadBySeqNumber(uint64_t seqNumber);
void WakeUpThreadBySeqNumber(uint64_t seqNumber, uint32_t handle);
int32_t RpcOnRemoteRequestInner(uint32_t code, IpcIo *data, IpcIo *reply,
    MessageOption option, IpcObjectStub *objectStub);
void UpdateProtoIfNeed(SvcIdentity *svc);
void WakeUpDataThread(pthread_t threadId);
uint64_t GetNewStubIndex(void);
SessionIdList *RpcGetSessionIdList(void);

#ifdef __cplusplus
}
#endif
#endif // OHOS_RPC_PROCESS_SKELETON_H
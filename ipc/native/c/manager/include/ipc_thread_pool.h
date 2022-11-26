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

#ifndef OHOS_IPC_RPC_THRREAD_H
#define OHOS_IPC_RPC_THRREAD_H

#include <pthread.h>
#include <stdbool.h>

#include "ipc_skeleton.h"
#include "iremote_invoker.h"
#include "dbinder_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum {
    SPAWN_PASSIVE,
    SPAWN_ACTIVE,
    PROCESS_PASSIVE,
    PROCESS_ACTIVE,
};

typedef struct {
    pthread_t threadId;
    int32_t proto;
    int32_t policy;
    IpcObjectStub *objectStub;
    pid_t callerPid;
    pid_t callerUid;
    char callerDeviceID[DEVICEID_LENGTH + 1];
    bool stopWorkThread;
    uint64_t seqNumber;
    uint32_t sessionId;
} ThreadContext;

typedef struct {
    int32_t maxThreadNum;
    int32_t idleThreadNum;
    int32_t idleSocketThreadNum;
    pthread_mutex_t lock;
} ThreadPool;

ThreadPool *InitThreadPool(int32_t maxThreadNum);

void DeinitThreadPool(ThreadPool *threadPool);

int32_t SpawnNewThread(ThreadPool *threadPool, int32_t policy, int32_t proto);

ThreadContext *GetCurrentThreadContext(void);

RemoteInvoker *GetRemoteInvoker(void);

void UpdateMaxThreadNum(ThreadPool *threadPool, int32_t maxThreadNum);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* OHOS_IPC_RPC_THRREAD_H */
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

#ifndef OHOS_IPC_RPC_PROCESS_SKELETON_H
#define OHOS_IPC_RPC_PROCESS_SKELETON_H

#include <stdbool.h>

#include "ipc_skeleton.h"
#include "ipc_thread_pool.h"
#include "rpc_types.h"
#include "utils_list.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    bool usedFlag;
    OnRemoteDead func;
    void *args;
} DeathHandler;

typedef struct {
    UTILS_DL_LIST list;
    pthread_mutex_t lock;
    DeathHandler handler[MAX_DEATH_CALLBACK_NUM];
    int32_t handle;
    int32_t deathNum;
    bool isRemoteDead;
    bool isNewHandler;
} DeathCallback;

typedef struct {
    UTILS_DL_LIST objects;
    pthread_mutex_t lock;
    ThreadPool *threadPool;
} IpcSkeleton;

IpcSkeleton *GetCurrentSkeleton(void);
int32_t SetMaxWorkThread(int32_t maxThreadNum);
void JoinMainWorkThread(void);
pid_t ProcessGetCallingPid(void);
pid_t ProcessGetCallingUid(void);
int32_t SpawnThread(int32_t policy, int32_t proto);
int32_t SetRegistryObject(SvcIdentity target);
const SvcIdentity *GetRegistryObject(void);
int32_t ProcessSendRequest(SvcIdentity target, uint32_t code, IpcIo *data, IpcIo *reply,
    MessageOption option, uintptr_t *buffer);
int32_t ProcessFreeBuffer(void *ptr);
void OnFirstStrongRef(int32_t handle);
int32_t ProcessAddDeathRecipient(int32_t handle, OnRemoteDead deathFunc, void *args, uint32_t *cbId);
int32_t ProcessRemoveDeathRecipient(int32_t handle, uint32_t cbId);
int32_t OnRemoteRequestInner(uint32_t code, IpcIo *data, IpcIo *reply,
    MessageOption option, IpcObjectStub *objectStub);
bool OnThreadTerminated(pthread_t threadId);
void SendObituary(DeathCallback *deathCallback);
void DeleteDeathCallback(DeathCallback *deathCallback);
void WaitForProxyInit(SvcIdentity *svc);
int32_t DeleteHandle(int32_t handle);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* OHOS_IPC_RPC_PROCESS_SKELETON_H */
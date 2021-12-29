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

#ifndef OHOS_IPC_RPC_SKELETON_H
#define OHOS_IPC_RPC_SKELETON_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "serializer.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef enum {
    TF_OP_SYNC = 0x00,
    TF_OP_ASYNC = 0x01,
    TF_OP_STATUS_CODE = 0x08,
    TF_OP_ACCEPT_FDS = 0x10,
} MessageOption;

typedef int32_t (*OnRemoteRequest)(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option);
typedef void (*OnRemoteDead)(void *args);

typedef struct {
    OnRemoteRequest func;
    bool isRemote;
} IpcObjectStub;

// default is 4
int32_t SetMaxWorkThreadNum(int32_t maxThreadNum);

// join current thread into work loop.
void JoinWorkThread(void);

pid_t GetCallingPid(void);

pid_t GetCallingUid(void);

const SvcIdentity *GetContextObject(void);

int32_t SetContextObject(SvcIdentity target);

int32_t SendRequest(SvcIdentity target, uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option, uintptr_t *buffer);

int32_t FreeBuffer(void *ptr);

int32_t AddDeathRecipient(SvcIdentity target, OnRemoteDead deathFunc, void *args, uint32_t *cbId);

int32_t RemoveDeathRecipient(SvcIdentity target, uint32_t cbId);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */
#endif /* OHOS_IPC_RPC_SKELETON_H */

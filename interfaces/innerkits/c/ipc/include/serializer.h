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

#ifndef OHOS_IPC_RPC_SERIALIZER_H
#define OHOS_IPC_RPC_SERIALIZER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef struct {
    char *bufferBase;
    size_t *offsetsBase;
    char *bufferCur;
    size_t *offsetsCur;
    size_t bufferLeft;
    size_t offsetsLeft;
    uint32_t flag;
} IpcIo;

typedef struct {
    int32_t handle;
    uintptr_t token;
    uintptr_t cookie;
} SvcIdentity;

#define MIN_BINDER_HANDLE (-1)
#define IPC_IO_INITIALIZED 0x01 /* ipc flag indicates whether io is initialized */
#define IPC_IO_OVERFLOW    0x02 /* ipc flag indicates whether io is running out of space */

void IpcIoInit(IpcIo* io, void* buffer, size_t bufferSize, size_t maxobjects);

bool WriteRemoteObject(IpcIo *io, const SvcIdentity *svc);
bool WriteFileDescriptor(IpcIo *io, uint32_t fd);

bool ReadRemoteObject(IpcIo *io, SvcIdentity *svc);
int32_t ReadFileDescriptor(IpcIo *io);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* OHOS_IPC_RPC_SERIALIZER_H */

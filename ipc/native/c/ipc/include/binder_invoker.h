/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_INVOKER_H
#define OHOS_IPC_INVOKER_H

#include "iremote_invoker.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

RemoteInvoker *GetIpcInvoker(void);
int32_t AcquireHandle(int32_t handle);
int32_t ReleaseHandle(int32_t handle);
int32_t IpcSendRequest(SvcIdentity target, uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option, uintptr_t *buffer);
int32_t IpcFreeBuffer(void *ptr);
int32_t IpcSetMaxWorkThread(int32_t maxThreadNum);
void IpcJoinThread(bool initiative);
int32_t IpcSetRegistryObject(void);
int32_t IpcAddDeathRecipient(int32_t handle, void *cookie);
int32_t IpcRemoveDeathRecipient(int32_t handle, void *cookie);
void IpcExitCurrentThread(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */
#endif /* OHOS_IPC_INVOKER_H */
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

#ifndef IPC_C_PROCESS_H
#define IPC_C_PROCESS_H

#include <stdint.h>
#include "c_parcel.h"
#include "c_remote_object.h"

#ifdef __cplusplus
extern "C" {
#endif

CRemoteObject *GetContextManager(void);
void JoinWorkThread(void);
void StopWorkThread(void);

uint64_t GetCallingTokenId(void);
uint64_t GetFirstToekenId(void);
uint64_t GetSelfToekenId(void);
uint64_t GetCallingPid(void);
uint64_t GetCallingUid(void);

bool IsLocalCalling(void);
bool SetMaxWorkThreadNum(int maxThreadNum);
bool SetCallingIdentity(const char *identity);
bool GetLocalDeviceID(void *value, OnCParcelBytesAllocator allocator);
bool GetCallingDeviceID(void *value, OnCParcelBytesAllocator allocator);
bool ResetCallingIdentity(void *value, OnCParcelBytesAllocator allocator);

#ifdef __cplusplus
}
#endif
#endif /* IPC_C_PROCESS_H */

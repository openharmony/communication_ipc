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

#ifndef IPC_C_REMOTE_OBJECT_H
#define IPC_C_REMOTE_OBJECT_H

#include <stdint.h>
#include "c_parcel.h"

#ifdef __cplusplus
extern "C" {
#endif

struct CRemoteObjectHolder;
typedef struct CRemoteObjectHolder CRemoteObject;

struct CDeathRecipient;
typedef struct CDeathRecipient CDeathRecipient;

// Callback as remote stub
typedef int (*OnRemoteRequestCb)(const void *userData, int code, 
    const CParcel *data, CParcel *reply);
typedef void (*OnRemoteObjectDestroyCb)(const void *userData);
// Callback as death recipient
typedef void (*OnDeathRecipientCb)(const void *userData);
typedef void (*OnDeathRecipientDestroyCb)(const void *userData);

typedef bool (*On16BytesAllocator)(void *stringData, uint16_t **buffer, int32_t len);

CRemoteObject *CreateRemoteStub(const char *desc, OnRemoteRequestCb callback,
    OnRemoteObjectDestroyCb destroy, const void *userData);

void RemoteObjectIncStrongRef(CRemoteObject *object);
void RemoteObjectDecStrongRef(CRemoteObject *object);

bool RemoteObjectLessThan(const CRemoteObject *lhs, const CRemoteObject *rhs);
int RemoteObjectSendRequest(const CRemoteObject *object, uint32_t code,
    const CParcel *data, CParcel *reply, bool isAsync);

// Death Recipient
CDeathRecipient *CreateDeathRecipient(OnDeathRecipientCb onDeathRecipient,
    OnDeathRecipientDestroyCb onDestroy, const void *userData);
void DeathRecipientIncStrongRef(CDeathRecipient *recipient);
void DeathRecipientDecStrongRef(CDeathRecipient *recipient);
bool AddDeathRecipient(CRemoteObject *object, CDeathRecipient *recipient);
bool RemoveDeathRecipient(CRemoteObject *object, CDeathRecipient *recipient);

bool IsProxyObject(CRemoteObject *object);
int Dump(CRemoteObject *object, int fd, const void *value,
    int32_t len, OnStringArrayWrite writer);

bool IsObjectDead(CRemoteObject *object);
bool GetInterfaceDescriptor(CRemoteObject *object, void *value, On16BytesAllocator allocator);
#ifdef __cplusplus
}
#endif
#endif /* IPC_C_REMOTE_OBJECT_H */

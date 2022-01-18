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

#ifndef DBINDER_SERVICE_H
#define DBINDER_SERVICE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "dbinder_types.h"
#include "utils_list.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    struct DHandleEntryHead head;
    uint32_t transType;
    uint32_t dBinderCode;
    uint16_t fromPort;
    uint16_t toPort;
    uint64_t stubIndex;
    uint32_t seqNumber;
    uintptr_t binderObject;
    struct DeviceIdInfo deviceIdInfo;
    uintptr_t stub;
    uint16_t serviceNameLength;
    char serviceName[SERVICENAME_LENGTH + 1];
    uint32_t pid;
    uint32_t uid;
} DHandleEntryTxRx;

int32_t StartDBinderService(void);
int32_t RegisterRemoteProxy(const void *name, uint32_t len, int32_t systemAbility);
int32_t MakeRemoteBinder(const void *serviceName, uint32_t nameLen, const char *deviceID, uint32_t idLen,
    uintptr_t binderObject, uint64_t pid, void *remoteObject);
int32_t OnRemoteMessageTask(const DHandleEntryTxRx *message);
SessionInfo *QuerySessionObject(uintptr_t stub);
void DetachProxyObject(ProxyObject *proxy);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* DBINDER_SERVICE_H */
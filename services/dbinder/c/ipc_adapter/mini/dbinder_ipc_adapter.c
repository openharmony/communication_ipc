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

#include "dbinder_ipc_adapter.h"

#include "rpc_errno.h"
#include "rpc_log.h"
#include "securec.h"

bool IsSameStub(DBinderServiceStub *stub, const char *serviceName,
    const char *deviceID, uintptr_t binderObject)
{
    if (stub == NULL) {
        return false;
    }
    return (strcmp(stub->serviceName, serviceName) == 0 && strcmp(stub->deviceID, deviceID) == 0
        && stub->binderObject == binderObject);
}

ProxyObject *RpcGetSystemAbility(int32_t systemAbility)
{
    IpcIo reply;
    uint8_t replyAlloc[RPC_IPC_LENGTH];
    IpcIoInit(&reply, replyAlloc, RPC_IPC_LENGTH, 0);
    if (GetSystemAbilityById(systemAbility, &reply) != ERR_NONE) {
        RPC_LOG_ERROR("GetSystemAbilityById failed");
        return NULL;
    }
    SvcIdentity target;
    ReadRemoteObject(&reply, &target);

    ProxyObject *proxyObject = (ProxyObject *)calloc(1, sizeof(ProxyObject));
    if (proxyObject == NULL) {
        return NULL;
    }
    proxyObject->proxy = (SvcIdentity *)malloc(sizeof(SvcIdentity));
    if (proxyObject->proxy == NULL) {
        free(proxyObject);
        return NULL;
    }

    if (memcpy_s(proxyObject->proxy, sizeof(SvcIdentity), &target, sizeof(SvcIdentity)) != EOK) {
        free(proxyObject->proxy);
        free(proxyObject);
        return NULL;
    }

    return proxyObject;
}
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

#include <pthread.h>
#include <string.h>

#include "securec.h"
#include "ipc_skeleton.h"
#include "rpc_log.h"
#include "rpc_errno.h"

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
    IpcIo data;
    uint8_t tmpData[RPC_IPC_LENGTH];
    IpcIoInit(&data, tmpData, RPC_IPC_LENGTH, 0);
    RPC_LOG_INFO("GetSystemAbility systemAbility %d", systemAbility);
    WriteInt32(&data, systemAbility);

    IpcIo reply;
    MessageOption option = {
        .flags = TF_OP_SYNC
    };

    RPC_LOG_INFO("get system ability from samgr");
    uintptr_t ptr;
    int32_t ret = SendRequest(*GetContextObject(), GET_SYSTEM_ABILITY_TRANSACTION, &data, &reply, option, &ptr);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("GetSystemAbility failed");
        FreeBuffer((void *)ptr);
        return NULL;
    }

    SvcIdentity svc;
    ReadRemoteObject(&reply, &svc);

    ProxyObject *proxyObject = (ProxyObject *)malloc(sizeof(ProxyObject));
    if (proxyObject == NULL) {
        FreeBuffer((void *)ptr);
        return NULL;
    }
    proxyObject->proxy = (SvcIdentity *)malloc(sizeof(SvcIdentity));
    if (proxyObject->proxy == NULL) {
        free(proxyObject);
        FreeBuffer((void *)ptr);
        return NULL;
    }

    if (memcpy_s(proxyObject->proxy, sizeof(SvcIdentity), &svc, sizeof(SvcIdentity)) != EOK) {
        free(proxyObject->proxy);
        free(proxyObject);
        FreeBuffer((void *)ptr);
        return NULL;
    }

    FreeBuffer((void *)ptr);
    return proxyObject;
}
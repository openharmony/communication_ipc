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

#include "securec.h"
#include "ipc_proxy_inner.h"
#include "rpc_errno.h"
#include "rpc_log.h"

#include "rpc_mini_samgr.h" // samgr refactory needed in mini system

bool IsSameStub(DBinderServiceStub *stub, const char *serviceName,
    const char *deviceID, uintptr_t binderObject)
{
    return false;
}

int32_t GetDBinderHandle(uintptr_t stubAddr)
{
    return (int32_t)stubAddr;
}

int32_t UpdateSessionIfNeed(uintptr_t stubAddr)
{
    UpdateProto((int32_t)stubAddr);
    return ERR_NONE;
}

ProxyObject *RpcGetSystemAbility(int32_t systemAbility)
{
    SvcIdentity *target = GetSystemAbilityById(systemAbility);
    if (target == NULL) {
        RPC_LOG_ERROR("GetSystemAbilityById return null");
        return NULL;
    }

    ProxyObject *proxyObject = (ProxyObject *)calloc(1, sizeof(ProxyObject));
    if (proxyObject == NULL) {
        return NULL;
    }
    proxyObject->proxy = (SvcIdentity *)malloc(sizeof(SvcIdentity));
    if (proxyObject->proxy == NULL) {
        free(proxyObject);
        return NULL;
    }

    if (memcpy_s(proxyObject->proxy, sizeof(SvcIdentity), target, sizeof(SvcIdentity)) != EOK) {
        free(proxyObject->proxy);
        free(proxyObject);
        return NULL;
    }

    return proxyObject;
}
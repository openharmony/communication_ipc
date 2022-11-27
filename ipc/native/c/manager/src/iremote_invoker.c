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

#include "iremote_invoker.h"

#include "dbinder_invoker.h"
#include "ipc_invoker.h"
#include "rpc_types.h"

RemoteInvoker *InitRemoteInvoker(int32_t proto)
{
    RemoteInvoker *remoteInvoker = NULL;
    if (proto == IF_PROT_BINDER) {
        remoteInvoker = GetIpcInvoker();
    } else {
        remoteInvoker = GetRpcInvoker();
    }
    return remoteInvoker;
}

void DeinitRemoteInvoker(RemoteInvoker *invoker, int32_t proto)
{
    if (invoker == NULL) {
        return;
    }
    if (proto == IF_PROT_BINDER) {
        DeinitIpcInvoker(invoker);
    }
}
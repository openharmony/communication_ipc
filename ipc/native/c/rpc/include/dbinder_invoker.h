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

#ifndef OHOS_RPC_INVOKER_H
#define OHOS_RPC_INVOKER_H

#include <stdbool.h>

#include "rpc_process_skeleton.h"
#include "iremote_invoker.h"

#ifdef __cplusplus
extern "C" {
#endif

RemoteInvoker *GetRpcInvoker(void);
void DeleteRpcInvoker(RemoteInvoker *remoteInvoker);
void RpcStopWorkThread(void);
int32_t OnReceiveNewConnection(int sessionId);
void OnDatabusSessionClosed(int sessionId);
void OnMessageAvailable(int sessionId, const void *data, uint32_t len);
void UpdateClientSession(int32_t handle, HandleSessionList *sessionObject,
    const char *serviceName, const char *deviceId);
int32_t CreateTransServer(const char *sessionName);

#ifdef __cplusplus
}
#endif
#endif // OHOS_RPC_INVOKER_H
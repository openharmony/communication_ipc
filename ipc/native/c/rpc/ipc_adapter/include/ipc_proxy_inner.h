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

#ifndef OHOS_IPC_PROXY_INNER_H
#define OHOS_IPC_PROXY_INNER_H

#include "dbinder_types.h"
#include "serializer.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InvokerListenThread(ProxyObject *proxyObject, const char *localDeviceID,
    const char *remoteDeviceID, uint32_t pid, uint32_t uid, IpcIo *reply, uintptr_t *ptr);
int32_t GetPidAndUidInfo(ProxyObject *proxy);
char *GetDataBusName(void);
void UpdateProto(SvcIdentity *svc);

#ifdef __cplusplus
}
#endif
#endif // OHOS_IPC_PROXY_INNER_H
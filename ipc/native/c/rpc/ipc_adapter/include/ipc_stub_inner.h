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

#ifndef OHOS_IPC_STUB_INNER_H
#define OHOS_IPC_STUB_INNER_H

#include <stdint.h>

#include "serializer.h"
#include "ipc_skeleton.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InvokerListenThreadStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option, OnRemoteRequest func);
int32_t GetPidAndUidInfoStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option);
int32_t GrantDataBusNameStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option);

#ifdef __cplusplus
}
#endif
#endif // OHOS_IPC_STUB_INNER_H
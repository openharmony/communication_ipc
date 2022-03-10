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

#include "ipc_stub_inner.h"

#include "rpc_errno.h"

int32_t InvokerListenThreadStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option, OnRemoteRequest func)
{
    (void)code;
    (void)data;
    (void)reply;
    (void)option;
    (void)func;
    return ERR_NONE;
}

int32_t GetPidAndUidInfoStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    (void)code;
    (void)data;
    (void)reply;
    (void)option;
    return ERR_NONE;
}

int32_t GrantDataBusNameStub(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    (void)code;
    (void)data;
    (void)reply;
    (void)option;
    return ERR_NONE;
}
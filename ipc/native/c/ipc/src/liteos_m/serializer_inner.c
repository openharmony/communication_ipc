/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "serializer.h"

#include "ipc_process_skeleton.h"
#include "rpc_log.h"

bool WriteRemoteObject(IpcIo *io, const SvcIdentity *svc)
{
    if (io == NULL || svc == NULL) {
        RPC_LOG_ERROR("write io or svc is NULL ...");
        return false;
    }
    return WriteBuffer(io, svc, sizeof(SvcIdentity));
}

bool WriteFileDescriptor(IpcIo *io, uint32_t fd)
{
    (void)io;
    (void)fd;
    return false;
}

bool ReadRemoteObject(IpcIo *io, SvcIdentity *svc)
{
    if (io == NULL || svc == NULL) {
        RPC_LOG_ERROR("read io or svc is NULL ...");
        return false;
    }
    SvcIdentity *svcId = ReadBuffer(io, sizeof(SvcIdentity));
    if (svcId == NULL) {
        return false;
    }
    svc->handle = svcId->handle;
    svc->token = svcId->token;
    svc->cookie = svcId->cookie;
    WaitForProxyInit(svcId);
    return true;
}

int32_t ReadFileDescriptor(IpcIo *io)
{
    (void)io;
    return -1;
}
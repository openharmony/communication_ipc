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

#include <stdlib.h>
#include <securec.h>
#include "dbinder_types.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "serializer.h"

enum {
    OP_ADD = 1,
    OP_SUB = 2,
    OP_MULTI = 3,
    OP_ADD_SERVICE = 4,
};

enum {
    ADD_SYSTEM_ABILITY_TRANSACTION = 2,
    GET_REMOTE_SYSTEM_ABILITY_TRANSACTION = 3,
    ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION = 4,
};

static const int32_t g_saID = 16;
static const uint32_t IPC_LENGTH = 128;

static int32_t RemoteRequestOne(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("server OnRemoteRequestOne called....");
    switch (code) {
        case OP_ADD: {
            int32_t a;
            ReadInt32(data, &a);
            int32_t b;
            ReadInt32(data, &b);
            RPC_LOG_INFO("RemoteRequestOne add called a = %d, b = %d", a, b);
            WriteInt32(reply, a + b);
            break;
        }
        case OP_SUB: {
            int32_t a;
            ReadInt32(data, &a);
            int32_t b;
            ReadInt32(data, &b);
            RPC_LOG_INFO("RemoteRequestOne sub called a = %d, b = %d", a, b);
            WriteInt32(reply, a - b);
            break;
        }
        case OP_MULTI: {
            int32_t a;
            ReadInt32(data, &a);
            int32_t b;
            ReadInt32(data, &b);
            RPC_LOG_INFO("RemoteRequestOne mulit called a = %d, b = %d", a, b);
            WriteInt32(reply, a * b);
            break;
        }
        default:
            RPC_LOG_ERROR("unknown code %u", code);
            break;
    }
    return result;
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("Enter System Ability Server .... ");

    IpcObjectStub objectStubOne = {
        .func = RemoteRequestOne,
        .isRemote = false
    };

    SvcIdentity svcOne = {
        .handle = -1,
        .token  = (uintptr_t)&objectStubOne,
        .cookie = (uintptr_t)&objectStubOne
    };

    IpcIo data;
    uint8_t tmpData1[IPC_LENGTH];
    IpcIoInit(&data, tmpData1, IPC_LENGTH, 1);
    WriteInt32(&data, g_saID);
    WriteRemoteObject(&data, &svcOne);

    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);

    SvcIdentity target = {
        .handle = 0
    };

    RPC_LOG_INFO("====== add ability one to samgr ======");
    uintptr_t ptr = 0;
    SendRequest(target, ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION, &data, &reply, option, &ptr);
    int32_t ret;
    ReadInt32(&reply, &ret);
    RPC_LOG_INFO("send request one ret = %d .... ", ret);
    FreeBuffer((void *)ptr);

    JoinWorkThread();
    return -1;
}
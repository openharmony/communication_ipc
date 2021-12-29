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
#include <pthread.h>
#include "rpc_log.h"
#include "rpc_errno.h"
#include "ipc_skeleton.h"
#include "serializer.h"
#include <unistd.h>

enum {
    OP_ADD = 1,
    OP_SUB = 2,
    OP_MULTI = 3,
    OP_ADD_SERVICE = 4,
};

static SvcIdentity *sid = NULL;

static void CallAnonymosFunc(const char *str)
{
    if (sid == NULL) {
        RPC_LOG_INFO("invalid anonymous client");
        return;
    }
    RPC_LOG_INFO("now server call client anonymous func");
    IpcIo data;
    uint8_t tmpData1[128];
    IpcIoInit(&data, tmpData1, 128, 1);
    IpcIoPushString(&data, str);

    IpcIo reply;
    MessageOption option = TF_OP_ASYNC;
    SendRequest(*sid, 3, &data, &reply, option, NULL);
}

int32_t RemoteRequestOne(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("server OnRemoteRequestOne called....");
    switch (code) {
        case OP_ADD: {
            int32_t a = IpcIoPopInt32(data);
            int32_t b = IpcIoPopInt32(data);
            IpcIoPushInt32(reply, a + b);
            break;
        }
        case OP_SUB: {
            int32_t a = IpcIoPopInt32(data);
            int32_t b = IpcIoPopInt32(data);
            IpcIoPushInt32(reply, a - b);
            break;
        }
        case OP_MULTI: {
            int32_t a = IpcIoPopInt32(data);
            int32_t b = IpcIoPopInt32(data);
            IpcIoPushInt32(reply, a * b);
            break;
        }
        case OP_ADD_SERVICE: {
            sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
            IpcIoPopSvc(data, sid);
            result = 77;
            const char *str = "server call anonymos service one.";
            CallAnonymosFunc(str);
            break;
        }
        default:
            RPC_LOG_ERROR("unknown code %{public}d", code);
            break;
    }
    return result;
}

int32_t RemoteRequestTwo(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("server OnRemoteRequestTwo called....");
    switch (code) {
        case OP_ADD: {
            int32_t a = IpcIoPopInt32(data);
            int32_t b = IpcIoPopInt32(data);
            IpcIoPushInt32(reply, a + b);
            break;
        }
        case OP_SUB: {
            int32_t a = IpcIoPopInt32(data);
            int32_t b = IpcIoPopInt32(data);
            IpcIoPushInt32(reply, a - b);
            break;
        }
        case OP_MULTI: {
            int32_t a = IpcIoPopInt32(data);
            int32_t b = IpcIoPopInt32(data);
            IpcIoPushInt32(reply, a * b);
            break;
        }
        default:
            RPC_LOG_ERROR("unknown code %{public}d", code);
            break;
    }
    return result;
}

static void *ThreadHandler()
{
    sleep(120); // sleep 2 min
    const char *str = "server call anonymos service new thread.";
    CallAnonymosFunc(str);
    return NULL;
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("Enter System Ability Server .... ");

    IpcObjectStub objectStubOne = {
        .func = RemoteRequestOne,
        .isRemote = false
    };

    IpcObjectStub objectStubTwo = {
        .func = RemoteRequestTwo,
        .isRemote = false
    };

    SvcIdentity svcOne = {
        .handle = -1,
        .token  = &objectStubOne,
        .cookie = &objectStubOne
    };

    SvcIdentity svcTwo = {
        .handle = -1,
        .token  = &objectStubTwo,
        .cookie = &objectStubTwo
    };

    IpcIo data;
    uint8_t tmpData1[128];
    IpcIoInit(&data, tmpData1, 128, 1);
    IpcIoPushInt32(&data, 15);
    IpcIoPushSvc(&data, &svcOne);

    IpcIo dataTwo;
    uint8_t tmpData2[128];
    IpcIoInit(&dataTwo, tmpData2, 128, 1);
    IpcIoPushInt32(&dataTwo, 18);
    IpcIoPushSvc(&dataTwo, &svcTwo);

    IpcIo reply;
    MessageOption option = TF_OP_SYNC;

    SvcIdentity target = {
        .handle = 0
    };

    RPC_LOG_INFO("====== add ability one to samgr ======");
    uintptr_t ptr = 0;
    int ret = SendRequest(target, 2, &data, &reply, option, &ptr);
    FreeBuffer((void *)ptr);

    sleep(2);
    RPC_LOG_INFO("====== add ability two to samgr ======");
    ret = SendRequest(target, 2, &dataTwo, &reply, option, &ptr);
    RPC_LOG_INFO("send request two ret = %{public}d .... ", IpcIoPopInt32(&reply));
    FreeBuffer((void *)ptr);

    sleep(2);
    RPC_LOG_INFO("====== get ability one from samgr ======");
    IpcIo data1;
    uint8_t dataGet[64];
    IpcIoInit(&data1, dataGet, 64, 0);
    IpcIoPushInt32(&data1, 15);
    ret = SendRequest(target, 1, &data1, &reply, option, &ptr);
    SvcIdentity sidOne;
    IpcIoPopSvc(&reply, &sidOne);
    FreeBuffer((void *)ptr);

    sleep(2);
    RPC_LOG_INFO("====== call serverone OP_MULTI ======");
    IpcIo data2;
    uint8_t dataMulti[128];
    IpcIoInit(&data2, dataMulti, 128, 0);
    IpcIoPushInt32(&data2, 12);
    IpcIoPushInt32(&data2, 17);

    ret = SendRequest(sidOne, OP_MULTI, &data2, &reply, option, &ptr);
    RPC_LOG_INFO(" 12 * 17 = %{public}d", IpcIoPopInt32(&reply));
    FreeBuffer((void *)ptr);

    pthread_t pid;
    ret = pthread_create(&pid, NULL, ThreadHandler, NULL);
    pthread_detach(pid);
    JoinWorkThread();
    return -1;
}
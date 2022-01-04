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

#include "ipc_proxy.h"

static SvcIdentity *sid = NULL;

static SvcIdentity g_samgr = {
    .handle = 0
};

static void CallAnonymosFunc(const char *str)
{
    if (sid == NULL) {
        RPC_LOG_INFO("invalid anonymous client");
        return;
    }
    RPC_LOG_INFO("now server call client anonymous func");
    IpcIo data;
    uint8_t tmpData1[IPC_MAX_SIZE];
    IpcIoInit(&data, tmpData1, IPC_MAX_SIZE, 1);
    WriteString(&data, str);

    IpcIo reply;
    MessageOption option = TF_OP_ASYNC;
    SendRequest(*sid, CLIENT_OP_PRINT, &data, &reply, option, NULL);
}

int32_t RemoteRequestOne(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("server OnRemoteRequestOne called....");
    int a = 0;
    int b = 0;
    switch (code) {
        case SERVER_OP_ADD: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            WriteInt32(reply, a + b);
            break;
        }
        case SERVER_OP_SUB: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            WriteInt32(reply, a - b);
            break;
        }
        case SERVER_OP_MULTI: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            WriteInt32(reply, a * b);
            break;
        }
        case SERVER_OP_ADD_SERVICE: {
            sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
            ReadRemoteObject(data, sid);
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
    int a = 0;
    int b = 0;
    switch (code) {
        case SERVER_OP_ADD: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            WriteInt32(reply, a + b);
            break;
        }
        case SERVER_OP_SUB: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            WriteInt32(reply, a - b);
            break;
        }
        case SERVER_OP_MULTI: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            WriteInt32(reply, a * b);
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
    sleep(IPC_TEST_TIME_INTERVAL); // sleep 2 min
    const char *str = "server call anonymos service new thread.";
    CallAnonymosFunc(str);
    return NULL;
}

MessageOption g_option = TF_OP_SYNC;

static IpcObjectStub objectStubOne = {
    .func = RemoteRequestOne,
    .isRemote = false
};

static IpcObjectStub objectStubTwo = {
    .func = RemoteRequestTwo,
    .isRemote = false
};

static SvcIdentity svcOne = {
    .handle = -1,
    .token  = (uintptr_t)&objectStubOne,
    .cookie = (uintptr_t)&objectStubOne
};

static SvcIdentity svcTwo = {
    .handle = -1,
    .token  = (uintptr_t)&objectStubTwo,
    .cookie = (uintptr_t)&objectStubTwo
};

static void AddSaOne()
{
    IpcIo data;
    uint8_t tmpData1[IPC_MAX_SIZE];
    IpcIoInit(&data, tmpData1, IPC_MAX_SIZE, 1);
    WriteInt32(&data, SERVER_SA_ID1);
    WriteRemoteObject(&data, &svcOne);
    IpcIo reply;
    uintptr_t ptr = 0;
    RPC_LOG_INFO("====== add ability one to samgr ======");
    int ret = SendRequest(g_samgr, ADD_SYSTEM_ABILITY_TRANSACTION, &data, &reply, g_option, &ptr);
    int res = -1;
    ReadInt32(&reply, &res);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
    EXPECT_EQ(res, ERR_NONE);
    sleep(2);
}

static void AddSaTwo()
{
    IpcIo dataTwo;
    uint8_t tmpData2[IPC_MAX_SIZE];
    IpcIoInit(&dataTwo, tmpData2, IPC_MAX_SIZE, 1);
    WriteInt32(&dataTwo, SERVER_SA_ID2);
    WriteRemoteObject(&dataTwo, &svcTwo);
    IpcIo reply;
    uintptr_t ptr = 0;
    RPC_LOG_INFO("====== add ability two to samgr ======");
    int ret = SendRequest(g_samgr, ADD_SYSTEM_ABILITY_TRANSACTION, &dataTwo, &reply, g_option, &ptr);
    int res = -1;
    ReadInt32(&reply, &res);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
    EXPECT_EQ(res, ERR_NONE);
    sleep(2);
}

int main()
{
    RPC_LOG_INFO("Enter System Ability Server .... ");
    AddSaOne();
    AddSaTwo();

    IpcIo reply;
    uintptr_t ptr = 0;
    RPC_LOG_INFO("====== get ability one from samgr ======");
    IpcIo data1;
    uint8_t dataGet[IPC_MAX_SIZE];
    IpcIoInit(&data1, dataGet, IPC_MAX_SIZE, 0);
    WriteInt32(&data1, SERVER_SA_ID1);
    int ret = SendRequest(g_samgr, GET_SYSTEM_ABILITY_TRANSACTION, &data1, &reply, g_option, &ptr);
    SvcIdentity sidOne;
    ReadRemoteObject(&reply, &sidOne);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
    sleep(2);

    RPC_LOG_INFO("====== call serverone OP_MULTI ======");
    IpcIo data2;
    uint8_t dataMulti[IPC_MAX_SIZE];
    IpcIoInit(&data2, dataMulti, IPC_MAX_SIZE, 0);
    WriteInt32(&data2, OP_A);
    WriteInt32(&data2, OP_B);
    ret = SendRequest(sidOne, SERVER_OP_MULTI, &data2, &reply, g_option, &ptr);
    int res = -1;
    ReadInt32(&reply, &res);
    RPC_LOG_INFO(" 12 * 17 = %{public}d", res);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
    int tmpMul = OP_A * OP_B;
    EXPECT_EQ(res, tmpMul);

    pthread_t pid;
    ret = pthread_create(&pid, NULL, ThreadHandler, NULL);
    pthread_detach(pid);
    JoinWorkThread();
    return -1;
}
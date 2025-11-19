/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <string.h>

#include "dbinder_service.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "rpc_process_skeleton.h"
#include "rpc_trans.h"
#include "serializer.h"

#define IPC_LENGTH 64
#define NUMBER_A 12
#define NUMBER_B 17

enum {
    OP_ADD = 1,
    OP_SUB = 2,
    OP_MULTI = 3,
    OP_ADD_SERVICE = 4,
    OP_DBINDER_CONNECT = 5,
    OP_DBINDER_RECEIVED = 6,
};

enum {
    GET_REMOTE_SYSTEM_ABILITY_TRANSACTION = 3,
    ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION = 4,
};

static const int32_t g_saID = 16;

static void ServerDead1(void)
{
    RPC_LOG_INFO("#### rpc server dead callback11 called");
}

static void RpcClientTestOne(SvcIdentity sid, MessageOption option)
{
    IpcIo data2;
    uint8_t tmpData2[IPC_LENGTH];
    IpcIoInit(&data2, tmpData2, IPC_LENGTH, 0);
    WriteInt32(&data2, NUMBER_A);
    WriteInt32(&data2, NUMBER_B);

    IpcIo reply2;
    uintptr_t ptr2 = 0;
    int32_t ret = SendRequest(sid, OP_ADD, &data2, &reply2, option, &ptr2);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("SendRequest OP_ADD failed, error = %d", ret);
        FreeBuffer((void *)ptr2);
        return;
    }

    int32_t sum;
    ReadInt32(&reply2, &sum);
    RPC_LOG_INFO("%d + %d = %d", NUMBER_A, NUMBER_B, sum);
    FreeBuffer((void *)ptr2);
}

static void RpcClientTestTwo(SvcIdentity sid, MessageOption option)
{
    IpcIo data3;
    uint8_t tmpData3[IPC_LENGTH];
    IpcIoInit(&data3, tmpData3, IPC_LENGTH, 0);
    WriteInt32(&data3, NUMBER_A);
    WriteInt32(&data3, NUMBER_B);

    IpcIo reply3;
    uintptr_t ptr3 = 0;
    int32_t ret = SendRequest(sid, OP_MULTI, &data3, &reply3, option, &ptr3);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("SendRequest OP_MULTI failed, error = %d", ret);
        FreeBuffer((void *)ptr3);
        return;
    }

    int32_t mutil;
    ReadInt32(&reply3, &mutil);
    RPC_LOG_INFO("%d * %d = %d", NUMBER_A, NUMBER_B, mutil);
    FreeBuffer((void *)ptr3);
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("Enter System Ability Client .... ");

    if (argc == 1) {
        RPC_LOG_INFO("input deviceid please");
        return -1;
    }

    const char *deviceId = argv[1];
    RPC_LOG_INFO("input deviceid is %s", deviceId);

    IpcIo data1;
    uint8_t tmpData1[IPC_LENGTH];
    IpcIoInit(&data1, tmpData1, IPC_LENGTH, 0);
    WriteInt32(&data1, g_saID);
    WriteString(&data1, deviceId);

    IpcIo reply1;
    MessageOption option;
    MessageOptionInit(&option);

    SvcIdentity target = {
        .handle = 0
    };

    RPC_LOG_INFO("get remote system ability from samgr.");
    uintptr_t ptr = 0;
    int32_t ret = SendRequest(target, GET_REMOTE_SYSTEM_ABILITY_TRANSACTION, &data1, &reply1, option, &ptr);
    SvcIdentity sid;
    ReadRemoteObject(&reply1, &sid);
    RPC_LOG_INFO("call server add func server handle = %d.", sid.handle);
    FreeBuffer((void *)ptr);

    uint32_t cbId1 = 0;
    ret = AddDeathRecipient(sid, ServerDead1, NULL, &cbId1);
    RPC_LOG_INFO("add death callback cbid1 = %d", ret);

    RpcClientTestOne(sid, option);
    RpcClientTestTwo(sid, option);

    JoinWorkThread();

    return 0;
}
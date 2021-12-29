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

#include "rpc_log.h"
#include "rpc_errno.h"
#include "ipc_skeleton.h"
#include "serializer.h"

static SvcIdentity *sid = NULL;
uint32_t cbId1 = -1;
uint32_t cbId2 = -1;
uint32_t cbId3 = -1;
uint32_t cbId4 = -1;
uint32_t cbId5 = -1;

enum {
    OP_ADD = 1,
    OP_SUB = 2,
    OP_PRINT = 3,
};

int32_t RemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("client OnRemoteRequest called....");
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
        case OP_PRINT: {
            size_t len;
            char *str = (char *)IpcIoPopString(data, &len);
            RPC_LOG_INFO("client pop string %{public}s....", str);
            break;
        }
        default:
            RPC_LOG_ERROR("unknown code %{public}d", code);
            break;
    }
    return result;
}

void ServerDead1()
{
    int ret = RemoveDeathRecipient(*sid, cbId1);
    RPC_LOG_INFO("#### server dead callback11 called %{public}d ... ", ret);
}

void ServerDead2()
{
    int ret = RemoveDeathRecipient(*sid, cbId2);
    RPC_LOG_INFO("#### server dead callback22 called %{public}d ... ", ret);
}

void ServerDead3()
{
    int ret = RemoveDeathRecipient(*sid, cbId3);
    RPC_LOG_INFO("#### server dead callback33 called %{public}d ... ", ret);
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("Enter System Ability Client .... ");

    IpcIo data1;
    uint8_t tmpData1[64];
    IpcIoInit(&data1, tmpData1, 64, 0);
    IpcIoPushInt32(&data1, 15);

    IpcIo reply1;
    MessageOption option = TF_OP_SYNC;

    SvcIdentity target = {
        .handle = 0
    };
    uintptr_t ptr = 0;
    int ret = SendRequest(target, 1, &data1, &reply1, option, &ptr);
    sid = (SvcIdentity *)malloc(sizeof(SvcIdentity));
    IpcIoPopSvc(&reply1, sid);
    FreeBuffer((void *)ptr);

    IpcIo data2;
    uint8_t tmpData2[64];
    IpcIoInit(&data2, tmpData2, 64, 0);
    IpcIoPushInt32(&data2, 12);
    IpcIoPushInt32(&data2, 17);

    IpcIo reply2;
    uintptr_t ptr2 = 0;
    ret = SendRequest(*sid, 1, &data2, &reply2, option, &ptr2);
    RPC_LOG_INFO(" 12 + 17 = %{public}d", IpcIoPopInt32(&reply2));
    FreeBuffer((void *)ptr2);

    IpcObjectStub objectStub = {
        .func = RemoteRequest,
        .isRemote = false
    };

    SvcIdentity svc = {
        .handle = -1,
        .token = &objectStub,
        .cookie = &objectStub
    };

    IpcIo anonymous;
    uint8_t anonymousData[128];
    IpcIoInit(&anonymous, anonymousData, 128, 1);
    IpcIoPushSvc(&anonymous, &svc);

    IpcIo anonymousreply;
    uintptr_t anonymousptr = 0;
    ret = SendRequest(*sid, 4, &anonymous, &anonymousreply, option, &anonymousptr);
    RPC_LOG_INFO("add self to server = %{public}d", IpcIoPopInt32(&anonymousreply));
    FreeBuffer((void *)anonymousptr);

    RPC_LOG_INFO("============= test case for add death callback ============");
    ret = AddDeathRecipient(*sid, ServerDead1, NULL, &cbId1);
    RPC_LOG_INFO("add death callback cbid1 = %{public}d", ret);
    ret = AddDeathRecipient(*sid, ServerDead2, NULL, &cbId2);
    RPC_LOG_INFO("add death callback cbid2 = %{public}d", ret);
    ret = AddDeathRecipient(*sid, ServerDead3, NULL, &cbId3);
    RPC_LOG_INFO("add death callback cbid3 = %{public}d", ret);
    ret = AddDeathRecipient(*sid, ServerDead3, NULL, &cbId4);
    RPC_LOG_INFO("add death callback cbid4 = %{public}d", ret);
    ret = AddDeathRecipient(*sid, ServerDead3, NULL, &cbId5); // failed
    RPC_LOG_INFO("add death callback cbid5 = %{public}d, ret = %{public}d", cbId5, ret);

    RPC_LOG_INFO("============= test case for remove death callback ============");
    ret = RemoveDeathRecipient(*sid, cbId2);
    RPC_LOG_INFO("remove death callback2 ret = %{public}d", ret);
    ret = RemoveDeathRecipient(*sid, cbId4);
    RPC_LOG_INFO("remove death callback4 ret = %{public}d", ret);
    ret = RemoveDeathRecipient(*sid, cbId1);
    RPC_LOG_INFO("remove death callback1 ret = %{public}d", ret);
    ret = RemoveDeathRecipient(*sid, cbId3);
    RPC_LOG_INFO("remove death callback3 ret = %{public}d", ret);


    int handleOld = sid->handle;
    sid->handle = 17;
    ret = AddDeathRecipient(*sid, ServerDead3, NULL, &cbId5); // failed
    RPC_LOG_INFO("add invalid death callback cbid5 = %{public}d, ret = %{public}d", cbId5, ret);

    ret = RemoveDeathRecipient(*sid, cbId3);
    RPC_LOG_INFO("remove invalid death callback ret = %{public}d", ret);

    sid->handle = handleOld;

    ret = AddDeathRecipient(*sid, ServerDead1, NULL, &cbId1);
    RPC_LOG_INFO("add death callback cbid1 = %{public}d", ret);
    ret = AddDeathRecipient(*sid, ServerDead2, NULL, &cbId2);
    RPC_LOG_INFO("add death callback cbid2 = %{public}d", ret);
    JoinWorkThread();
    return -1;
}
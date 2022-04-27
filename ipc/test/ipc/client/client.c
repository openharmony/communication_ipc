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

#include "ipc_proxy.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "serializer.h"

static SvcIdentity g_serverSid;
static MessageOption g_option;

int32_t RemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("client OnRemoteRequest called....");
    int a = 0;
    int b = 0;
    switch (code) {
        case CLIENT_OP_ADD: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            WriteInt32(reply, a + b);
            break;
        }
        case CLIENT_OP_SUB: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            WriteInt32(reply, a - b);
            break;
        }
        case CLIENT_OP_PRINT: {
            size_t len;
            char *str = (char *)ReadString(data, &len);
            RPC_LOG_INFO("client pop string %s....", str);
            break;
        }
        default:
            RPC_LOG_ERROR("unknown code %d", code);
            break;
    }
    return result;
}

void ServerDead1(void)
{
    RPC_LOG_INFO("#### server dead callback11 called ... ");
}

void ServerDead2(void)
{
    RPC_LOG_INFO("#### server dead callback22 called ... ");
}

void ServerDead3(void)
{
    RPC_LOG_INFO("#### server dead callback33 called ... ");
}

static SvcIdentity *g_samgr = NULL;

static void GetServerOne(void)
{
    IpcIo data1;
    uint8_t tmpData1[IPC_MAX_SIZE];
    IpcIoInit(&data1, tmpData1, IPC_MAX_SIZE, 0);
    WriteInt32(&data1, SERVER_SA_ID1);
    IpcIo reply1;
    uintptr_t ptr = 0;
    int ret = SendRequest(*g_samgr, GET_SYSTEM_ABILITY_TRANSACTION, &data1, &reply1, g_option, &ptr);
    ReadRemoteObject(&reply1, &g_serverSid);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
}

static void CallServerAdd(void)
{
    IpcIo data2;
    uint8_t tmpData2[IPC_MAX_SIZE];
    IpcIoInit(&data2, tmpData2, IPC_MAX_SIZE, 0);
    WriteInt32(&data2, OP_A);
    WriteInt32(&data2, OP_B);

    IpcIo reply2;
    uintptr_t ptr2 = 0;
    int ret = SendRequest(g_serverSid, SERVER_OP_ADD, &data2, &reply2, g_option, &ptr2);
    int res;
    ReadInt32(&reply2, &res);
    RPC_LOG_INFO(" 12 + 17 = %d", res);
    FreeBuffer((void *)ptr2);
    EXPECT_EQ(ret, ERR_NONE);
    int tmpSum = OP_A + OP_B;
    EXPECT_EQ(res, tmpSum);
}

static void CallServerMulti(void)
{
    RPC_LOG_INFO("====== call serverone OP_MULTI ======");
    IpcIo data2;
    uint8_t dataMulti[IPC_MAX_SIZE];
    IpcIoInit(&data2, dataMulti, IPC_MAX_SIZE, 0);
    WriteInt32(&data2, OP_A);
    WriteInt32(&data2, OP_B);
    IpcIo reply;
    uintptr_t ptr = 0;
    int ret = SendRequest(g_serverSid, SERVER_OP_MULTI, &data2, &reply, g_option, &ptr);
    int res = -1;
    ReadInt32(&reply, &res);
    RPC_LOG_INFO(" 12 * 17 = %d", res);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
    int tmpMul = OP_A * OP_B;
    EXPECT_EQ(res, tmpMul);
}

static IpcObjectStub g_objectStub = {
    .func = RemoteRequest,
    .isRemote = false
};

static SvcIdentity g_clientSvc = {
    .handle = -1,
    .token = 0,
    .cookie = &g_objectStub
};

static void AnonymousTest(void)
{
    IpcIo anonymous;
    uint8_t anonymousData[IPC_MAX_SIZE];
    IpcIoInit(&anonymous, anonymousData, IPC_MAX_SIZE, 1);
    WriteRemoteObject(&anonymous, &g_clientSvc);

    IpcIo anonymousreply;
    uintptr_t anonymousptr = 0;
    int ret = SendRequest(g_serverSid, SERVER_OP_ADD_SERVICE, &anonymous, &anonymousreply, g_option, &anonymousptr);
    int res = -1;
    ReadInt32(&anonymousreply, &res);
    RPC_LOG_INFO("add self to server = %d", res);
    FreeBuffer((void *)anonymousptr);
    EXPECT_EQ(ret, ERR_NONE);
    EXPECT_EQ(res, ERR_NONE);
}

static void DeathCallbackTest(void)
{
    uint32_t cbId1 = -1;
    uint32_t cbId2 = -1;
    uint32_t cbId3 = -1;
    uint32_t cbId4 = -1;
    uint32_t cbId5 = -1;
    RPC_LOG_INFO("============= test case for add death callback ============");
    int ret = AddDeathRecipient(g_serverSid, ServerDead1, NULL, &cbId1);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(g_serverSid, ServerDead2, NULL, &cbId2);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(g_serverSid, ServerDead3, NULL, &cbId3);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(g_serverSid, ServerDead3, NULL, &cbId4);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(g_serverSid, ServerDead3, NULL, &cbId5); // failed
    EXPECT_EQ(ret, ERR_INVALID_PARAM);

    RPC_LOG_INFO("============= test case for remove death callback ============");
    ret = RemoveDeathRecipient(g_serverSid, cbId2);
    EXPECT_EQ(ret, ERR_NONE);
    ret = RemoveDeathRecipient(g_serverSid, cbId4);
    EXPECT_EQ(ret, ERR_NONE);
    ret = RemoveDeathRecipient(g_serverSid, cbId1);
    EXPECT_EQ(ret, ERR_NONE);
    ret = RemoveDeathRecipient(g_serverSid, cbId3);
    EXPECT_EQ(ret, ERR_NONE);
    ++g_serverSid.handle;
    ret = AddDeathRecipient(g_serverSid, ServerDead3, NULL, &cbId5); // failed
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    ret = RemoveDeathRecipient(g_serverSid, cbId3); // failed
    EXPECT_EQ(ret, ERR_INVALID_PARAM);

    --g_serverSid.handle;

    ret = AddDeathRecipient(g_serverSid, ServerDead1, NULL, &cbId1);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(g_serverSid, ServerDead2, NULL, &cbId2);
    EXPECT_EQ(ret, ERR_NONE);
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("Enter System Ability Client .... ");
    g_samgr = GetContextObject();
    MessageOptionInit(&g_option);
    GetServerOne();
    CallServerAdd();
    CallServerMulti();
    AnonymousTest();
    DeathCallbackTest();
    while (1) {}
    return -1;
}
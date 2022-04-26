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

#include "gtest/gtest.h"

#include <ctime>

#include "ipc_proxy.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "serializer.h"

namespace {
constexpr int32_t PERFORMANCE_TEST_TIMES = 100;
SvcIdentity sidServer;
MessageOption g_option = {
    .flags = TF_OP_SYNC
};

uint32_t cbId1 = -1;
uint32_t cbId2 = -1;
uint32_t cbId3 = -1;
uint32_t cbId4 = -1;
uint32_t cbId5 = -1;

int32_t RemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    RPC_LOG_INFO("client OnRemoteRequest called....");
    switch (code) {
        case CLIENT_OP_ADD: {
            int32_t a;
            ReadInt32(data, &a);
            int32_t b;
            ReadInt32(data, &b);
            WriteInt32(reply, a + b);
            break;
        }
        case CLIENT_OP_SUB: {
            int32_t a;
            ReadInt32(data, &a);
            int32_t b;
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
            RPC_LOG_ERROR("unknown code %u", code);
            break;
    }
    return result;
}

void ServerDead1()
{
    RPC_LOG_INFO("#### server dead callback11 called ... ");
}

void ServerDead2()
{
    RPC_LOG_INFO("#### server dead callback22 called ... ");
}

void ServerDead3()
{
    RPC_LOG_INFO("#### server dead callback33 called ... ");
}
}

using namespace testing::ext;

namespace OHOS {
class IpcClientTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        pid_t pid = fork();
        if (pid != 0) {
            exit(0);
        }
        RPC_LOG_INFO("----------test case for ipc client start-------------\n");
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(IpcClientTest, IpcClientTest001, TestSize.Level1)
{
    IpcIo data1;
    uint8_t tmpData1[IPC_MAX_SIZE];
    IpcIoInit(&data1, tmpData1, IPC_MAX_SIZE, 0);
    WriteInt32(&data1, SERVER_SA_ID1);
    SvcIdentity target = {
        .handle = 0
    };
    IpcIo reply1;
    uintptr_t ptr = 0;
    int ret = SendRequest(target, GET_SYSTEM_ABILITY_TRANSACTION, &data1, &reply1, g_option, &ptr);
    ReadRemoteObject(&reply1, &sidServer);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
}

HWTEST_F(IpcClientTest, IpcClientTest002, TestSize.Level1)
{
    IpcIo data2;
    uint8_t tmpData2[IPC_MAX_SIZE];
    IpcIoInit(&data2, tmpData2, IPC_MAX_SIZE, 0);
    WriteInt32(&data2, OP_A);
    WriteInt32(&data2, OP_B);

    IpcIo reply2;
    uintptr_t ptr2 = 0;
    int ret = SendRequest(sidServer, SERVER_OP_ADD, &data2, &reply2, g_option, &ptr2);
    int res = -1;
    ReadInt32(&reply2, &res);
    RPC_LOG_INFO(" 12 + 17 = %d", res);
    FreeBuffer((void *)ptr2);
    EXPECT_EQ(ret, ERR_NONE);
    int tmpSum = OP_A + OP_B;
    EXPECT_EQ(res, tmpSum);
}

HWTEST_F(IpcClientTest, IpcServerTest002_01, TestSize.Level1)
{
    RPC_LOG_INFO("====== call serverone OP_MULTI ======");
    IpcIo data2;
    uint8_t dataMulti[IPC_MAX_SIZE];
    IpcIoInit(&data2, dataMulti, IPC_MAX_SIZE, 0);
    WriteInt32(&data2, OP_A);
    WriteInt32(&data2, OP_B);
    IpcIo reply;
    uintptr_t ptr = 0;
    int ret = SendRequest(sidServer, SERVER_OP_MULTI, &data2, &reply, g_option, &ptr);
    int res = -1;
    ReadInt32(&reply, &res);
    RPC_LOG_INFO(" 12 * 17 = %d", res);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
    int tmpMul = OP_A * OP_B;
    EXPECT_EQ(res, tmpMul);
}

static IpcObjectStub objectStub = {
    .func = RemoteRequest,
    .isRemote = false
};

static SvcIdentity clientSvc = {
    .handle = -1,
    .token = 0,
    .cookie = (uintptr_t)&objectStub
};

HWTEST_F(IpcClientTest, IpcClientTest003, TestSize.Level1)
{
    IpcIo anonymous;
    uint8_t anonymousData[IPC_MAX_SIZE];
    IpcIoInit(&anonymous, anonymousData, IPC_MAX_SIZE, 1);
    WriteRemoteObject(&anonymous, &clientSvc);

    IpcIo anonymousreply;
    uintptr_t anonymousptr = 0;
    int ret = SendRequest(sidServer, SERVER_OP_ADD_SERVICE, &anonymous, &anonymousreply, g_option, &anonymousptr);
    int res;
    ReadInt32(&anonymousreply, &res);
    RPC_LOG_INFO("add self to server = %d", res);
    FreeBuffer((void *)anonymousptr);
    EXPECT_EQ(ret, ERR_NONE);
    EXPECT_EQ(res, ERR_NONE);
}

HWTEST_F(IpcClientTest, IpcClientTest004, TestSize.Level0)
{
    RPC_LOG_INFO("============= test case for add death callback ============");
    int ret = AddDeathRecipient(sidServer, (OnRemoteDead)ServerDead1, nullptr, &cbId1);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(sidServer, (OnRemoteDead)ServerDead2, nullptr, &cbId2);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(sidServer, (OnRemoteDead)ServerDead3, nullptr, &cbId3);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(sidServer, (OnRemoteDead)ServerDead3, nullptr, &cbId4);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(sidServer, (OnRemoteDead)ServerDead3, nullptr, &cbId5); // failed
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
}

HWTEST_F(IpcClientTest, IpcClientTest005, TestSize.Level0)
{
    RPC_LOG_INFO("============= test case for remove death callback ============");
    int ret = RemoveDeathRecipient(sidServer, cbId2);
    EXPECT_EQ(ret, ERR_NONE);
    ret = RemoveDeathRecipient(sidServer, cbId4);
    EXPECT_EQ(ret, ERR_NONE);
    ret = RemoveDeathRecipient(sidServer, cbId1);
    EXPECT_EQ(ret, ERR_NONE);
    ret = RemoveDeathRecipient(sidServer, cbId3);
    EXPECT_EQ(ret, ERR_NONE);
}

HWTEST_F(IpcClientTest, IpcClientTest006, TestSize.Level1)
{
    ++sidServer.handle;
    int ret = AddDeathRecipient(sidServer, (OnRemoteDead)ServerDead3, nullptr, &cbId5); // failed
    EXPECT_EQ(ret, ERR_INVALID_PARAM);

    ret = RemoveDeathRecipient(sidServer, cbId3); // failed
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    --sidServer.handle;
}

HWTEST_F(IpcClientTest, IpcClientTest007, TestSize.Level2)
{
    IpcIo data2;
    uint8_t tmpData2[IPC_MAX_SIZE];
    IpcIoInit(&data2, tmpData2, IPC_MAX_SIZE, 0);
    WriteInt32(&data2, OP_A);
    WriteInt32(&data2, OP_B);

    IpcIo reply2;
    uintptr_t ptr2 = 0;
    int res;

    struct timespec start = {0, 0};
    struct timespec end = {0, 0};

    clock_gettime(CLOCK_REALTIME, &start);
    for (int i = 0; i < PERFORMANCE_TEST_TIMES; i++) {
        SendRequest(sidServer, SERVER_OP_ADD, &data2, &reply2, g_option, &ptr2);
        ReadInt32(&reply2, &res);
        FreeBuffer((void *)ptr2);
    }
    clock_gettime(CLOCK_REALTIME, &end);

    float time = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000; // ms
    RPC_LOG_INFO("############ sync time with 100 times = %f ms", time);
}

HWTEST_F(IpcClientTest, IpcClientTest008, TestSize.Level2)
{
    IpcIo data2;
    uint8_t tmpData2[IPC_MAX_SIZE];
    IpcIoInit(&data2, tmpData2, IPC_MAX_SIZE, 0);
    WriteInt32(&data2, OP_A);
    WriteInt32(&data2, OP_B);

    struct timespec start = {0, 0};
    struct timespec end = {0, 0};

    MessageOption option = {
        .flags = TF_OP_ASYNC
    };

    clock_gettime(CLOCK_REALTIME, &start);
    for (int i = 0; i < PERFORMANCE_TEST_TIMES; i++) {
        SendRequest(sidServer, SERVER_OP_ADD, &data2, nullptr, option, nullptr);
    }
    clock_gettime(CLOCK_REALTIME, &end);

    float time = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000; // ms
    RPC_LOG_INFO("########### async time with 100 times = %f ms", time);
}

HWTEST_F(IpcClientTest, IpcClientTest009, TestSize.Level0)
{
    int ret = AddDeathRecipient(sidServer, (OnRemoteDead)ServerDead1, nullptr, &cbId1);
    EXPECT_EQ(ret, ERR_NONE);
    ret = AddDeathRecipient(sidServer, (OnRemoteDead)ServerDead2, nullptr, &cbId2);
    EXPECT_EQ(ret, ERR_NONE);
    while (1) {}
}
}  // namespace OHOS
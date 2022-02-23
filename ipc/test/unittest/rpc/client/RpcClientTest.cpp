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
#include "rpc_test.h"

#include <cstring>
#include <pthread.h>
#include <iostream>

#include "rpc_log.h"
#include "rpc_errno.h"
#include "rpc_trans.h"
#include "dbinder_service.h"
#include "ipc_skeleton.h"
#include "ipc_process_skeleton.h"
#include "rpc_process_skeleton.h"
#include "serializer.h"

namespace {
void ServerDead1(void *args)
{
    RPC_LOG_INFO("#### rpc server dead callback11 called");
}

MessageOption option = {
    .flags = TF_OP_SYNC,
    .waitTime = RPC_DEFAULT_SEND_WAIT_TIME
};
SvcIdentity sid;
char deviceId[DEVICEID_LENGTH];
uint32_t cbId1 = 0;
}

using namespace testing::ext;
using namespace std;

namespace OHOS {
class RpcClientTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        cout << "输入对端设备IP地址: ";
        cin >> deviceId;
        RPC_LOG_INFO("input deviceid is %s", deviceId);
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown()
    {
        sleep(1);
    }
};

/**
 * @tc.name: RPC_SendRequestNum_06
 * @tc.desc: proxy get stub failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest001, TestSize.Level0)
{
    IpcIo data1;
    uint8_t tmpData1[IPC_LENGTH];
    IpcIoInit(&data1, tmpData1, IPC_LENGTH, 0);
    WriteInt32(&data1, INVALID_SAID);
    WriteString(&data1, deviceId);

    IpcIo reply1;
    SvcIdentity target = {
        .handle = 0
    };

    RPC_LOG_INFO("get remote system ability from samgr.");
    uintptr_t ptr = 0;
    int32_t ret = SendRequest(target, GET_REMOTE_SYSTEM_ABILITY_TRANSACTION, &data1, &reply1, option, &ptr);
    EXPECT_EQ(ret, ERR_NONE);
    ReadInt32(&reply1, &ret);
    EXPECT_EQ(ret, ERR_FAILED);
    FreeBuffer((void *)ptr);
}

/**
 * @tc.name: RPC_SendRequestNum_05
 * @tc.desc: proxy get stub success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest002, TestSize.Level1)
{
    IpcIo data1;
    uint8_t tmpData1[IPC_LENGTH];
    IpcIoInit(&data1, tmpData1, IPC_LENGTH, 0);
    WriteInt32(&data1, SAID);
    WriteString(&data1, deviceId);

    IpcIo reply1;
    SvcIdentity target = {
        .handle = 0
    };

    RPC_LOG_INFO("get remote system ability from samgr.");
    uintptr_t ptr = 0;
    int32_t ret = SendRequest(target, GET_REMOTE_SYSTEM_ABILITY_TRANSACTION, &data1, &reply1, option, &ptr);
    EXPECT_EQ(ret, ERR_NONE);

    ReadRemoteObject(&reply1, &sid);
    RPC_LOG_INFO("call server add func server handle = %d.", sid.handle);
    EXPECT_NE(sid.handle, INVALID_HANDLE);
    FreeBuffer((void *)ptr);
}

/**
 * @tc.name: RPC_SendRequestNum_08
 * @tc.desc: proxy sendrequest failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest003, TestSize.Level1)
{
    IpcIo data2;
    uint8_t tmpData2[IPC_LENGTH];
    IpcIoInit(&data2, tmpData2, IPC_LENGTH, 0);
    WriteInt32(&data2, NUMBER_A);
    WriteInt32(&data2, NUMBER_B);

    IpcIo reply2;
    uintptr_t ptr2 = 0;
    int32_t oldHandle = sid.handle;
    sid.handle = INVALID_HANDLE;
    int32_t ret = SendRequest(sid, OP_ADD, &data2, &reply2, option, &ptr2);
    EXPECT_EQ(ret, ERR_FAILED);
    RPC_LOG_ERROR("SendRequest OP_ADD failed, error = %d", ret);
    FreeBuffer((void *)ptr2);

    sid.handle = oldHandle;
    EXPECT_EQ(sid.handle, oldHandle);
}

/**
 * @tc.name: RPC_SendRequestNum_07
 * @tc.desc: proxy sendrequest success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest004, TestSize.Level0)
{
    IpcIo data2;
    uint8_t tmpData2[IPC_LENGTH];
    IpcIoInit(&data2, tmpData2, IPC_LENGTH, 0);
    WriteInt32(&data2, NUMBER_A);
    WriteInt32(&data2, NUMBER_B);

    IpcIo reply2;
    uintptr_t ptr2 = 0;
    int32_t ret = SendRequest(sid, OP_ADD, &data2, &reply2, option, &ptr2);
    EXPECT_EQ(ret, ERR_NONE);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("SendRequest OP_ADD failed, error = %d", ret);
        FreeBuffer((void *)ptr2);
        return;
    }

    int32_t sum;
    ReadInt32(&reply2, &sum);
    RPC_LOG_INFO("%d + %d = %d", NUMBER_A, NUMBER_B, sum);
    EXPECT_EQ(sum, NUMBER_A + NUMBER_B);
    FreeBuffer((void *)ptr2);
}

/**
 * @tc.name: RPC_SendRequestNum_09
 * @tc.desc: stub process success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest005, TestSize.Level0)
{
    IpcIo data3;
    uint8_t tmpData3[IPC_LENGTH];
    IpcIoInit(&data3, tmpData3, IPC_LENGTH, 0);
    WriteInt32(&data3, NUMBER_A);
    WriteInt32(&data3, NUMBER_B);

    IpcIo reply3;
    uintptr_t ptr3 = 0;
    int32_t ret = SendRequest(sid, OP_MULTI, &data3, &reply3, option, &ptr3);
    EXPECT_EQ(ret, ERR_NONE);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("SendRequest OP_MULTI failed, error = %d", ret);
        FreeBuffer((void *)ptr3);
        return;
    }

    int32_t mutil;
    ReadInt32(&reply3, &mutil);
    RPC_LOG_INFO("%d * %d = %d", NUMBER_A, NUMBER_B, mutil);
    EXPECT_EQ(mutil, NUMBER_A * NUMBER_B);
    FreeBuffer((void *)ptr3);
}

/**
 * @tc.name: RPC_SendRequestNum_10
 * @tc.desc: stub process failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest006, TestSize.Level1)
{
    IpcIo data3;
    uint8_t tmpData3[IPC_LENGTH];
    IpcIoInit(&data3, tmpData3, IPC_LENGTH, 0);
    WriteInt32(&data3, NUMBER_A);
    WriteInt32(&data3, NUMBER_ZERO);

    IpcIo reply3;
    uintptr_t ptr3 = 0;
    int32_t ret = SendRequest(sid, OP_DIVISION, &data3, &reply3, option, &ptr3);
    EXPECT_EQ(ret, ERR_NONE);
    ReadInt32(&reply3, &ret);
    EXPECT_EQ(ret, ERR_FAILED);
    FreeBuffer((void *)ptr3);
}

/**
 * @tc.name: RPC_SendRequestNum_11
 * @tc.desc: proxy process success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest007, TestSize.Level0)
{
    IpcIo data;
    uint8_t tmpData[IPC_LENGTH];
    IpcIoInit(&data, tmpData, IPC_LENGTH, 0);
    WriteInt32(&data, NUMBER_A);
    WriteInt32(&data, NUMBER_B);

    IpcIo reply;
    uintptr_t ptr3 = 0;
    int32_t ret = SendRequest(sid, OP_DIVISION, &data, &reply, option, &ptr3);
    EXPECT_EQ(ret, ERR_NONE);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("SendRequest OP_DIVISION failed, error = %d", ret);
        FreeBuffer((void *)ptr3);
        return;
    }

    int32_t division;
    ReadInt32(&reply, &division);
    RPC_LOG_INFO("%d / %d = %d", NUMBER_A, NUMBER_B, division);
    EXPECT_EQ(division, NUMBER_A / NUMBER_B);
    FreeBuffer((void *)ptr3);
}

/**
 * @tc.name: RPC_SendRequestNum_12
 * @tc.desc: proxy sendrequest oneway
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest008, TestSize.Level0)
{
    IpcIo data;
    uint8_t tmpData[IPC_LENGTH];
    IpcIoInit(&data, tmpData, IPC_LENGTH, 0);
    WriteInt32(&data, NUMBER_A);
    WriteInt32(&data, NUMBER_B);

    IpcIo reply;
    uintptr_t ptr = 0;
    MessageOption oneWayOption = {
        .flags = TF_OP_ASYNC
    };
    int32_t ret = SendRequest(sid, OP_DIVISION, &data, &reply, oneWayOption, &ptr);
    EXPECT_EQ(ret, ERR_NONE);
    FreeBuffer((void *)ptr);
}

/**
 * @tc.name: RPC_SendRequestNum_14
 * @tc.desc: update proto
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest009, TestSize.Level1)
{
    UpdateProtoIfNeed(&sid);
    ThreadContext *threadContext = GetCurrentThreadContext();
    ASSERT_TRUE(threadContext != NULL);
    EXPECT_EQ(threadContext->proto, IF_PROT_DATABUS);
}

/**
 * @tc.name: RPC_SerializerNum_01
 * @tc.desc: data serializer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest010, TestSize.Level0)
{
    IpcIo data;
    uint8_t tmpData[IPC_LENGTH];
    IpcIoInit(&data, tmpData, IPC_LENGTH, 0);
    WriteInt32(&data, NUMBER_A);
    WriteInt32(&data, NUMBER_B);

    IpcIo reply;
    uintptr_t ptr = 0;
    int32_t ret = SendRequest(sid, OP_SERIALIZER, &data, &reply, option, &ptr);
    EXPECT_EQ(ret, ERR_NONE);
    ReadInt32(&reply, &ret);
    EXPECT_EQ(ret, ERR_NONE);
    FreeBuffer((void *)ptr);
}

/**
 * @tc.name: RPC_SerializerNum_08
 * @tc.desc: query proxy session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest011, TestSize.Level1)
{
    HandleSessionList *session = QueryProxySession(sid.handle);
    EXPECT_TRUE(session != NULL);
    EXPECT_GE(session->sessionId, 0);
}

/**
 * @tc.name: RPC_SessionNum_08
 * @tc.desc: proxy send normal code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest012, TestSize.Level1)
{
    IpcIo data;
    uint8_t tmpData[IPC_LENGTH];
    IpcIoInit(&data, tmpData, IPC_LENGTH, 0);
    WriteInt32(&data, NUMBER_A);
    WriteInt32(&data, NUMBER_B);

    IpcIo reply;
    uintptr_t ptr = 0;
    int32_t ret = SendRequest(sid, OP_MULTI, &data, &reply, option, &ptr);
    EXPECT_EQ(ret, ERR_NONE);
    FreeBuffer((void *)ptr);
}

/**
 * @tc.name: RPC_SessionNum_09
 * @tc.desc: proxy send invalid code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest013, TestSize.Level1)
{
    IpcIo data;
    uint8_t tmpData[IPC_LENGTH];
    IpcIoInit(&data, tmpData, IPC_LENGTH, 0);
    WriteInt32(&data, NUMBER_A);
    WriteInt32(&data, NUMBER_B);

    IpcIo reply;
    uintptr_t ptr = 0;
    int32_t ret = SendRequest(sid, OP_INVALID, &data, &reply, option, &ptr);
    EXPECT_EQ(ret, ERR_NONE);
    ReadInt32(&reply, &ret);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    FreeBuffer((void *)ptr);
}

/**
 * @tc.name: RPC_DeathRecipient_01
 * @tc.desc: proxy add death recipient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest014, TestSize.Level0)
{
    int32_t ret = AddDeathRecipient(sid, ServerDead1, nullptr, &cbId1);
    RPC_LOG_INFO("add death callback cbid1 = %d", ret);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: RPC_DeathRecipient_06
 * @tc.desc: proxy remote death recipient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest015, TestSize.Level0)
{
    int32_t ret = RemoveDeathRecipient(sid, cbId1);
    RPC_LOG_INFO("add death callback cbid1 = %d", ret);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: RPC_SessionNum_10
 * @tc.desc: stub disconnectted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcClientTest, RpcClientTest016, TestSize.Level1)
{
    int32_t ret = AddDeathRecipient(sid, ServerDead1, nullptr, &cbId1);
    RPC_LOG_INFO("add death callback cbid1 = %d", ret);
    EXPECT_EQ(ret, ERR_NONE);
    JoinWorkThread();
}
}  // namespace OHOS
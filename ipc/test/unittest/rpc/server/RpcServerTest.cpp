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

#include <securec.h>
#include "rpc_log.h"
#include "rpc_errno.h"
#include "ipc_skeleton.h"
#include "ipc_process_skeleton.h"
#include "serializer.h"
#include "dbinder_invoker.h"
#include "dbinder_types.h"

namespace {
int32_t Calculator(uint32_t code, int32_t a, int32_t b, IpcIo *reply)
{
    switch (code) {
        case OP_ADD: {
            RPC_LOG_INFO("RemoteRequestOne add called a = %d, b = %d", a, b);
            WriteInt32(reply, a + b);
            break;
        }
        case OP_SUB: {
            RPC_LOG_INFO("RemoteRequestOne sub called a = %d, b = %d", a, b);
            WriteInt32(reply, a - b);
            break;
        }
        case OP_MULTI: {
            RPC_LOG_INFO("RemoteRequestOne mulit called a = %d, b = %d", a, b);
            WriteInt32(reply, a * b);
            break;
        }
        case OP_DIVISION: {
            if (b == 0) {
                WriteInt32(reply, ERR_FAILED);
                return ERR_FAILED;
            }
            RPC_LOG_INFO("RemoteRequestOne division called a = %d, b = %d", a, b);
            WriteInt32(reply, a / b);
            break;
        }
        default: {
            RPC_LOG_ERROR("unknown calculator code %u", code);
            break;
        }
    }
    return ERR_NONE;
}

int32_t RemoteRequestOne(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    int32_t result = ERR_NONE;
    int32_t a = 0;
    int32_t b = 0;
    RPC_LOG_INFO("server OnRemoteRequestOne called....");
    switch (code) {
        case OP_ADD:
        case OP_SUB:
        case OP_MULTI:
        case OP_DIVISION: {
            ReadInt32(data, &a);
            ReadInt32(data, &b);
            result = Calculator(code, a, b, reply);
            break;
        }
        case OP_SERIALIZER: {
            WriteInt32(reply, ERR_NONE);
            result = ERR_NONE;
            break;
        }
        default: {
            RPC_LOG_ERROR("unknown code %u", code);
            result = ERR_INVALID_PARAM;
            WriteInt32(reply, ERR_INVALID_PARAM);
            break;
        }
    }
    return result;
}
}

using namespace testing::ext;

namespace OHOS {
class RpcServerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        RPC_LOG_INFO("----------test case for rpc server start-------------\n");
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: RPC_SendRequestNum_04
 * @tc.desc: stub registration failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcServerTest, RpcServerTest001, TestSize.Level1)
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
    WriteInt32(&data, INVALID_SAID);
    WriteRemoteObject(&data, &svcOne);

    IpcIo reply;
    MessageOption option = {
        .flags = TF_OP_SYNC
    };

    SvcIdentity target = {
        .handle = 0
    };

    RPC_LOG_INFO("====== add ability one to samgr ======");
    uintptr_t ptr = 0;
    int32_t ret = SendRequest(target, ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION, &data, &reply, option, &ptr);
    EXPECT_EQ(ret, ERR_NONE);

    ReadInt32(&reply, &ret);
    EXPECT_EQ(ret, ERR_FAILED);
    FreeBuffer((void *)ptr);
}

/**
 * @tc.name: RPC_SendRequestNum_13
 * @tc.desc: stub registration success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcServerTest, RpcServerTest002, TestSize.Level1)
{
    IpcSkeleton *current = GetCurrentSkeleton();
    ASSERT_TRUE(current != NULL);
    if (current->threadPool->idleSocketThreadNum > 0) {
        int32_t ret = SpawnThread(SPAWN_PASSIVE, IF_PROT_DATABUS);
        EXPECT_EQ(ret, ERR_NONE);
    }
}

/**
 * @tc.name: RPC_SendRequestNum_03
 * @tc.desc: stub registration success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RpcServerTest, RpcServerTest003, TestSize.Level0)
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
    WriteInt32(&data, SAID);
    WriteRemoteObject(&data, &svcOne);

    IpcIo reply;
    MessageOption option = {
        .flags = TF_OP_SYNC
    };

    SvcIdentity target = {
        .handle = 0
    };

    RPC_LOG_INFO("====== add ability one to samgr ======");
    uintptr_t ptr = 0;
    int32_t ret = SendRequest(target, ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION, &data, &reply, option, &ptr);
    EXPECT_EQ(ret, ERR_NONE);

    ReadInt32(&reply, &ret);
    RPC_LOG_INFO("send request one ret = %d .... ", ret);
    EXPECT_EQ(ret, ERR_NONE);
    FreeBuffer((void *)ptr);

    JoinWorkThread();
}
}  // namespace OHOS
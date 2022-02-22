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

#include <cstdlib>
#include <thread>
#include <unistd.h>

#include "ipc_proxy.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "serializer.h"

static SvcIdentity *sid = nullptr;

static SvcIdentity g_samgr = {
    .handle = 0
};

static void CallAnonymosFunc(const char *str)
{
    if (sid == nullptr) {
        RPC_LOG_INFO("invalid anonymous client");
        return;
    }
    RPC_LOG_INFO("now server call client anonymous func");
    IpcIo data;
    uint8_t tmpData1[IPC_MAX_SIZE];
    IpcIoInit(&data, tmpData1, IPC_MAX_SIZE, 1);
    WriteString(&data, str);

    IpcIo reply;
    MessageOption option = {
        .flags = TF_OP_ASYNC
    };
    SendRequest(*sid, CLIENT_OP_PRINT, &data, &reply, option, nullptr);
}

static int32_t RemoteRequestOne(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
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
            RPC_LOG_ERROR("unknown code %d", code);
            break;
    }
    return result;
}

static int32_t RemoteRequestTwo(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
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
            RPC_LOG_ERROR("unknown code %d", code);
            break;
    }
    return result;
}

static void ThreadHandler()
{
    sleep(IPC_TEST_TIME_INTERVAL); // sleep 2 min
    const char *str = "server call anonymos service new thread.";
    CallAnonymosFunc(str);
}

static MessageOption g_option = {
    .flags = TF_OP_SYNC
};

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

class Ability {
public:
    explicit Ability(int32_t data) : data_(data)
    {
        sid_ = (SvcIdentity *)malloc(sizeof(SvcIdentity));
        objectStub_ = (IpcObjectStub *)malloc(sizeof(IpcObjectStub));
        objectStub_->func = Ability::MsgHandleInner;
        objectStub_->args = this;
        sid_->handle = -1;
        sid_->token  = (uintptr_t)objectStub_;
        sid_->cookie = (uintptr_t)objectStub_;
    }

    static int32_t MsgHandleInner(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
    {
        Ability *ability = static_cast<Ability *>(option.args);
        RPC_LOG_INFO("server MsgHandleInner called...., p = %p, data = %d", ability, ability->data_);

        int32_t result = ERR_NONE;
        switch (code) {
            case SERVER_OP_ADD: {
                int32_t a;
                ReadInt32(data, &a);
                int32_t b;
                ReadInt32(data, &b);
                WriteInt32(reply, a + b);
                break;
            }
            case SERVER_OP_SUB: {
                int32_t a;
                ReadInt32(data, &a);
                int32_t b;
                ReadInt32(data, &b);
                WriteInt32(reply, a - b);
                break;
            }
            case SERVER_OP_MULTI: {
                int32_t a;
                ReadInt32(data, &a);
                int32_t b;
                ReadInt32(data, &b);
                WriteInt32(reply, a * b);
                break;
            }
            case SERVER_OP_ADD_SERVICE: {
                sid = (SvcIdentity *)calloc(1, sizeof(SvcIdentity));
                ReadRemoteObject(data, sid);
                const char *str = "server call anonymos service one.";
                break;
            }
            default:
                RPC_LOG_ERROR("unknown code %d", code);
                break;
        }
        return result;
    }

    SvcIdentity *sid_;
private:
    int32_t data_;
    IpcObjectStub *objectStub_;
};

static void AddSaOne(void)
{
    IpcIo data;
    uint8_t tmpData1[IPC_MAX_SIZE];
    IpcIoInit(&data, tmpData1, IPC_MAX_SIZE, 1);
    WriteInt32(&data, SERVER_SA_ID1);

    Ability *ability = new Ability(322516);
    RPC_LOG_INFO("====== add ability one to samgr ====== %p", ability);
    WriteRemoteObject(&data, ability->sid_);

    IpcIo reply;
    uintptr_t ptr = 0;
    RPC_LOG_INFO("====== add ability one to samgr ======");
    int ret = SendRequest(g_samgr, ADD_SYSTEM_ABILITY_TRANSACTION, &data, &reply, g_option, &ptr);
    int res = -1;
    ReadInt32(&reply, &res);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
    EXPECT_EQ(res, ERR_NONE);
    sleep(1);
}

static void AddSaTwo(void)
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
    sleep(1);
}

int main(int argc, char *argv[])
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
    sleep(1);

    RPC_LOG_INFO("====== call serverone OP_MULTI ======");
    IpcIo data2;
    uint8_t dataMulti[IPC_MAX_SIZE];
    IpcIoInit(&data2, dataMulti, IPC_MAX_SIZE, 0);
    WriteInt32(&data2, OP_A);
    WriteInt32(&data2, OP_B);
    ret = SendRequest(sidOne, SERVER_OP_MULTI, &data2, &reply, g_option, &ptr);
    int res = -1;
    ReadInt32(&reply, &res);
    RPC_LOG_INFO(" 12 * 17 = %d", res);
    FreeBuffer((void *)ptr);
    EXPECT_EQ(ret, ERR_NONE);
    int tmpMul = OP_A * OP_B;
    EXPECT_EQ(res, tmpMul);

    std::thread task(ThreadHandler);
    task.detach();
    JoinWorkThread();
    return -1;
}
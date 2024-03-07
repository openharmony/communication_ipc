/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <ohos_init.h>

#include "ipc_proxy.h"
#include "ipc_skeleton.h"
#include "iproxy_client.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "serializer.h"
#include "samgr_lite.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50

static IClientProxy *g_serverProxy = NULL;

static void ServerDeadCallback(void *arg)
{
    RPC_LOG_INFO("====== server dead ServerDeadCallback called ======");
}

static void AddDeathCallback()
{
    IpcIo reply;
    SvcIdentity sid;
    uint32_t cbId = 0;

    SvcIdentity svcIdentity = SAMGR_GetRemoteIdentity(IPC_TEST_SERVICE, NULL);
    int32_t ret = AddDeathRecipient(svcIdentity, ServerDeadCallback, NULL, &cbId);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("[ipc_test_client] AddDeathRecipient failed, ret:[%d]", ret);
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] add death callback success, cbId = [%u]", cbId);
}

static int ServerAddCallback(IOwner owner, int code, IpcIo *reply)
{
    RPC_LOG_INFO("ServerAddCallback start.");
    if (code != 0) {
        RPC_LOG_ERROR("server add callback error[%d].", code);
        return -1;
    }

    ReadInt32(reply, (int *)owner);
    int tmpSum = OP_A + OP_B;
    RPC_LOG_INFO("ServerAddCallback return[%d].", *(int32_t*)owner);
    EXPECT_EQ(*(int32_t*)owner, tmpSum);
    return 0;
}

static void CallServerAdd(void)
{
    RPC_LOG_INFO("====== CallServerAdd start ======");
    IpcIo data;
    uint8_t dataAdd[IPC_MAX_SIZE];
    IpcIoInit(&data, dataAdd, IPC_MAX_SIZE, 0);
    WriteInt32(&data, OP_A);
    WriteInt32(&data, OP_B);

    int32_t ret = -1;
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_OP_ADD, &data, &ret, ServerAddCallback);
    RPC_LOG_INFO("SERVER_OP_ADD callback ret=[%d] ans=[%d]", ret, ans);
    if (ans != 0) {
        RPC_LOG_ERROR("SERVER_OP_ADD callback ret [%d]", ret);
    }

    RPC_LOG_INFO("====== CallServerAdd end ======");
}

static int ServerMultiCallback(IOwner owner, int code, IpcIo *reply)
{
    if (code != 0) {
        RPC_LOG_ERROR("server multi callback error[%d].", code);
        return -1;
    }

    ReadInt32(reply, (int *)owner);
    int tmpMulti = OP_A * OP_B;
    RPC_LOG_INFO("ServerMultiCallback return[%d].", *(int32_t*)owner);
    EXPECT_EQ(*(int32_t*)owner, tmpMulti);
    return 0;
}

static void CallServerMulti(void)
{
    RPC_LOG_INFO("====== call serverone OP_MULTI start======");
    IpcIo data;
    uint8_t dataMulti[IPC_MAX_SIZE];
    IpcIoInit(&data, dataMulti, IPC_MAX_SIZE, 0);
    WriteInt32(&data, OP_A);
    WriteInt32(&data, OP_B);
    int ret = -1;
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_OP_MULTI, &data, &ret, ServerMultiCallback);
    if (ans != 0) {
        RPC_LOG_ERROR("SERVER_OP_MULTI callback ret [%d]", ret);
    }

    RPC_LOG_INFO("====== call serverone OP_MULTI end======");
}

static int ServerSubCallback(IOwner owner, int code, IpcIo *reply)
{
    if (code != 0) {
        RPC_LOG_ERROR("server multi callback error[%d].", code);
        return -1;
    }

    ReadInt32(reply, (int *)owner);
    int tmpMulti = OP_A - OP_B;
    RPC_LOG_INFO("ServerSubCallback return[%d].", *(int32_t*)owner);
    EXPECT_EQ(*(int32_t*)owner, tmpMulti);
    return 0;
}

static void CallServerSub(void)
{
    RPC_LOG_INFO("====== call serverone OP_SUB start======");
    IpcIo data;
    uint8_t dataSub[IPC_MAX_SIZE];
    IpcIoInit(&data, dataSub, IPC_MAX_SIZE, 0);
    WriteInt32(&data, OP_A);
    WriteInt32(&data, OP_B);
    int ret = -1;
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_OP_SUB, &data, &ret, ServerSubCallback);
    if (ans != 0) {
        RPC_LOG_INFO("SERVER_OP_SUB callback ret [%d]", ret);
    }
    RPC_LOG_INFO("====== call serverone OP_SUB end======");
}

static IClientProxy *GetServerProxy(void)
{
    IClientProxy *clientProxy = NULL;

    RPC_LOG_INFO("[ipc_test_client] start get client proxy");
    int32_t proxyInitCount = 0;
    while (clientProxy == NULL) {
        proxyInitCount++;
        if (proxyInitCount == WAIT_SERVER_READY_INTERVAL_COUNT) {
            RPC_LOG_ERROR("[ipc_test_client] get server proxy error");
            return NULL;
        }
        IUnknown *iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(IPC_TEST_SERVICE);
        if (iUnknown == NULL) {
            RPC_LOG_ERROR("iUnknown is null");
            sleep(1);
            continue;
        }
        RPC_LOG_INFO("[ipc_test_client] GetDefaultFeatureApi success");

        int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&clientProxy);
        if (ret != EC_SUCCESS || clientProxy == NULL) {
            RPC_LOG_ERROR("QueryInterface failed [%d]", ret);
            sleep(1);
            continue;
        }
    }

    RPC_LOG_INFO("[ipc_test_client] get client proxy ok");
    return clientProxy;
}

static void __attribute__((weak)) HOS_SystemInit(void)
{
    SAMGR_Bootstrap();
    return;
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("[ipc_test_client] Enter System Ability Client");
    HOS_SystemInit();
    RPC_LOG_INFO("[ipc_test_client] SystemInit end");

    RPC_LOG_INFO("[ipc_test_client] GetServerProxy start");
    g_serverProxy = GetServerProxy();
    if (g_serverProxy == NULL) {
        RPC_LOG_ERROR("get ipc client proxy failed");
        return -1;
    }
    RPC_LOG_INFO("[ipc_test_client] GetServerProxy end");

    AddDeathCallback();
    CallServerAdd();
    CallServerMulti();
    CallServerSub();

    while (1) {
        pause();
    }

    return -1;
}
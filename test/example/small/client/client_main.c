/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <ohos_init.h>
#include <stdlib.h>

#include "client_business_impl.h"
#include "common.h"
#include "ipc_skeleton.h"
#include "iproxy_client.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "samgr_lite.h"
#include "serializer.h"

#define INVALID_CB_ID 0xFF
#define WAIT_SERVER_READY_INTERVAL_COUNT 50
#define EXIT_TIMEOUT 60 // 60s

static IClientProxy *g_serverProxy = NULL;

static void ServerDeadCallback(void *arg)
{
    (void)arg;
    RPC_LOG_INFO("====== server dead ServerDeadCallback called ======");
}

static void AddDeathCallback()
{
    uint32_t cbId = INVALID_CB_ID;

    SvcIdentity svcIdentity = SAMGR_GetRemoteIdentity(IPC_TEST_SMALL, NULL);
    int32_t ret = AddDeathRecipient(svcIdentity, ServerDeadCallback, NULL, &cbId);
    if (ret != ERR_NONE) {
        RPC_LOG_ERROR("[ipc_test_client] AddDeathRecipient failed, ret:[%d]", ret);
        return;
    }
    RPC_LOG_INFO("[ipc_test_client] add death callback success, cbId = [%u]", cbId);
}

static void HOS_SystemInit(void)
{
    SAMGR_Bootstrap();
    return;
}

void ClientSendData()
{
    const int32_t executionInterval = 2; // 2s
    SendBool();
    SendInt8();
    SendInt16();
    SendInt32();
    SendInt64();
    sleep(executionInterval);
    SendUint8();
    SendUint16();
    SendUint32();
    SendUint64();
    SendFloat();
    SendDouble();
    sleep(executionInterval);
    SendInt8Vector();
    SendInt8Vector();
    SendInt16Vector();
    SendInt32Vector();
    SendInt64Vector();
    sleep(executionInterval);
    SendUint8Vector();
    SendUint16Vector();
    SendUint32Vector();
    SendUint64Vector();
    SendFloatVector();
    SendDoubleVector();
    sleep(executionInterval);
    SendFileDescriptor();
    SendString();
    SendRawData();
    SendBuffer();
    //remoteObject sent in RegisterToService
    RPC_LOG_INFO("[ipc_test_client] SendData end");
    return;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    RPC_LOG_INFO("[ipc_test_client] Enter System Ability Client");
    HOS_SystemInit();
    RPC_LOG_INFO("[ipc_test_client] SystemInit end");
    InitLocalIdentity();
    RegisterToService();
    AddDeathCallback();
    ClientSendData();

    // auto exit when timeout
    sleep(EXIT_TIMEOUT);
    RPC_LOG_INFO("[ipc_test_client] exit");
    return 0;
}
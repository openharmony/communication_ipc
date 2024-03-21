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
#include <unistd.h>
#include <ohos_init.h>

#include "ipc_proxy.h"
#include "ipc_skeleton.h"
#include "iproxy_server.h"
#include "iproxy_client.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "serializer.h"
#include "samgr_lite.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50
#define STACK_SIZE 0x800
#define QUEUE_SIZE 20
#define WAIT_FOR_SERVER 2

typedef struct IPCSaInterface {
    INHERIT_SERVER_IPROXY;
} IPCSaInterface;

typedef struct IPCSaService {
    INHERIT_SERVICE;
    INHERIT_IUNKNOWNENTRY(IPCSaInterface);
    Identity identity;
} IPCSaService;

static const char *GetName(Service *service)
{
    (void)service;
    return IPC_TEST_SERVICE;
}

static BOOL Initialize(Service *service, Identity identity)
{
    if (service == NULL) {
        RPC_LOG_ERROR("invalid param");
        return FALSE;
    }
    IPCSaService *ipcSaService = (IPCSaService *)service;
    ipcSaService->identity = identity;
    return TRUE;
}

static BOOL MessageHandle(Service *service, Request *msg)
{
    return TRUE;
}

static TaskConfig GetTaskConfig(Service *service)
{
    (void)service;
    TaskConfig config = { LEVEL_HIGH, PRI_BELOW_NORMAL, STACK_SIZE, QUEUE_SIZE, SHARED_TASK };
    return config;
}

static int32_t ServerOpAdd(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] ServerOpAdd called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("invalid param");
        return ERR_INVALID_PARAM;
    }
    int32_t a;
    ReadInt32(req, &a);
    int32_t b;
    ReadInt32(req, &b);
    WriteInt32(reply, a + b);
    RPC_LOG_INFO("[ipc_test_server] ServerOpAdd:a = %d, b = %d", a, b);
    return 0;
}

static int32_t ServerOpSub(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] ServerOpSub called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("invalid param");
        return ERR_INVALID_PARAM;
    }
    int32_t a;
    ReadInt32(req, &a);
    int32_t b;
    ReadInt32(req, &b);
    WriteInt32(reply, a - b);
    RPC_LOG_INFO("[ipc_test_server] ServerOpSub:a = %d, b = %d", a, b);
    return 0;
}

static int32_t ServerOpMulit(IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server] ServerOpMulit called");
    if (req == NULL || reply == NULL) {
        RPC_LOG_ERROR("invalid param");
        return ERR_INVALID_PARAM;
    }
    int32_t a;
    ReadInt32(req, &a);
    int32_t b;
    ReadInt32(req, &b);
    WriteInt32(reply, a * b);
    RPC_LOG_INFO("[ipc_test_server] ServerOpMulit:a = %d, b = %d", a, b);
    return 0;
}

typedef struct {
    enum ServerFuncId id;
    int32_t (*func)(IpcIo *req, IpcIo *reply);
} ServerInvokeCmd;

ServerInvokeCmd g_serverInvokeCmdTbl[] = {
    { SERVER_OP_ADD, ServerOpAdd },
    { SERVER_OP_SUB, ServerOpSub },
    { SERVER_OP_MULTI, ServerOpMulit },
};

static int32_t Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    RPC_LOG_INFO("[ipc_test_server]Invoke:RECEIVE FUNCID:%d", funcId);
    int tblSize = sizeof(g_serverInvokeCmdTbl) / sizeof(ServerInvokeCmd);
    for (int i = 0; i < tblSize; i++) {
        if (funcId == g_serverInvokeCmdTbl[i].id) {
            return g_serverInvokeCmdTbl[i].func(req, reply);
        }
    }
    RPC_LOG_INFO("[ipc_test_server]not support func[%d]", funcId);
    return -1;
}

static IPCSaService g_ipcSaService = {
    .GetName = GetName,
    .Initialize = Initialize,
    .MessageHandle = MessageHandle,
    .GetTaskConfig = GetTaskConfig,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = Invoke,
    IPROXY_END,
};

static void __attribute__((weak)) HOS_SystemInit(void)
{
    SAMGR_Bootstrap();
    return;
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("[ipc_test_server] Enter System Ability Server");
    HOS_SystemInit();

    while (1) {
        pause();
    }
    RPC_LOG_INFO("[ipc_test_server] return");
    return -1;
}

static void Init(void)
{
    RPC_LOG_INFO("[ipc_test_server] Init start");
    sleep(WAIT_FOR_SERVER);
    SAMGR_GetInstance()->RegisterService((Service *)&g_ipcSaService);
    SAMGR_GetInstance()->RegisterDefaultFeatureApi(IPC_TEST_SERVICE, GET_IUNKNOWN(g_ipcSaService));
}

SYSEX_SERVICE_INIT(Init);

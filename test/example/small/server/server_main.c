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
#include <unistd.h>

#include "common.h"
#include "rpc_errno.h"
#include "rpc_log.h"
#include "ipc_skeleton.h"
#include "samgr_lite.h"
#include "serializer.h"
#include "server_business_impl.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50
#define STACK_SIZE 0x800
#define QUEUE_SIZE 50
#define WAIT_FOR_SERVER 2
#define EXIT_TIMEOUT 60 // 60s

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
    return IPC_TEST_SMALL;
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
    RPC_LOG_INFO("[ipc_test_server] MessageHandle called");
    return FALSE;
}

static TaskConfig GetTaskConfig(Service *service)
{
    (void)service;
    TaskConfig config = { LEVEL_HIGH, PRI_BELOW_NORMAL, STACK_SIZE, QUEUE_SIZE, SHARED_TASK };
    return config;
}

static IPCSaService g_ipcSaService = {
    .GetName = GetName,
    .Initialize = Initialize,
    .MessageHandle = MessageHandle,
    .GetTaskConfig = GetTaskConfig,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = DispatchInvoke,
    IPROXY_END,
};

void __attribute__((weak)) HOS_SystemInit(void)
{
    SAMGR_Bootstrap();
    return;
}

int main(int argc, char *argv[])
{
    RPC_LOG_INFO("[ipc_test_server] server enter");
    HOS_SystemInit();

    // auto exit when timeout
    sleep(EXIT_TIMEOUT);
    RPC_LOG_INFO("[ipc_test_server] exit");
    return 0;
}

static void Init(void)
{
    // server register to samgr_lite
    RPC_LOG_INFO("[ipc_test_server] Init start");
    sleep(WAIT_FOR_SERVER);
    SAMGR_GetInstance()->RegisterService((Service *)&g_ipcSaService);
    SAMGR_GetInstance()->RegisterDefaultFeatureApi(IPC_TEST_SMALL, GET_IUNKNOWN(g_ipcSaService));
}

SYSEX_SERVICE_INIT(Init);

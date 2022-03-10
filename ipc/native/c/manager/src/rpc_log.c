/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "rpc_log.h"

#include <stdint.h>
#include "securec.h"

#define LOG_NAME_MAX_LEN 5
#define LOG_PRINT_MAX_LEN 256

typedef struct {
    RpcLogModule mod;
    char name[LOG_NAME_MAX_LEN];
} LogInfo;

static LogInfo g_logInfo[RPC_LOG_MODULE_MAX] = {
    {RPC_LOG_IPC, "IPC"},
    {RPC_LOG_RPC, "RPC"},
    {RPC_LOG_SER, "SER"},
};

static void RpcOutPrint(const char *buf, RpcLogLevel level)
{
#ifdef IPCRPC_PRINTF
    printf("%s\n", buf);
    return;
#endif
    switch (level) {
        case RPC_LOG_DBG:
            HILOG_DEBUG(RPC_HILOG_ID, "%{public}s", buf);
            break;
        case RPC_LOG_INFO:
            HILOG_INFO(RPC_HILOG_ID, "%{public}s", buf);
            break;
        case RPC_LOG_WARN:
            HILOG_WARN(RPC_HILOG_ID, "%{public}s", buf);
            break;
        case RPC_LOG_ERROR:
            HILOG_ERROR(RPC_HILOG_ID, "%{public}s", buf);
            break;
        default:
            break;
    }
}

void RpcLog(RpcLogModule module, RpcLogLevel level, const char *fmt, ...)
{
    int32_t ulPos;
    char szStr[LOG_PRINT_MAX_LEN] = {0};
    va_list arg;
    int32_t ret;

    if (module >= RPC_LOG_MODULE_MAX || level >= RPC_LOG_LEVEL_MAX) {
        HILOG_ERROR(RPC_HILOG_ID, "rpc log type or module error");
        return;
    }

    ret = sprintf_s(szStr, sizeof(szStr), "[%s]", g_logInfo[module].name);
    if (ret < 0) {
        HILOG_ERROR(RPC_HILOG_ID, "rpc log error");
        return;
    }
    ulPos = strlen(szStr);
    (void)memset_s(&arg, sizeof(va_list), 0, sizeof(va_list));
    va_start(arg, fmt);
    ret = vsprintf_s(&szStr[ulPos], sizeof(szStr) - ulPos, fmt, arg);
    va_end(arg);
    if (ret < 0) {
        HILOG_ERROR(RPC_HILOG_ID, "rpc log len error");
        return;
    }
    RpcOutPrint(szStr, level);

    return;
}

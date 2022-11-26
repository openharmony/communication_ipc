/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_RPC_LOG_H
#define OHOS_IPC_RPC_LOG_H

#include <stdio.h>
#include <stdbool.h>

#ifndef IPCRPC_DEBUG
#if defined(__LITEOS_M__)
#define IPCRPC_PRINTF
#include "log.h"
#else
#include "hilog/log.h"
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IPCRPC_DEBUG
#if defined(__LITEOS_M__)
#define RPC_LOG_DEBUG(fmt, ...)  HILOG_DEBUG(HILOG_MODULE_SOFTBUS, fmt, ##__VA_ARGS__)
#define RPC_LOG_INFO(fmt, ...)   HILOG_INFO(HILOG_MODULE_SOFTBUS, fmt, ##__VA_ARGS__)
#define RPC_LOG_WARN(fmt, ...)   HILOG_WARN(HILOG_MODULE_SOFTBUS, fmt, ##__VA_ARGS__)
#define RPC_LOG_ERROR(fmt, ...)  HILOG_ERROR(HILOG_MODULE_SOFTBUS, fmt, ##__VA_ARGS__)
#else
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD001518
#define LOG_TAG "IPCRPC"

#define RPC_LOG_DEBUG(fmt, ...) HILOG_DEBUG(LOG_CORE, fmt, ##__VA_ARGS__)
#define RPC_LOG_INFO(fmt, ...)  HILOG_INFO(LOG_CORE, fmt, ##__VA_ARGS__)
#define RPC_LOG_WARN(fmt, ...)  HILOG_WARN(LOG_CORE, fmt, ##__VA_ARGS__)
#define RPC_LOG_ERROR(fmt, ...) HILOG_ERROR(LOG_CORE, fmt, ##__VA_ARGS__)
#endif
#else
enum {
    RPC_LOG_LEVEL_DEBUG = 0,
    RPC_LOG_LEVEL_INFO,
    RPC_LOG_LEVEL_WARNING,
    RPC_LOG_LEVEL_ERROR
};

#define RPC_LOG_LEVEL RPC_LOG_LEVEL_INFO

#define LOG_DBG(fmt, ...) do { \
    if (RPC_LOG_LEVEL_DEBUG >= RPC_LOG_LEVEL) { \
        printf("DEBUG: " fmt "\n", ##__VA_ARGS__); \
    } \
} while (0)

#define LOG_INFO(fmt, ...) do { \
    if (RPC_LOG_LEVEL_INFO >= RPC_LOG_LEVEL) { \
        printf("INFO: " fmt "\n", ##__VA_ARGS__); \
    } \
} while (0)

#define LOG_WARN(fmt, ...) do { \
    if (RPC_LOG_LEVEL_WARNING >= RPC_LOG_LEVEL) { \
        printf("WARN: " fmt "\n", ##__VA_ARGS__); \
    } \
} while (0)

#define LOG_ERR(fmt, ...) do { \
    if (RPC_LOG_LEVEL_ERROR >= RPC_LOG_LEVEL) { \
        printf("ERROR: " fmt "\n", ##__VA_ARGS__); \
    } \
} while (0)
#endif

#if defined(__LITEOS_M__)
#define RPC_HILOG_ID HILOG_MODULE_SOFTBUS
#else
#define RPC_HILOG_ID LOG_CORE
#endif

typedef enum {
    RPC_LOG_DBG,
    RPC_LOG_INFO,
    RPC_LOG_WARN,
    RPC_LOG_ERROR,
    RPC_LOG_LEVEL_MAX,
} RpcLogLevel;

typedef enum {
    RPC_LOG_IPC,
    RPC_LOG_RPC,
    RPC_LOG_SER,
    RPC_LOG_MODULE_MAX,
} RpcLogModule;

void RpcLog(RpcLogModule module, RpcLogLevel level, const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* OHOS_IPC_RPC_LOG_H */
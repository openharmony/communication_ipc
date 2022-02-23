/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_RPC_DBINDER_TYPES_H
#define OHOS_RPC_DBINDER_TYPES_H

#include <stdint.h>

#include "utils_list.h"

#include "serializer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEVICEID_LENGTH 64
#define SERVICENAME_LENGTH 200
#define VERSION_NUM 1
#define SESSION_NAME_LEGNTH 8
#define RPC_IPC_LENGTH 128
#define RPC_IPC_LENGTH_LONG 256
#define GET_SYSTEM_ABILITY_TRANSACTION 1
#define ID_DIGITS 10
#define USECTONSEC 1000

enum DBinderCode {
    MESSAGE_AS_INVOKER          = 1,
    MESSAGE_AS_REPLY            = 2,
    MESSAGE_AS_OBITUARY         = 3,
};

enum AfType {
    IPV4_TYPE          = 1,
    IPV6_TYPE          = 2,
    DATABBUS_TYPE      = 3,
};

enum {
    DATABUS_TYPE
};

struct DeviceIdInfo {
    uint16_t afType;
    uint16_t reserved;
    char fromDeviceId[DEVICEID_LENGTH + 1];
    char toDeviceId[DEVICEID_LENGTH + 1];
};

struct DHandleEntryHead {
    uint32_t len;
    uint32_t version;
};

typedef struct {
    UTILS_DL_LIST list;
    uint32_t type;
    uint16_t toPort;
    uint16_t fromPort;
    uint64_t stubIndex;
    uint32_t socketFd;
    char serviceName[SERVICENAME_LENGTH + 1];
    struct DeviceIdInfo deviceIdInfo;
    uintptr_t stub;
} SessionInfo;

typedef struct {
    UTILS_DL_LIST list;
    uintptr_t binderObject;
    SvcIdentity *proxy;
    char *sessionName;
    uint32_t cbId;
} ProxyObject;

typedef struct {
    uint32_t sizeOfSelf;
    uint32_t magic;
    uint32_t version;
    int32_t cmd;
    uint32_t code;
    uint32_t flags;
    uint64_t cookie;
    uint64_t seqNumber;
    uint64_t buffer_size;
    uint64_t offsets_size;
    uint64_t offsets;
    char *buffer;
} dbinder_transaction_data;

typedef struct {
    struct DHandleEntryHead head;
    uint32_t transType;
    uint32_t dBinderCode;
    uint16_t fromPort;
    uint16_t toPort;
    uint64_t stubIndex;
    uint32_t seqNumber;
    uintptr_t binderObject;
    struct DeviceIdInfo deviceIdInfo;
    uintptr_t stub;
    uint16_t serviceNameLength;
    char serviceName[SERVICENAME_LENGTH + 1];
    uint32_t pid;
    uint32_t uid;
} DHandleEntryTxRx;

#ifdef __cplusplus
}
#endif
#endif // OHOS_RPC_DBINDER_TYPES_H
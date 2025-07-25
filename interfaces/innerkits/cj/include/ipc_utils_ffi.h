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

#ifndef IPC_UTILS_FFI_H
#define IPC_UTILS_FFI_H

#include <cstdint>
#include <cstring>
#include <string>

#include "hilog/log.h"

namespace OHOS {
const unsigned int LOG_ID_IPC_BASE = 0xD0057C0;
const unsigned int LOG_ID_IPC_FFI = LOG_ID_IPC_BASE | 0x08;
const int64_t INVALID_ID = 0;
const int32_t INVALID_REMOTE_TYPE = -1;
const int32_t REMOTE_OBJECT = 0;
const int32_t REMOTE_PROXY = 1;
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_FFI, "RPC_FFI" };

constexpr size_t MAX_CAPACITY_TO_WRITE = 200 * 1024;
constexpr size_t MAX_BYTES_LENGTH = 40960;
constexpr size_t BYTE_SIZE_8 = 1;
constexpr size_t BYTE_SIZE_16 = 2;
constexpr size_t BYTE_SIZE_32 = 4;
constexpr size_t BYTE_SIZE_64 = 8;

struct RequestResult {
    int32_t errCode;
    uint32_t code;
    int64_t data;
    int64_t reply;
};

enum errorDesc {
    CHECK_PARAM_ERROR = 401,
    OS_MMAP_ERROR = 1900001,
    OS_IOCTL_ERROR,
    WRITE_TO_ASHMEM_ERROR,
    READ_FROM_ASHMEM_ERROR,
    ONLY_PROXY_OBJECT_PERMITTED_ERROR,
    ONLY_REMOTE_OBJECT_PERMITTED_ERROR,
    COMMUNICATION_ERROR,
    PROXY_OR_REMOTE_OBJECT_INVALID_ERROR,
    WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR,
    READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
    PARCEL_MEMORY_ALLOC_ERROR,
    CALL_JS_METHOD_ERROR,
    OS_DUP_ERROR
};

enum TypeCode {
    INT8_ARRAY = 0,
    UINT8_ARRAY = 1,
    INT16_ARRAY = 2,
    UINT16_ARRAY = 3,
    INT32_ARRAY = 4,
    UINT32_ARRAY = 5,
    FLOAT32_ARRAY = 6,
    FLOAT64_ARRAY = 7,
    BIGINT64_ARRAY = 8,
    BIGUINT64_ARRAY = 9,
};

typedef struct {
    int8_t* data;
    uint32_t len;
} CJByteArray;

typedef struct {
    int16_t* data;
    uint32_t len;
} CJShortArray;

typedef struct {
    uint16_t* data;
    uint32_t len;
} CJUInt16Array;

typedef struct {
    int32_t* data;
    uint32_t len;
} CJIntArray;

typedef struct {
    uint32_t* data;
    uint32_t len;
} CJUInt32Array;

typedef struct {
    int64_t* data;
    uint32_t len;
} CJLongArray;

typedef struct {
    uint64_t* data;
    uint32_t len;
} CJUInt64Array;

typedef struct {
    float* data;
    uint32_t len;
} CJFloatArray;

typedef struct {
    double* data;
    uint32_t len;
} CJDoubleArray;

typedef struct {
    uint8_t* data;
    uint32_t len;
} CJCharArray;

typedef struct {
    char** data;
    uint32_t len;
} CJStringArray;

typedef struct {
    int32_t* type;
    int64_t* id;
    uint32_t len;
} RemoteObjectArray;

char* MallocCString(const std::string& origin);

#define ZLOGF(LOG_LABEL, fmt, args...)                                                                            \
    HILOG_IMPL(LOG_CORE, LOG_FATAL, LOG_LABEL.domain, LOG_LABEL.tag, "%{public}s %{public}d: " fmt, __FUNCTION__, \
        __LINE__, ##args)
#define ZLOGE(LOG_LABEL, fmt, args...)                                                                            \
    HILOG_IMPL(LOG_CORE, LOG_ERROR, LOG_LABEL.domain, LOG_LABEL.tag, "%{public}s %{public}d: " fmt, __FUNCTION__, \
        __LINE__, ##args)
#define ZLOGW(LOG_LABEL, fmt, args...)                                                                           \
    HILOG_IMPL(LOG_CORE, LOG_WARN, LOG_LABEL.domain, LOG_LABEL.tag, "%{public}s %{public}d: " fmt, __FUNCTION__, \
        __LINE__, ##args)
#define ZLOGI(LOG_LABEL, fmt, args...)                                                                           \
    HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_LABEL.domain, LOG_LABEL.tag, "%{public}s %{public}d: " fmt, __FUNCTION__, \
        __LINE__, ##args)
#define ZLOGD(LOG_LABEL, fmt, args...)                                                                            \
    HILOG_IMPL(LOG_CORE, LOG_DEBUG, LOG_LABEL.domain, LOG_LABEL.tag, "%{public}s %{public}d: " fmt, __FUNCTION__, \
        __LINE__, ##args)
} // namespace OHOS
#endif
/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_TAIHE_ERROR_H
#define OHOS_TAIHE_ERROR_H

#include <map>
#include <string>

namespace OHOS {
enum RpcTaiheErrorCode {
    TAIHE_CHECK_PARAM_ERROR,
    TAIHE_OS_MMAP_ERROR,
    TAIHE_OS_IOCTL_ERROR,
    TAIHE_WRITE_TO_ASHMEM_ERROR,
    TAIHE_READ_FROM_ASHMEM_ERROR,
    TAIHE_ONLY_PROXY_OBJECT_PERMITTED_ERROR,
    TAIHE_ONLY_REMOTE_OBJECT_PERMITTED_ERROR,
    TAIHE_COMMUNICATION_ERROR,
    TAIHE_PROXY_OR_REMOTE_OBJECT_INVALID_ERROR,
    TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR,
    TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
    TAIHE_PARCEL_MEMORY_ALLOC_ERROR,
    TAIHE_CALL_JS_METHOD_ERROR,
    TAIHE_OS_DUP_ERROR
};

struct RpcTaiheErrorInfo {
    int errorCode;
    std::string errorMsg;
};

#define RPC_TAIHE_ERROR(error_code)                             \
    do {                                                        \
        taihe::set_business_error(                              \
            OHOS::RpcTaiheError::Convert(error_code),           \
            OHOS::RpcTaiheError::ToMessage(error_code));        \
        return;                                                 \
    } while (0)

#define RPC_TAIHE_ERROR_WITH_RETVAL(error_code, retVal)         \
    do {                                                        \
        taihe::set_business_error(                              \
            OHOS::RpcTaiheError::Convert(error_code),           \
            OHOS::RpcTaiheError::ToMessage(error_code));        \
        return retVal;                                          \
    } while (0)

const std::map<int, RpcTaiheErrorInfo> RPC_TAIHE_ERR_MAP {
    { TAIHE_CHECK_PARAM_ERROR, { 401, "check param error" } },
    { TAIHE_OS_MMAP_ERROR, { 1900001, "os mmap function failed" } },
    { TAIHE_OS_IOCTL_ERROR, { 1900002, "os ioctl function failed" } },
    { TAIHE_WRITE_TO_ASHMEM_ERROR, { 1900003, "write to ashmem failed" } },
    { TAIHE_READ_FROM_ASHMEM_ERROR, { 1900004, "read from ashmem failed" } },
    { TAIHE_ONLY_PROXY_OBJECT_PERMITTED_ERROR, { 1900005, "only proxy object permitted" } },
    { TAIHE_ONLY_REMOTE_OBJECT_PERMITTED_ERROR, { 1900006, "only remote object permitted" } },
    { TAIHE_COMMUNICATION_ERROR, { 1900007, "communication failed" } },
    { TAIHE_PROXY_OR_REMOTE_OBJECT_INVALID_ERROR, { 1900008, "proxy or remote object is invalid" } },
    { TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR, { 1900009, "write data to message sequence failed" } },
    { TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, { 1900010, "read data from message sequence failed" } },
    { TAIHE_PARCEL_MEMORY_ALLOC_ERROR, { 1900011, "parcel memory alloc failed" } },
    { TAIHE_CALL_JS_METHOD_ERROR, { 1900012, "call js method failed" } },
    { TAIHE_OS_DUP_ERROR, { 1900013, "os dup function failed" } }
};

class RpcTaiheError {
public:
    static int32_t Convert(const int errCode);
    static std::string ToMessage(const int errCode);
};
}

#endif // OHOS_TAIHE_ERROR_H
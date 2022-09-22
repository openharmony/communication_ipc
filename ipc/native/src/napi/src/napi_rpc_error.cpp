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

#include "napi_rpc_error.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "napi_rpc_error" };

std::map<int, errorInfo> NapiError::napiErrMap_ {
    {VERIFY_PARAM_FAILED, errorInfo{401, "verify param failed"}},
    {OS_MMAP_ERROR, errorInfo{1900001, "os mmap function failed"}},
    {OS_IOCTL_ERROR, errorInfo{1900002, "os ioctl function failed"}},
    {WRITE_TO_ASHMEM_ERROR, errorInfo{1900003, "write to ashmem failed"}},
    {READ_FROM_ASHMEM_ERROR, errorInfo{1900004, "read from ashmem failed"}},
    {JUST_PROXY_OBJECT_PERMITTED_ERROR, errorInfo{1900005, "just proxy object permitted"}},
    {JUST_REMOTE_OBJECT_PERMITTED_ERROR, errorInfo{1900006, "os mmap function failed"}},
    {COMMUNICATION_ERROR, errorInfo{1900007, "communication failed"}},
    {PROXY_OR_REMOTE_OBJECT_INVALID_ERROR, errorInfo{1900008, "proxy or remote object is invalid"}},
    {WRITE_DATA_TO_MESSAGE_PARCEL_ERROR, errorInfo{1900009, "write data to message parcel failed"}},
    {READ_DATA_FROM_MESSAGE_PARCEL_ERROR, errorInfo{1900010, "read data from message parcel failed"}},
    {PARCEL_MEMORY_ALLOC_ERROR, errorInfo{1900011, "parcel memory alloc failed"}},
    {CALL_JS_METHOD_ERROR, errorInfo{1900012, "call js method failed"}},
    {OS_DUP_ERROR, errorInfo{1900013, "os dup function failed"}}
};

napi_value NapiError::GetError(napi_env& env) const
{
    napi_value napiError = nullptr;
    if (!IsError()) {
        napi_get_undefined(env, &napiError);
        return napiError;
    }
    
    napi_value napiCode = nullptr;
    std::string msg = napiErrMap_[errorCode_].errorMsg;
    int code = napiErrMap_[errorCode_].errorCode;
    std::string codeStr = std::to_string(code);

    NAPI_CALL(env, napi_create_string_utf8(env, codeStr.c_str(), codeStr.size(), &napiCode));
    napi_value napiMsg = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), msg.size(), &napiMsg));
    NAPI_CALL(env, napi_create_error(env, napiCode, napiMsg, &napiError));

    ZLOGD(LOG_LABEL, "throw error code: %{public}d, msg: %{public}s,", code, msg.c_str());
    return napiError;
}

napi_value NapiError::ThrowError(napi_env& env, int32_t code)
{
    Error(code);
    napi_value error = GetError(env);
    napi_throw(env, error);
    return nullptr;
}
} // OHOS
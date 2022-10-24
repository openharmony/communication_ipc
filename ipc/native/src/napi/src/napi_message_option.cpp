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

#include "napi_message_option.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
/*
 * Get flags field from ohos.rpc.MessageOption.
 */
napi_value NapiOhosRpcMessageOptionGetFlags(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, (void **)&option);
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    int flags = option->GetFlags();
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, flags, &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create int32 value");
    return result;
}

/*
 * Set flags to ohos.rpc.MessageOption
 */
napi_value NapiOhosRpcMessageOptionSetFlags(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    int32_t flags = 0;
    napi_status status = napi_get_value_int32(env, argv[0], &flags);
    NAPI_ASSERT(env, status == napi_ok, "failed to get int32 value");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, (void **)&option);
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    option->SetFlags(flags);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

/*
 * Get async to ohos.rpc.MessageOption
 */
napi_value NapiOhosRpcMessageOptionIsAsync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, (void **)&option);
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    int flags = option->GetFlags();
    napi_value result = nullptr;
    napi_status status = napi_get_boolean(env, flags != 0 ? true : false, &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create boolean value");
    return result;
}

/*
 * Set async to ohos.rpc.MessageOption
 */
napi_value NapiOhosRpcMessageOptionSetAsync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_boolean, "type mismatch for parameter 1");
    bool flags = false;
    napi_status status = napi_get_value_bool(env, argv[0], &flags);
    NAPI_ASSERT(env, status == napi_ok, "failed to get boolean value");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, (void **)&option);
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    option->SetFlags(static_cast<int32_t> (flags));
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

/*
 * Get wait time field from ohos.rpc.MessageOption.
 */
napi_value NapiOhosRpcMessageOptionGetWaittime(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, (void **)&option);
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    int flags = option->GetWaitTime();
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, flags, &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create int32 value");
    return result;
}

/*
 * Set wait time to ohos.rpc.MessageOption
 */
napi_value NapiOhosRpcMessageOptionSetWaittime(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    int32_t waittime = 0;
    napi_status status = napi_get_value_int32(env, argv[0], &waittime);
    NAPI_ASSERT(env, status == napi_ok, "failed to get int32 value");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, (void **)&option);
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    option->SetWaitTime(waittime);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}
} // namespace OHOS
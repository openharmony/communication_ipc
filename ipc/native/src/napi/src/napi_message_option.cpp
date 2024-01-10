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

#include "ipc_debug.h"
#include "log_tags.h"
#include "message_option.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "native_engine/native_value.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "NapiMessageOption" };

static const size_t ARGV_INDEX_0 = 0;
static const size_t ARGV_INDEX_1 = 1;

static const size_t ARGV_LENGTH_1 = 1;
static const size_t ARGV_LENGTH_2 = 2;
/*
 * Get flags field from ohos.rpc.MessageOption.
 */
static napi_value NapiOhosRpcMessageOptionGetFlags(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&option));
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
static napi_value NapiOhosRpcMessageOptionSetFlags(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    int32_t flags = 0;
    napi_status status = napi_get_value_int32(env, argv[ARGV_INDEX_0], &flags);
    NAPI_ASSERT(env, status == napi_ok, "failed to get int32 value");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&option));
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    option->SetFlags(flags);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

/*
 * Get async to ohos.rpc.MessageOption
 */
static napi_value NapiOhosRpcMessageOptionIsAsync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&option));
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
static napi_value NapiOhosRpcMessageOptionSetAsync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_boolean, "type mismatch for parameter 1");
    bool flags = false;
    napi_status status = napi_get_value_bool(env, argv[ARGV_INDEX_0], &flags);
    NAPI_ASSERT(env, status == napi_ok, "failed to get boolean value");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&option));
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    option->SetFlags(static_cast<int32_t>(flags));
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

/*
 * Get wait time field from ohos.rpc.MessageOption.
 */
static napi_value NapiOhosRpcMessageOptionGetWaittime(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&option));
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
static napi_value NapiOhosRpcMessageOptionSetWaittime(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js message option object");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    int32_t waitTime = 0;
    napi_status status = napi_get_value_int32(env, argv[ARGV_INDEX_0], &waitTime);
    NAPI_ASSERT(env, status == napi_ok, "failed to get int32 value");
    MessageOption *option = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&option));
    NAPI_ASSERT(env, option != nullptr, "failed to get native message option");
    option->SetWaitTime(waitTime);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value NAPIMessageOption_JS_Constructor(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    int flags = 0;
    int waitTime = 0;
    if (argc == 0) {
        flags = MessageOption::TF_SYNC;
        waitTime = MessageOption::TF_WAIT_TIME;
    } else if (argc == 1) {
        napi_valuetype valueType;
        napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
        NAPI_ASSERT(env, valueType == napi_number || valueType == napi_boolean, "type mismatch for parameter 1");
        if (valueType == napi_boolean) {
            bool jsBoolFlags = false;
            napi_get_value_bool(env, argv[ARGV_INDEX_0], &jsBoolFlags);
            flags = jsBoolFlags ? MessageOption::TF_ASYNC : MessageOption::TF_SYNC;
        } else {
            int32_t jsFlags = 0;
            napi_get_value_int32(env, argv[ARGV_INDEX_0], &jsFlags);
            flags = jsFlags == 0 ? MessageOption::TF_SYNC : MessageOption::TF_ASYNC;
        }
        waitTime = MessageOption::TF_WAIT_TIME;
    } else {
        napi_valuetype valueType = napi_null;
        napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
        napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
        int32_t jsFlags = 0;
        napi_get_value_int32(env, argv[ARGV_INDEX_0], &jsFlags);
        int32_t jsWaitTime = 0;
        napi_get_value_int32(env, argv[ARGV_INDEX_1], &jsWaitTime);
        flags = jsFlags == 0 ? MessageOption::TF_SYNC : MessageOption::TF_ASYNC;
        waitTime = jsWaitTime;
    }

    auto messageOption = new MessageOption(flags, waitTime);
    // connect native message option to js thisVar
    napi_status status = napi_wrap(
        env, thisVar, messageOption,
        [](napi_env env, void *data, void *hint) {
            ZLOGD(LOG_LABEL, "NAPIMessageOption destructed by js callback");
            delete (reinterpret_cast<MessageOption *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js MessageOption and native option failed");
    return thisVar;
}

EXTERN_C_START
/*
 * function for module exports
 */
napi_value NAPIMessageOptionExport(napi_env env, napi_value exports)
{
    const std::string className = "MessageOption";
    napi_value tfSync = nullptr;
    napi_create_int32(env, MessageOption::TF_SYNC, &tfSync);
    napi_value tfAsync = nullptr;
    napi_create_int32(env, MessageOption::TF_ASYNC, &tfAsync);
    napi_value tfFds = nullptr;
    napi_create_int32(env, MessageOption::TF_ACCEPT_FDS, &tfFds);
    napi_value tfWaitTime = nullptr;
    napi_create_int32(env, MessageOption::TF_WAIT_TIME, &tfWaitTime);
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getFlags", NapiOhosRpcMessageOptionGetFlags),
        DECLARE_NAPI_FUNCTION("setFlags", NapiOhosRpcMessageOptionSetFlags),
        DECLARE_NAPI_FUNCTION("isAsync", NapiOhosRpcMessageOptionIsAsync),
        DECLARE_NAPI_FUNCTION("setAsync", NapiOhosRpcMessageOptionSetAsync),
        DECLARE_NAPI_FUNCTION("getWaitTime", NapiOhosRpcMessageOptionGetWaittime),
        DECLARE_NAPI_FUNCTION("setWaitTime", NapiOhosRpcMessageOptionSetWaittime),
        DECLARE_NAPI_STATIC_PROPERTY("TF_SYNC", tfSync),
        DECLARE_NAPI_STATIC_PROPERTY("TF_ASYNC", tfAsync),
        DECLARE_NAPI_STATIC_PROPERTY("TF_ACCEPT_FDS", tfFds),
        DECLARE_NAPI_STATIC_PROPERTY("TF_WAIT_TIME", tfWaitTime),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), NAPIMessageOption_JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class MessageOption failed");
    napi_status status = napi_set_named_property(env, exports, "MessageOption", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property MessageOption to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "IPCOptionConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set message option constructor failed");
    return exports;
}
EXTERN_C_END
} // namespace OHOS
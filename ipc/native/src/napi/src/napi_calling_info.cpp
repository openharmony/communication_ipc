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

#include "ipc_debug.h"
#include "log_tags.h"
#include "napi_remote_object.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "native_engine/native_value.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "NapiCallingInfo" };

enum ArgIndex : size_t {
    ARGV_INDEX_0 = 0,
    ARGV_INDEX_1 = 1,
    ARGV_INDEX_2 = 2,
    ARGV_INDEX_3 = 3,
    ARGV_INDEX_4 = 4,
    ARGV_INDEX_5 = 5,
};

enum ArgcLength : size_t {
    ARGC_LENGTH_6 = 6
};

static const size_t DEVICEID_LENGTH = 64;

static CallingInfo* GetCallingInfo(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_ASSERT(env, thisVar != nullptr, "failed to get js CallingInfo object");
    CallingInfo *callingInfo = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&callingInfo));
    NAPI_ASSERT(env, callingInfo != nullptr, "failed to get native CallingInfo object");
    return callingInfo;
}

static napi_value NapiGetCallingPid(napi_env env, napi_callback_info info)
{
    CallingInfo *callingInfo = GetCallingInfo(env, info);
    NAPI_ASSERT(env, callingInfo != nullptr, "failed to get native CallingInfo object");
    pid_t callingPid = callingInfo->callingPid;
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, callingPid, &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create int32 value");
    return result;
}

static napi_value NapiGetCallingUid(napi_env env, napi_callback_info info)
{
    CallingInfo *callingInfo = GetCallingInfo(env, info);
    NAPI_ASSERT(env, callingInfo != nullptr, "failed to get native CallingInfo object");
    pid_t callingUid = callingInfo->callingUid;
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, callingUid, &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create int32 value");
    return result;
}

static napi_value NapiGetCallingTokenId(napi_env env, napi_callback_info info)
{
    CallingInfo *callingInfo = GetCallingInfo(env, info);
    NAPI_ASSERT(env, callingInfo != nullptr, "failed to get native CallingInfo object");
    uint32_t callingTokenId = callingInfo->callingTokenId;
    napi_value result = nullptr;
    napi_status status = napi_create_uint32(env, callingTokenId, &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create uint32 value");
    return result;
}

static napi_value NapiGetCallingDeviceId(napi_env env, napi_callback_info info)
{
    CallingInfo *callingInfo = GetCallingInfo(env, info);
    NAPI_ASSERT(env, callingInfo != nullptr, "failed to get native CallingInfo object");
    std::string callingDeviceId = callingInfo->callingDeviceID;
    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, callingDeviceId.c_str(), callingDeviceId.length(), &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create string value");
    return result;
}

static napi_value NapiGetLocalDeviceId(napi_env env, napi_callback_info info)
{
    CallingInfo *callingInfo = GetCallingInfo(env, info);
    NAPI_ASSERT(env, callingInfo != nullptr, "failed to get native CallingInfo object");
    std::string localDeviceId = callingInfo->localDeviceID;
    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, localDeviceId.c_str(), localDeviceId.length(), &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create string value");
    return result;
}

static napi_value NapiGetIsLocalCalling(napi_env env, napi_callback_info info)
{
    CallingInfo *callingInfo = GetCallingInfo(env, info);
    NAPI_ASSERT(env, callingInfo != nullptr, "failed to get native CallingInfo object");
    bool isLocalCalling = callingInfo->isLocalCalling;
    napi_value result = nullptr;
    napi_status status = napi_get_boolean(env, isLocalCalling, &result);
    NAPI_ASSERT(env, status == napi_ok, "failed to create bool value");
    return result;
}

static bool IsParametersTypeValid(napi_env env, napi_value argv[], size_t argc)
{
    if (argc != ArgcLength::ARGC_LENGTH_6) {
        ZLOGE(LOG_LABEL, "arguments count mismatch, argc %{public}zu", argc);
        return false;
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ArgIndex::ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return false;
    }
    napi_typeof(env, argv[ArgIndex::ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return false;
    }
    napi_typeof(env, argv[ArgIndex::ARGV_INDEX_2], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 3");
        return false;
    }
    napi_typeof(env, argv[ArgIndex::ARGV_INDEX_3], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 4");
        return false;
    }
    napi_typeof(env, argv[ArgIndex::ARGV_INDEX_4], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 5");
        return false;
    }
    napi_typeof(env, argv[ArgIndex::ARGV_INDEX_5], &valueType);
    if (valueType != napi_boolean) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 6");
        return false;
    }
    return true;
}

static napi_value NAPICallingInfo_JS_Constructor(napi_env env, napi_callback_info info)
{
    size_t argc = ArgcLength::ARGC_LENGTH_6;
    napi_value argv[ArgcLength::ARGC_LENGTH_6] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == ArgcLength::ARGC_LENGTH_6, "invalid parameter count");
    NAPI_ASSERT(env, IsParametersTypeValid(env, argv, argc), "type mismatch for parameter");
    int32_t callingPid = 0;
    napi_status status = napi_get_value_int32(env, argv[ArgIndex::ARGV_INDEX_0], &callingPid);
    NAPI_ASSERT(env, status == napi_ok, "failed to get int32 value");
    int32_t callingUid = 0;
    status = napi_get_value_int32(env, argv[ArgIndex::ARGV_INDEX_1], &callingUid);
    NAPI_ASSERT(env, status == napi_ok, "failed to get int32 value");
    uint32_t callingTokenId = 0;
    status = napi_get_value_uint32(env, argv[ArgIndex::ARGV_INDEX_2], &callingTokenId);
    NAPI_ASSERT(env, status == napi_ok, "failed to get uint32 value");
    char deviceId[65] = { 0 };
    size_t deviceIdLength = 0;
    status = napi_get_value_string_utf8(env, argv[ArgIndex::ARGV_INDEX_3], deviceId, sizeof(deviceId), &deviceIdLength);
    NAPI_ASSERT(env, status == napi_ok, "failed to get string value");
    NAPI_ASSERT(env, deviceIdLength == 0 || deviceIdLength == DEVICEID_LENGTH, "Illegal deviceIdLength");
    char localDeviceId[65] = { 0 };
    size_t localDeviceIdLength = 0;
    status = napi_get_value_string_utf8(env, argv[ArgIndex::ARGV_INDEX_4], localDeviceId,
        sizeof(localDeviceId), &localDeviceIdLength);
    NAPI_ASSERT(env, status == napi_ok, "failed to get string value");
    NAPI_ASSERT(env, localDeviceIdLength == 0 || localDeviceIdLength == DEVICEID_LENGTH, "Illegal localDeviceIdLength");
    bool isLocalCalling = true;
    status = napi_get_value_bool(env, argv[ArgIndex::ARGV_INDEX_5], &isLocalCalling);
    NAPI_ASSERT(env, status == napi_ok, "failed to get bool value");
    auto callingInfo =
        new (std::nothrow) CallingInfo{callingPid, callingUid, callingTokenId, deviceId, localDeviceId, isLocalCalling};
    NAPI_ASSERT(env, callingInfo != nullptr, "new CallingInfo failed");
    status = napi_wrap(env, thisVar, callingInfo, [](napi_env env, void *data, void *hint) {
            delete (reinterpret_cast<CallingInfo *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        delete callingInfo;
        NAPI_ASSERT(env, false, "wrap js callingInfo and native object failed");
    }
    return thisVar;
}

EXTERN_C_START
/**
 * function for module exports
 */
napi_value NAPICallingInfoExport(napi_env env, napi_value exports)
{
    const std::string className = "CallingInfo";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_GETTER("callerPid", NapiGetCallingPid),
        DECLARE_NAPI_GETTER("callerUid", NapiGetCallingUid),
        DECLARE_NAPI_GETTER("callerTokenId", NapiGetCallingTokenId),
        DECLARE_NAPI_GETTER("remoteDeviceId", NapiGetCallingDeviceId),
        DECLARE_NAPI_GETTER("localDeviceId", NapiGetLocalDeviceId),
        DECLARE_NAPI_GETTER("isLocalCalling", NapiGetIsLocalCalling)
    };

    size_t count = sizeof(properties) / sizeof(properties[0]);
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), NAPICallingInfo_JS_Constructor,
        nullptr, count, properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class CallingInfo failed");

    napi_status status = napi_set_named_property(env, exports, "CallingInfo", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property CallingInfo to exports failed");

    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");

    status = napi_set_named_property(env, global, "IPCCallingInfoConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set CallingInfo constructor failed");
    return exports;
}
EXTERN_C_END

} // namespace OHOS
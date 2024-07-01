/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <cinttypes>

#include "hilog/log.h"
#include "ipc_skeleton.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "iremote_invoker.h"
#include "napi_rpc_error.h"
#include "napi_process_skeleton.h"
#include "napi_remote_object.h"
#include "native_engine/native_value.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "NapiIpcSkeleton" };

static NapiError napiErr;

static const size_t ARGV_INDEX_0 = 0;

static const size_t ARGV_LENGTH_1 = 1;
static constexpr size_t UINT64_STRING_MAX_LEN = 20;

napi_value NAPI_IPCSkeleton_getContextObject(napi_env env, napi_callback_info info)
{
    sptr<IRemoteObject> object = IPCSkeleton::GetContextObject();
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "fatal error, could not get registry object");
        return nullptr;
    }
    return NAPI_ohos_rpc_CreateJsRemoteObject(env, object);
}

napi_value NAPI_IPCSkeleton_getCallingPid(napi_env env, napi_callback_info info)
{
    return NAPI_getCallingPid(env, info);
}

napi_value NAPI_IPCSkeleton_getCallingUid(napi_env env, napi_callback_info info)
{
    return NAPI_getCallingUid(env, info);
}

napi_value NAPI_IPCSkeleton_getCallingTokenId(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    if (napiActiveStatus != nullptr) {
        int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
        napi_get_value_int32(env, napiActiveStatus, &activeStatus);
        if (activeStatus == IRemoteInvoker::ACTIVE_INVOKER) {
            napi_value callingTokenId = nullptr;
            napi_get_named_property(env, global, "callingTokenId_", &callingTokenId);
            return callingTokenId;
        }
    }
    uint64_t tokenId = IPCSkeleton::GetSelfTokenID();
    napi_value result = nullptr;
    napi_create_uint32(env, static_cast<uint32_t>(tokenId), &result);
    return result;
}

napi_value NAPI_IPCSkeleton_getCallingDeviceID(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    if (napiActiveStatus != nullptr) {
        int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
        napi_get_value_int32(env, napiActiveStatus, &activeStatus);
        if (activeStatus == IRemoteInvoker::ACTIVE_INVOKER) {
            napi_value callingDeviceID = nullptr;
            napi_get_named_property(env, global, "callingDeviceID_", &callingDeviceID);
            return callingDeviceID;
        }
    }
    napi_value result = nullptr;
    napi_create_string_utf8(env, "", 0, &result);
    return result;
}

napi_value NAPI_IPCSkeleton_getLocalDeviceID(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    if (napiActiveStatus != nullptr) {
        int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
        napi_get_value_int32(env, napiActiveStatus, &activeStatus);
        if (activeStatus == IRemoteInvoker::ACTIVE_INVOKER) {
            napi_value localDeviceID = nullptr;
            napi_get_named_property(env, global, "localDeviceID_", &localDeviceID);
            return localDeviceID;
        }
    }
    napi_value result = nullptr;
    napi_create_string_utf8(env, "", 0, &result);
    return result;
}

napi_value NAPI_IPCSkeleton_isLocalCalling(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    if (napiActiveStatus != nullptr) {
        int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
        napi_get_value_int32(env, napiActiveStatus, &activeStatus);
        if (activeStatus == IRemoteInvoker::ACTIVE_INVOKER) {
            napi_value isLocalCalling = nullptr;
            napi_get_named_property(env, global, "isLocalCalling_", &isLocalCalling);
            return isLocalCalling;
        }
    }
    napi_value result = nullptr;
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value NAPI_IPCSkeleton_flushCommands(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 1");

    sptr<IRemoteObject> target = NAPI_ohos_rpc_getNativeRemoteObject(env, argv[ARGV_INDEX_0]);
    int32_t result = IPCSkeleton::FlushCommands(target);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_IPCSkeleton_flushCmdBuffer(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    sptr<IRemoteObject> target = NAPI_ohos_rpc_getNativeRemoteObject(env, argv[ARGV_INDEX_0]);
    IPCSkeleton::FlushCommands(target);
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_IPCSkeleton_resetCallingIdentity(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
    napi_get_value_int32(env, napiActiveStatus, &activeStatus);
    if (activeStatus != IRemoteInvoker::ACTIVE_INVOKER) {
        napi_value result = nullptr;
        napi_create_string_utf8(env, "", 0, &result);
        return result;
    }
    napi_value napiCallingPid = nullptr;
    napi_get_named_property(env, global, "callingPid_", &napiCallingPid);
    int32_t callerPid;
    napi_get_value_int32(env, napiCallingPid, &callerPid);
    napi_value napiCallingUid = nullptr;
    napi_get_named_property(env, global, "callingUid_", &napiCallingUid);
    uint32_t callerUid;
    napi_get_value_uint32(env, napiCallingUid, &callerUid);
    napi_value napiIsLocalCalling = nullptr;
    napi_get_named_property(env, global, "isLocalCalling_", &napiIsLocalCalling);
    bool isLocalCalling = true;
    napi_get_value_bool(env, napiIsLocalCalling, &isLocalCalling);
    if (isLocalCalling) {
        int64_t identity = (static_cast<uint64_t>(callerUid) << PID_LEN) | static_cast<uint64_t>(callerPid);
        callerPid = getpid();
        callerUid = getuid();
        napi_value newCallingPid;
        napi_create_int32(env, callerPid, &newCallingPid);
        napi_set_named_property(env, global, "callingPid_", newCallingPid);
        napi_value newCallingUid;
        napi_create_uint32(env, callerUid, &newCallingUid);
        napi_set_named_property(env, global, "callingUid_", newCallingUid);
        napi_value result = nullptr;
        napi_create_string_utf8(env, std::to_string(identity).c_str(), NAPI_AUTO_LENGTH, &result);
        return result;
    } else {
        napi_value napiCallingDeviceID = nullptr;
        napi_get_named_property(env, global, "callingDeviceID_", &napiCallingDeviceID);
        size_t bufferSize = 0;
        size_t maxLen = 4096;
        napi_get_value_string_utf8(env, napiCallingDeviceID, nullptr, 0, &bufferSize);
        NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");
        char stringValue[bufferSize + 1];
        size_t jsStringLength = 0;
        napi_get_value_string_utf8(env, napiCallingDeviceID, stringValue, bufferSize + 1, &jsStringLength);
        NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");
        std::string callerDeviceID = stringValue;
        std::string token = std::to_string(((static_cast<uint64_t>(callerUid) << PID_LEN)
            | static_cast<uint64_t>(callerPid)));
        std::string identity = callerDeviceID + token;
        callerUid = getuid();
        napi_value newCallingUid;
        napi_create_uint32(env, callerUid, &newCallingUid);
        napi_set_named_property(env, global, "callingUid_", newCallingUid);
        callerPid = getpid();
        napi_value newCallingPid;
        napi_create_int32(env, callerPid, &newCallingPid);
        napi_set_named_property(env, global, "callingPid_", newCallingPid);
        napi_value newCallingDeviceID = nullptr;
        napi_get_named_property(env, global, "localDeviceID_", &newCallingDeviceID);
        napi_set_named_property(env, global, "callingDeviceID_", newCallingDeviceID);

        napi_value result = nullptr;
        napi_create_string_utf8(env, identity.c_str(), NAPI_AUTO_LENGTH, &result);
        return result;
    }
}

static bool IsValidIdentity(const std::string &identity)
{
    // 20 represents the maximum string length uint64_t can represent
    if (identity.empty() || identity.length() > UINT64_STRING_MAX_LEN) {
        return false;
    }

    auto predicate = [](char c) {
        return isdigit(c) == 0;
    };
    auto it = std::find_if(identity.begin(), identity.end(), predicate);
    return it == identity.end();
}

napi_value NAPI_IPCSkeleton_setCallingIdentity(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
    napi_get_value_int32(env, napiActiveStatus, &activeStatus);
    if (activeStatus != IRemoteInvoker::ACTIVE_INVOKER) {
        napi_value result = nullptr;
        napi_get_boolean(env, true, &result);
        return result;
    }

    napi_value retValue = nullptr;
    napi_get_boolean(env, false, &retValue);

    size_t argc = 1;
    size_t expectedArgc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT_BASE(env, argc == expectedArgc, "requires 1 parameters", retValue);
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT_BASE(env, valueType == napi_string, "type mismatch for parameter 1", retValue);
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    NAPI_ASSERT_BASE(env, bufferSize < maxLen, "string length too large", retValue);
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    NAPI_ASSERT_BASE(env, jsStringLength == bufferSize, "string length wrong", retValue);

    std::string identity = stringValue;
    napi_value napiIsLocalCalling = nullptr;
    napi_get_named_property(env, global, "isLocalCalling_", &napiIsLocalCalling);
    bool isLocalCalling = true;
    napi_get_value_bool(env, napiIsLocalCalling, &isLocalCalling);
    napi_value result;
    if (isLocalCalling) {
        if (!IsValidIdentity(identity)) {
            napi_get_boolean(env, false, &result);
            return result;
        }

        int64_t token = std::stoll(identity);
        int callerUid = static_cast<int>((static_cast<uint64_t>(token)) >> PID_LEN);
        int callerPid = static_cast<int>(token);
        napi_value napiCallingPid;
        napi_create_int32(env, callerPid, &napiCallingPid);
        napi_set_named_property(env, global, "callingPid_", napiCallingPid);
        napi_value napiCallingUid;
        napi_create_int32(env, callerUid, &napiCallingUid);
        napi_set_named_property(env, global, "callingUid_", napiCallingUid);
        napi_get_boolean(env, true, &result);
        return result;
    } else {
        if (identity.empty() || identity.length() <= DEVICEID_LENGTH) {
            napi_get_boolean(env, false, &result);
            return result;
        }

        std::string deviceId = identity.substr(0, DEVICEID_LENGTH);
        const std::string readIdentity = identity.substr(DEVICEID_LENGTH, identity.length() - DEVICEID_LENGTH);
        if (!IsValidIdentity(readIdentity)) {
            napi_get_boolean(env, false, &result);
            return result;
        }
        int64_t token = std::stoll(readIdentity);
        int callerUid = static_cast<int>((static_cast<uint64_t>(token)) >> PID_LEN);
        int callerPid = static_cast<int>(token);
        napi_value napiCallingPid;
        napi_create_int32(env, callerPid, &napiCallingPid);
        napi_set_named_property(env, global, "callingPid_", napiCallingPid);
        napi_value napiCallingUid;
        napi_create_int32(env, callerUid, &napiCallingUid);
        napi_set_named_property(env, global, "callingUid_", napiCallingUid);
        napi_value napiCallingDeviceID = nullptr;
        napi_create_string_utf8(env, deviceId.c_str(), NAPI_AUTO_LENGTH, &napiCallingDeviceID);
        napi_set_named_property(env, global, "callingDeviceID_", napiCallingDeviceID);
        napi_get_boolean(env, true, &result);
        return result;
    }
}

static napi_value NAPI_IPCSkeleton_restoreCallingIdentitySetProperty(napi_env env,
                                                                     napi_value &global,
                                                                     char* stringValue)
{
    std::string identity = stringValue;
    napi_value napiIsLocalCalling = nullptr;
    napi_get_named_property(env, global, "isLocalCalling_", &napiIsLocalCalling);
    bool isLocalCalling = true;
    napi_get_value_bool(env, napiIsLocalCalling, &isLocalCalling);
    napi_value result;
    napi_get_undefined(env, &result);
    if (isLocalCalling) {
        if (!IsValidIdentity(identity)) {
            ZLOGE(LOG_LABEL, "identity is empty");
            return result;
        }

        int64_t token = std::stoll(identity);
        int callerUid = static_cast<int>((static_cast<uint64_t>(token)) >> PID_LEN);
        int callerPid = static_cast<int>(token);
        napi_value napiCallingPid;
        napi_create_int32(env, callerPid, &napiCallingPid);
        napi_set_named_property(env, global, "callingPid_", napiCallingPid);
        napi_value napiCallingUid;
        napi_create_int32(env, callerUid, &napiCallingUid);
        napi_set_named_property(env, global, "callingUid_", napiCallingUid);
        return result;
    } else {
        if (identity.empty() || identity.length() <= DEVICEID_LENGTH) {
            ZLOGE(LOG_LABEL, "identity is empty or length is too short");
            return result;
        }

        std::string deviceId = identity.substr(0, DEVICEID_LENGTH);
        const std::string readIdentity = identity.substr(DEVICEID_LENGTH, identity.length() - DEVICEID_LENGTH);
        if (!IsValidIdentity(readIdentity)) {
            ZLOGE(LOG_LABEL, "readIdentity is invalid");
            return result;
        }
        int64_t token = std::stoll(readIdentity);
        int callerUid = static_cast<int>((static_cast<uint64_t>(token)) >> PID_LEN);
        int callerPid = static_cast<int>(token);
        napi_value napiCallingPid;
        napi_create_int32(env, callerPid, &napiCallingPid);
        napi_set_named_property(env, global, "callingPid_", napiCallingPid);
        napi_value napiCallingUid;
        napi_create_int32(env, callerUid, &napiCallingUid);
        napi_set_named_property(env, global, "callingUid_", napiCallingUid);
        napi_value napiCallingDeviceID = nullptr;
        napi_create_string_utf8(env, deviceId.c_str(), NAPI_AUTO_LENGTH, &napiCallingDeviceID);
        napi_set_named_property(env, global, "callingDeviceID_", napiCallingDeviceID);
        return result;
    }
}

napi_value NAPI_IPCSkeleton_restoreCallingIdentity(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
    napi_get_value_int32(env, napiActiveStatus, &activeStatus);
    if (activeStatus != IRemoteInvoker::ACTIVE_INVOKER) {
        ZLOGD(LOG_LABEL, "status is not active");
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        return result;
    }

    size_t argc = 1;
    size_t expectedArgc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    if (jsStringLength != bufferSize) {
        ZLOGE(LOG_LABEL, "string length wrong");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    return NAPI_IPCSkeleton_restoreCallingIdentitySetProperty(env, global, stringValue);
}

napi_value NAPIIPCSkeleton_JS_Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    napi_value global = nullptr;
    napi_get_global(env, &global);
    return thisArg;
}

EXTERN_C_START
/*
 * function for module exports
 */
napi_value NAPIIPCSkeletonExport(napi_env env, napi_value exports)
{
    uint64_t startTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    ZLOGI(LOG_LABEL, "napi_moudule IPCSkeleton Init start...time:%{public}" PRIu64, startTime);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getContextObject", NAPI_IPCSkeleton_getContextObject),
        DECLARE_NAPI_STATIC_FUNCTION("getCallingPid", NAPI_IPCSkeleton_getCallingPid),
        DECLARE_NAPI_STATIC_FUNCTION("getCallingUid", NAPI_IPCSkeleton_getCallingUid),
        DECLARE_NAPI_STATIC_FUNCTION("getCallingDeviceID", NAPI_IPCSkeleton_getCallingDeviceID),
        DECLARE_NAPI_STATIC_FUNCTION("getLocalDeviceID", NAPI_IPCSkeleton_getLocalDeviceID),
        DECLARE_NAPI_STATIC_FUNCTION("isLocalCalling", NAPI_IPCSkeleton_isLocalCalling),
        DECLARE_NAPI_STATIC_FUNCTION("flushCmdBuffer", NAPI_IPCSkeleton_flushCmdBuffer),
        DECLARE_NAPI_STATIC_FUNCTION("flushCommands", NAPI_IPCSkeleton_flushCommands),
        DECLARE_NAPI_STATIC_FUNCTION("resetCallingIdentity", NAPI_IPCSkeleton_resetCallingIdentity),
        DECLARE_NAPI_STATIC_FUNCTION("restoreCallingIdentity", NAPI_IPCSkeleton_restoreCallingIdentity),
        DECLARE_NAPI_STATIC_FUNCTION("setCallingIdentity", NAPI_IPCSkeleton_setCallingIdentity),
        DECLARE_NAPI_STATIC_FUNCTION("getCallingTokenId", NAPI_IPCSkeleton_getCallingTokenId),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    napi_value result = nullptr;
    napi_define_class(env, "IPCSkeleton", NAPI_AUTO_LENGTH, NAPIIPCSkeleton_JS_Constructor, nullptr,
        sizeof(desc) / sizeof(desc[0]), desc, &result);
    napi_status status = napi_set_named_property(env, exports, "IPCSkeleton", result);
    NAPI_ASSERT(env, status == napi_ok, "create ref to js RemoteObject constructor failed");
    uint64_t endTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    ZLOGI(LOG_LABEL, "napi_moudule IPCSkeleton Init end...time:%{public}" PRIu64, endTime);
    return exports;
}
EXTERN_C_END
}
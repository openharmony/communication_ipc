/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_remote_object_holder.h"
#include "napi_remote_object_internal.h"

#include <hitrace_meter.h>
#include <string_ex.h>
#include <uv.h>

#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "iremote_invoker.h"
#include "log_tags.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_message_parcel.h"
#include "napi_message_sequence.h"
#include "napi_remote_proxy_holder.h"
#include "napi_rpc_error.h"
#include "native_engine/native_value.h"
#include "napi_process_skeleton.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "napi_remoteObject" };

static const size_t ARGV_INDEX_0 = 0;
static const size_t ARGV_INDEX_1 = 1;
static const size_t ARGV_INDEX_2 = 2;
static const size_t ARGV_INDEX_3 = 3;
static const size_t ARGV_INDEX_4 = 4;
static const size_t ARGV_INDEX_6 = 6;

static const size_t ARGV_LENGTH_1 = 1;
static const size_t ARGV_LENGTH_2 = 2;
static const size_t ARGV_LENGTH_4 = 4;
static const size_t ARGV_LENGTH_5 = 5;

static const size_t ARGC_LENGTH_6 = 6;

static const size_t DEVICE_ID_LENGTH = 64;

static const uint64_t HITRACE_TAG_RPC = (1ULL << 46); // RPC and IPC tag.

static std::atomic<int32_t> bytraceId = 1000;
static NapiError napiErr;

static bool IsValidParamWithNotify(napi_value value, CallbackParam *param, const char *errDesc)
{
    if (value == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s", errDesc);
        param->result = IPC_INVALID_PARAM_ERR;
        std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
        param->lockInfo->ready = true;
        param->lockInfo->condition.notify_all();
        return false;
    }
    return true;
}

enum class OnRemoteRequestType {
    ON_REMOTE_REQUEST,
    ON_REMOTE_MESSAGE_REQUEST,
    ON_REMOTE_MESSAGE_REQUEST_WITH_CALLING_INFO,
};

static bool GetJsOnRemoteRequestCallback(CallbackParam *param, const napi_value thisVar, napi_value &onRemoteRequest,
    OnRemoteRequestType &requestType)
{
    napi_get_named_property(param->env, thisVar, "onRemoteMessageRequest", &onRemoteRequest);
    if (IsValidParamWithNotify(onRemoteRequest, param, "get function onRemoteMessageRequest failed")) {
        napi_valuetype type = napi_undefined;
        napi_typeof(param->env, onRemoteRequest, &type);
        if (type == napi_function) {
            uint32_t funcParamCount = ARGV_LENGTH_4;
            napi_value jsFuncParamCount = nullptr;
            napi_get_named_property(param->env, onRemoteRequest, "length", &jsFuncParamCount);
            napi_get_value_uint32(param->env, jsFuncParamCount, &funcParamCount);
            requestType = (funcParamCount == ARGV_LENGTH_4)
                ? OnRemoteRequestType::ON_REMOTE_MESSAGE_REQUEST
                : OnRemoteRequestType::ON_REMOTE_MESSAGE_REQUEST_WITH_CALLING_INFO;
            return true;
        }
        ZLOGD(LOG_LABEL, "onRemoteMessageRequest is not function");
    }

    napi_get_named_property(param->env, thisVar, "onRemoteRequest", &onRemoteRequest);
    if (IsValidParamWithNotify(onRemoteRequest, param, "get function onRemoteRequest failed")) {
        napi_valuetype type = napi_undefined;
        napi_typeof(param->env, onRemoteRequest, &type);
        if (type == napi_function) {
            requestType = OnRemoteRequestType::ON_REMOTE_REQUEST;
            return true;
        }
        ZLOGE(LOG_LABEL, "onRemoteRequest is not function");
    }
    ZLOGE(LOG_LABEL, "failed to get OnRemoteRequest function");
    param->result = IPC_INVALID_PARAM_ERR;
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->ready = true;
    param->lockInfo->condition.notify_all();
    return false;
}

static bool CreateJsOption(CallbackParam *param, const napi_value global, napi_value &jsOption)
{
    napi_value jsOptionConstructor = nullptr;
    napi_get_named_property(param->env, global, "IPCOptionConstructor_", &jsOptionConstructor);
    if (!IsValidParamWithNotify(jsOptionConstructor, param, "jsOption constructor is null")) {
        return false;
    }

    size_t argc = ARGV_LENGTH_2;
    napi_value flags = nullptr;
    napi_create_int32(param->env, param->option->GetFlags(), &flags);
    napi_value waittime = nullptr;
    napi_create_int32(param->env, param->option->GetWaitTime(), &waittime);
    napi_value argv[ARGV_LENGTH_2] = { flags, waittime };
    napi_new_instance(param->env, jsOptionConstructor, argc, argv, &jsOption);
    if (!IsValidParamWithNotify(jsOption, param, "new jsOption failed")) {
        return false;
    }
    return true;
}

static bool GetJsParcelConstructor(CallbackParam *param, const napi_value global, OnRemoteRequestType requestType,
    napi_value &jsParcelConstructor)
{
    if (requestType != OnRemoteRequestType::ON_REMOTE_REQUEST) {
        napi_get_named_property(param->env, global, "IPCSequenceConstructor_", &jsParcelConstructor);
    } else {
        napi_get_named_property(param->env, global, "IPCParcelConstructor_", &jsParcelConstructor);
    }
    if (!IsValidParamWithNotify(jsParcelConstructor, param, "jsParcel constructor is null")) {
        return false;
    }
    return true;
}

static bool CreateJsParcel(CallbackParam *param, const napi_value jsParcelConstructor, napi_value &jsParcel,
    bool isJsDataParcel)
{
    napi_value parcel;
    napi_create_object(param->env, &parcel);
    napi_wrap(param->env, parcel, isJsDataParcel ? param->data : param->reply,
        [](napi_env env, void *data, void *hint) {}, nullptr, nullptr);

    if (!IsValidParamWithNotify(parcel, param, "create js parcel object failed")) {
        return false;
    }

    size_t argc = 1;
    napi_value argv[1] = { parcel };
    napi_new_instance(param->env, jsParcelConstructor, argc, argv, &jsParcel);
    if (!IsValidParamWithNotify(parcel, param,
        isJsDataParcel ? "create js data parcel failed" : "create js reply parcel failed")) {
        return false;
    }
    return true;
}

static bool CreateInt32NapiValue(CallbackParam *param, napi_value &value, int32_t num)
{
    napi_status status = napi_create_int32(param->env, num, &value);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to create int32 napi value");
        return false;
    }
    return true;
}

static bool CreateUint32NapiValue(CallbackParam *param, napi_value &value, uint32_t num)
{
    napi_status status = napi_create_uint32(param->env, num, &value);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to create uint32 napi value");
        return false;
    }
    return true;
}

static bool CreateStringNapiValue(CallbackParam *param, napi_value &value, const std::string &str)
{
    napi_status status = napi_create_string_utf8(param->env, str.c_str(), str.length(), &value);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to create str napi value");
        return false;
    }
    return true;
}

static bool CreateBoolNapiValue(CallbackParam *param, napi_value &value, bool boolVal)
{
    napi_status status = napi_get_boolean(param->env, boolVal, &value);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to create bool napi value");
        return false;
    }
    return true;
}

static bool CreateJsCallingInfo(CallbackParam *param, const napi_value global, napi_value &jsCallingInfo)
{
    napi_value jsCallingInfoConstructor = nullptr;
    napi_get_named_property(param->env, global, "IPCCallingInfoConstructor_", &jsCallingInfoConstructor);
    if (!IsValidParamWithNotify(jsCallingInfoConstructor, param, "jsCallingInfo constructor is null")) {
        return false;
    }
    size_t argc = ARGC_LENGTH_6;

    napi_value callingPid = nullptr;
    napi_value callingUid = nullptr;
    napi_value callingTokenId = nullptr;
    napi_value callingDeviceId = nullptr;
    napi_value localDeviceId = nullptr;
    napi_value isLocalCalling = nullptr;
    if (!CreateInt32NapiValue(param, callingPid, param->callingInfo.callingPid)
        || !CreateInt32NapiValue(param, callingUid, param->callingInfo.callingUid)
        || !CreateUint32NapiValue(param, callingTokenId, param->callingInfo.callingTokenId)
        || !CreateStringNapiValue(param, callingDeviceId, param->callingInfo.callingDeviceID)
        || !CreateStringNapiValue(param, localDeviceId, param->callingInfo.localDeviceID)
        || !CreateBoolNapiValue(param, isLocalCalling, param->callingInfo.isLocalCalling)) {
        param->result = IPC_INVALID_PARAM_ERR;
        std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
        param->lockInfo->ready = true;
        param->lockInfo->condition.notify_all();
        return false;
    }

    napi_value argv[ARGV_INDEX_6] = { callingPid, callingUid, callingTokenId,
        callingDeviceId, localDeviceId, isLocalCalling };
    napi_new_instance(param->env, jsCallingInfoConstructor, argc, argv, &jsCallingInfo);
    if (!IsValidParamWithNotify(jsCallingInfo, param, "new jsCallingInfo failed")) {
        return false;
    }
    return true;
}

static bool IsPromiseResult(CallbackParam *param, const napi_value returnVal)
{
    bool isPromise = false;
    napi_is_promise(param->env, returnVal, &isPromise);
    if (!isPromise) {
        ZLOGD(LOG_LABEL, "onRemoteRequest is synchronous");
        bool result = false;
        napi_get_value_bool(param->env, returnVal, &result);
        if (!result) {
            uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            ZLOGE(LOG_LABEL, "OnRemoteRequest result:false, time:%{public}" PRIu64, curTime);
            param->result = ERR_UNKNOWN_TRANSACTION;
        } else {
            param->result = ERR_NONE;
        }
        return false;
    }
    return true;
}

static bool GetPromiseThen(CallbackParam *param, const napi_value returnVal, napi_value &promiseThen)
{
    napi_get_named_property(param->env, returnVal, "then", &promiseThen);
    if (promiseThen == nullptr) {
        ZLOGE(LOG_LABEL, "get promiseThen failed");
        param->result = IPC_INVALID_PARAM_ERR;
        return false;
    }
    return true;
}

static void NAPI_RemoteObject_saveOldCallingInfoInner(napi_env env, CallingInfo &oldCallingInfo)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value value = nullptr;
    napi_get_named_property(env, global, "callingPid_", &value);
    napi_get_value_int32(env, value, &oldCallingInfo.callingPid);
    napi_get_named_property(env, global, "callingUid_", &value);
    napi_get_value_int32(env, value, &oldCallingInfo.callingUid);
    napi_get_named_property(env, global, "callingTokenId_", &value);
    napi_get_value_uint32(env, value, &oldCallingInfo.callingTokenId);
    napi_get_named_property(env, global, "callingDeviceID_", &value);
    char deviceID[DEVICE_ID_LENGTH + 1] = { 0 };
    size_t deviceLength = 0;
    napi_get_value_string_utf8(env, global, deviceID, DEVICE_ID_LENGTH + 1, &deviceLength);
    oldCallingInfo.callingDeviceID = deviceID;
    char localDeviceID[DEVICE_ID_LENGTH + 1] = { 0 };
    napi_get_named_property(env, global, "localDeviceID_", &value);
    napi_get_value_string_utf8(env, global, localDeviceID, DEVICE_ID_LENGTH + 1, &deviceLength);
    oldCallingInfo.localDeviceID = localDeviceID;
    napi_get_named_property(env, global, "isLocalCalling_", &value);
    napi_get_value_bool(env, value, &oldCallingInfo.isLocalCalling);
    napi_get_named_property(env, global, "activeStatus_", &value);
    napi_get_value_int32(env, value, &oldCallingInfo.activeStatus);
}

static void NAPI_RemoteObject_resetOldCallingInfoInner(napi_env env, CallingInfo &oldCallingInfo)
{
    NAPI_RemoteObject_setNewCallingInfo(env, oldCallingInfo);
}
static napi_value ThenCallback(napi_env env, napi_callback_info info)
{
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    ZLOGD(LOG_LABEL, "call js onRemoteRequest done, time:%{public}" PRIu64, curTime);
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {nullptr};
    void* data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, nullptr, &data);
    napi_value res;
    CallbackParam *param = static_cast<CallbackParam *>(data);
    if (param == nullptr) {
        ZLOGE(LOG_LABEL, "param is null");
        napi_get_undefined(env, &res);
        return res;
    }
    bool result = false;
    napi_get_value_bool(param->env, argv[ARGV_INDEX_0], &result);
    if (!result) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LOG_LABEL, "OnRemoteRequest result:false time:%{public}" PRIu64, curTime);
        param->result = ERR_UNKNOWN_TRANSACTION;
    } else {
        param->result = ERR_NONE;
    }

    // Reset old calling pid, uid, device id
    NAPI_RemoteObject_resetOldCallingInfoInner(param->env, param->oldCallingInfo);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->ready = true;
    param->lockInfo->condition.notify_all();
    napi_get_undefined(env, &res);
    return res;
}

static bool CreateThenCallback(CallbackParam *param, napi_value &thenValue)
{
    napi_status ret = napi_create_function(param->env, "thenCallback",
        NAPI_AUTO_LENGTH, ThenCallback, param, &thenValue);
    if (ret != napi_ok) {
        ZLOGE(LOG_LABEL, "thenCallback got exception");
        param->result = ERR_UNKNOWN_TRANSACTION;
        return false;
    }
    return true;
}

static napi_value CatchCallback(napi_env env, napi_callback_info info)
{
    ZLOGD(LOG_LABEL, "call js onRemoteRequest got exception");
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {nullptr};
    void* data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, nullptr, &data);
    napi_value res;
    CallbackParam *param = static_cast<CallbackParam *>(data);
    if (param == nullptr) {
        ZLOGE(LOG_LABEL, "param is null");
        napi_get_undefined(env, &res);
        return res;
    }

    // Reset old calling pid, uid, device id
    NAPI_RemoteObject_resetOldCallingInfoInner(param->env, param->oldCallingInfo);
    param->result = ERR_UNKNOWN_TRANSACTION;
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->ready = true;
    param->lockInfo->condition.notify_all();
    napi_get_undefined(env, &res);
    return res;
}

static bool CreateCatchCallback(CallbackParam *param, napi_value &catchValue)
{
    napi_status ret = napi_create_function(param->env, "catchCallback",
        NAPI_AUTO_LENGTH, CatchCallback, param, &catchValue);
    if (ret != napi_ok) {
        ZLOGE(LOG_LABEL, "catchCallback got exception");
        param->result = ERR_UNKNOWN_TRANSACTION;
        return false;
    }
    return true;
}

static bool CallPromiseThen(CallbackParam *param, napi_value &thenValue, napi_value &catchValue,
    napi_value &returnVal, napi_value &promiseThen)
{
    napi_env env = param->env;
    napi_value thenReturnValue;
    constexpr uint32_t THEN_ARGC = 2;
    napi_value thenArgv[THEN_ARGC] = { thenValue, catchValue };
    napi_status ret = napi_call_function(env, returnVal, promiseThen, THEN_ARGC, thenArgv, &thenReturnValue);
    if (ret != napi_ok) {
        ZLOGE(LOG_LABEL, "PromiseThen got exception ret:%{public}d", ret);
        param->result = ERR_UNKNOWN_TRANSACTION;
        return false;
    }
    return true;
}

static void CallJsOnRemoteRequestCallback(CallbackParam *param, napi_value &onRemoteRequest, napi_value &thisVar,
    const napi_value *argv, size_t argc)
{
    NAPI_RemoteObject_saveOldCallingInfoInner(param->env, param->oldCallingInfo);
    NAPI_RemoteObject_setNewCallingInfo(param->env, param->callingInfo);

    // start to call onRemoteRequest
    napi_value returnVal;
    napi_status ret = napi_call_function(param->env, thisVar, onRemoteRequest, argc, argv, &returnVal);

    do {
        if (ret != napi_ok) {
            ZLOGW(LOG_LABEL, "OnRemoteRequest got exception. ret:%{public}d", ret);
            param->result = ERR_UNKNOWN_TRANSACTION;
            break;
        }

        if (!IsPromiseResult(param, returnVal)) {
            break;
        }

        napi_value promiseThen = nullptr;
        if (!GetPromiseThen(param, returnVal, promiseThen)) {
            break;
        }

        napi_value thenValue = nullptr;
        if (!CreateThenCallback(param, thenValue)) {
            break;
        }

        napi_value catchValue = nullptr;
        if (!CreateCatchCallback(param, catchValue)) {
            break;
        }

        // Start to call promiseThen
        if (!CallPromiseThen(param, thenValue, catchValue, returnVal, promiseThen)) {
            break;
        }
        return;
    } while (0);

    // Reset old calling pid, uid, device id
    NAPI_RemoteObject_resetOldCallingInfoInner(param->env, param->oldCallingInfo);
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->ready = true;
    param->lockInfo->condition.notify_all();
}

static void OnJsRemoteRequestCallBack(CallbackParam *param, std::string &desc)
{
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());

    ZLOGI(LOG_LABEL, "%{public}s time:%{public}" PRIu64, desc.c_str(), curTime);

    NapiScope napiScope(param->env);
    if (!napiScope.IsValid()) {
        ZLOGE(LOG_LABEL, "napiScope is invalid");
        param->result = IPC_INVALID_PARAM_ERR;
        std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
        param->lockInfo->ready = true;
        param->lockInfo->condition.notify_all();
        return;
    }

    napi_value thisVar = nullptr;
    napi_get_reference_value(param->env, param->thisVarRef, &thisVar);
    if (!IsValidParamWithNotify(thisVar, param, "thisVar is null")) {
        return;
    }

    napi_value onRemoteRequest = nullptr;
    OnRemoteRequestType requestType = OnRemoteRequestType::ON_REMOTE_REQUEST;
    if (!GetJsOnRemoteRequestCallback(param, thisVar, onRemoteRequest, requestType)) {
        return;
    }

    napi_value jsCode;
    napi_create_uint32(param->env, param->code, &jsCode);

    napi_value global = nullptr;
    napi_get_global(param->env, &global);
    if (!IsValidParamWithNotify(global, param, "get napi global failed")) {
        return;
    }

    napi_value jsOption = nullptr;
    napi_value jsParcelConstructor = nullptr;
    napi_value jsData = nullptr;
    napi_value jsReply = nullptr;
    napi_value jsCallingInfo = nullptr;
    if (!CreateJsOption(param, global, jsOption) ||
        !GetJsParcelConstructor(param, global, requestType, jsParcelConstructor) ||
        !CreateJsParcel(param, jsParcelConstructor, jsData, true) ||
        !CreateJsParcel(param, jsParcelConstructor, jsReply, false) ||
        !CreateJsCallingInfo(param, global, jsCallingInfo)) {
        return;
    }

    napi_value argv[ARGV_LENGTH_5] = { jsCode, jsData, jsReply, jsOption, jsCallingInfo };
    size_t argc = requestType == OnRemoteRequestType::ON_REMOTE_MESSAGE_REQUEST_WITH_CALLING_INFO
        ? ARGV_LENGTH_5 : ARGV_LENGTH_4;
    CallJsOnRemoteRequestCallback(param, onRemoteRequest, thisVar, argv, argc);
}

static void RemoteObjectHolderFinalizeCb(napi_env env, void *data, void *hint)
{
    (void)hint;
    NAPIRemoteObjectHolder *holder = reinterpret_cast<NAPIRemoteObjectHolder *>(data);
    if (holder == nullptr) {
        ZLOGW(LOG_LABEL, "RemoteObjectHolderFinalizeCb null holder");
        return;
    }
    holder->Lock();
    int32_t curAttachCount = holder->DecAttachCount();
    holder->Unlock();
    ZLOGD(LOG_LABEL, "NAPIRemoteObjectHolder destructed by js callback, curAttachCount:%{public}d", curAttachCount);
    if (curAttachCount == 0) {
        delete holder;
    }
}

static void DecreaseJsObjectRef(napi_env env, napi_ref ref)
{
    if (ref == nullptr) {
        ZLOGI(LOG_LABEL, "ref is nullptr, do nothing");
        return;
    }

    uint32_t result;
    napi_status napiStatus = napi_reference_unref(env, ref, &result);
    NAPI_ASSERT_RETURN_VOID(env, napiStatus == napi_ok, "failed to decrease ref to js RemoteObject");
}

static void IncreaseJsObjectRef(napi_env env, napi_ref ref)
{
    uint32_t result;
    napi_status napiStatus = napi_reference_ref(env, ref, &result);
    NAPI_ASSERT_RETURN_VOID(env, napiStatus == napi_ok, "failed to increase ref to js RemoteObject");
}

static void RemoteObjectHolderRefCb(napi_env env, void *data, void *hint)
{
    (void)hint;
    NAPIRemoteObjectHolder *holder = reinterpret_cast<NAPIRemoteObjectHolder *>(data);
    NAPI_ASSERT_RETURN_VOID(env, holder != nullptr, "holder is nullptr");

    holder->Lock();
    int32_t curAttachCount = holder->DecAttachCount();
    holder->Unlock();
    ZLOGD(LOG_LABEL, "RemoteObjectHolderRefCb, curAttachCount:%{public}d", curAttachCount);

    napi_ref ref = holder->GetJsObjectRef();
    NAPI_ASSERT_RETURN_VOID(env, ref != nullptr, "ref is nullptr");
    napi_env workerEnv = holder->GetJsObjectEnv();
    NAPI_ASSERT_RETURN_VOID(env, workerEnv != nullptr, "workerEnv is nullptr");

    OperateJsRefParam *param = new (std::nothrow) OperateJsRefParam {
        .env = workerEnv,
        .thisVarRef = ref
    };
    NAPI_ASSERT_RETURN_VOID(workerEnv, param != nullptr, "new OperateJsRefParam failed");

    auto task = [param]() {
        ZLOGI(LOG_LABEL, "decrease");
        napi_handle_scope scope = nullptr;
        napi_status status = napi_open_handle_scope(param->env, &scope);
        if (status != napi_ok || scope == nullptr) {
            ZLOGE(LOG_LABEL, "Fail to open scope");
            delete param;
            return;
        }
        DecreaseJsObjectRef(param->env, param->thisVarRef);
        napi_close_handle_scope(param->env, scope);
        delete param;
    };
    napi_status sendRet = napi_send_event(env, task, napi_eprio_high, "IPC_RemoteObjectHolderRefCb");
    if (sendRet != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_send_event failed, ret:%{public}d", sendRet);
        delete param;
    }
}

static void *RemoteObjectDetachCb(napi_env engine, void *value, void *hint)
{
    (void)hint;
    napi_env env = engine;
    NAPIRemoteObjectHolder *holder = reinterpret_cast<NAPIRemoteObjectHolder *>(value);
    napi_ref ref = holder->GetJsObjectRef();

    uint32_t result;
    napi_status napiStatus = napi_reference_ref(env, ref, &result);
    if (napiStatus != napi_ok) {
        ZLOGE(LOG_LABEL, "RemoteObjectDetachCb, failed to increase ref");
    } else {
        ZLOGI(LOG_LABEL, "RemoteObjectDetachCb, ref result:%{public}u", result);
    }
    return value;
}

static napi_value RemoteObjectAttachCb(napi_env engine, void *value, void *hint)
{
    (void)hint;
    NAPIRemoteObjectHolder *holder = reinterpret_cast<NAPIRemoteObjectHolder *>(value);
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "holder is nullptr when attach");
        return nullptr;
    }
    holder->Lock();
    ZLOGI(LOG_LABEL, "create js remote object when attach");
    napi_env env = engine;
    // retrieve js remote object constructor
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "IPCStubConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get stub constructor failed");
    NAPI_ASSERT(env, constructor != nullptr, "failed to get js RemoteObject constructor");
    // retrieve descriptor and it's length
    std::u16string descriptor = holder->GetDescriptor();
    std::string desc = Str16ToStr8(descriptor);
    napi_value jsDesc = nullptr;
    napi_create_string_utf8(env, desc.c_str(), desc.length(), &jsDesc);
    // create a new js remote object
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { jsDesc };
    napi_value jsRemoteObject = nullptr;
    status = napi_new_instance(env, constructor, argc, argv, &jsRemoteObject);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteObject when attach");
    // retrieve and remove create holder
    NAPIRemoteObjectHolder *createHolder = nullptr;
    status = napi_remove_wrap(env, jsRemoteObject, (void **)&createHolder);
    NAPI_ASSERT(env, status == napi_ok && createHolder != nullptr, "failed to remove create holder when attach");
    status = napi_wrap(env, jsRemoteObject, holder, RemoteObjectHolderRefCb, nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js RemoteObject and native holder failed when attach");
    holder->IncAttachCount();
    holder->Unlock();
    return jsRemoteObject;
}

napi_value RemoteObject_JS_Constructor(napi_env env, napi_callback_info info)
{
    // new napi remote object
    size_t argc = 2;
    size_t expectedArgc = 1;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc >= expectedArgc, "requires at least 1 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");
    std::string descriptor = stringValue;
    auto holder = new (std::nothrow) NAPIRemoteObjectHolder(env, Str8ToStr16(descriptor), thisVar);
    NAPI_ASSERT(env, holder != nullptr, "new NAPIRemoteObjectHolder failed");
    napi_status status = napi_coerce_to_native_binding_object(env, thisVar, RemoteObjectDetachCb, RemoteObjectAttachCb,
        holder, nullptr);
    if (status != napi_ok) {
        delete holder;
        NAPI_ASSERT(env, false, "bind native RemoteObject failed");
    }
    // connect native object to js thisVar
    status = napi_wrap(env, thisVar, holder, RemoteObjectHolderFinalizeCb, nullptr, nullptr);
    if (status != napi_ok) {
        delete holder;
        NAPI_ASSERT(env, false, "wrap js RemoteObject and native holder failed");
    }
    return thisVar;
}

NapiScope::NapiScope(napi_env env) : env_(env)
{
    napi_status status = napi_open_handle_scope(env_, &scope_);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "open handle scope failed, status:%{public}d", status);
        isValid_ = false;
    } else {
        isValid_ = true;
    }
}

NapiScope::~NapiScope()
{
    if (isValid_) {
        napi_status status = napi_close_handle_scope(env_, scope_);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "close handle scope failed, status:%{public}d", status);
        }
    }
}

bool NapiScope::IsValid()
{
    return isValid_;
}

HandleEscape::HandleEscape(napi_env env) : env_(env)
{
    napi_status status = napi_open_escapable_handle_scope(env_, &scope_);
    if (status != napi_ok || scope_ == nullptr) {
        ZLOGE(LOG_LABEL, "open escapable handle scope failed, status:%{public}d", status);
        escapeIsValid_ = false;
    } else {
        escapeIsValid_ = true;
    }
}

HandleEscape::~HandleEscape()
{
    if (escapeIsValid_) {
        napi_status status = napi_close_escapable_handle_scope(env_, scope_);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "close escapable handle scope failed, status:%{public}d", status);
        }
    }
}

napi_value HandleEscape::Escape(napi_value value)
{
    napi_value result = nullptr;
    napi_status status = napi_escape_handle(env_, scope_, value, &result);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "escapable handle failed, result is nullptr, status:%{public}d", status);
        return nullptr;
    }
    return result;
}

bool HandleEscape::EscapeIsValid()
{
    return escapeIsValid_;
}

NAPIRemoteObject::NAPIRemoteObject(std::thread::id jsThreadId, napi_env env, napi_ref jsObjectRef,
    const std::u16string &descriptor)
    : IPCObjectStub(descriptor), jsThreadId_(jsThreadId)
{
    desc_ = Str16ToStr8(descriptor_);
    ZLOGD(LOG_LABEL, "created, desc:%{public}s", desc_.c_str());
    env_ = env;
    thisVarRef_ = jsObjectRef;

    if ((jsThreadId_ == std::this_thread::get_id()) &&
        (IPCThreadSkeleton::GetThreadType() != ThreadType::IPC_THREAD)) {
        IncreaseJsObjectRef(env_, jsObjectRef);
    } else {
        std::shared_ptr<struct ThreadLockInfo> lockInfo = std::make_shared<struct ThreadLockInfo>();
        OperateJsRefParam *param = new (std::nothrow) OperateJsRefParam {
            .env = env_,
            .thisVarRef = jsObjectRef,
            .lockInfo = lockInfo.get()
        };
        NAPI_ASSERT_RETURN_VOID(env_, param != nullptr, "new OperateJsRefParam failed");

        auto task = [param]() {
            napi_handle_scope scope = nullptr;
            napi_status status = napi_open_handle_scope(param->env, &scope);
            if (status != napi_ok || scope == nullptr) {
                ZLOGE(LOG_LABEL, "Fail to open scope");
                delete param;
                return;
            }
            IncreaseJsObjectRef(param->env, param->thisVarRef);
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            napi_close_handle_scope(param->env, scope);
        };
        napi_status sendRet = napi_send_event(env_, task, napi_eprio_high, "IPC_NAPIRemoteObject::NAPIRemoteObject");
        if (sendRet != napi_ok) {
            ZLOGE(LOG_LABEL, "napi_send_event failed, ret:%{public}d", sendRet);
        } else {
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->condition.wait(lock, [&param] { return param->lockInfo->ready; });
        }
        delete param;
    }
}

NAPIRemoteObject::~NAPIRemoteObject()
{
    ZLOGD(LOG_LABEL, "destoryed, desc:%{public}s", desc_.c_str());
    if (thisVarRef_ == nullptr || env_ == nullptr) {
        ZLOGD(LOG_LABEL, "thisVarRef_ or env_ is nullptr");
        return;
    }
    if ((jsThreadId_ == std::this_thread::get_id()) &&
        (IPCThreadSkeleton::GetThreadType() != ThreadType::IPC_THREAD)) {
        DecreaseJsObjectRef(env_, thisVarRef_);
    } else {
        OperateJsRefParam *param = new (std::nothrow) OperateJsRefParam {
            .env = env_,
            .thisVarRef = thisVarRef_
        };
        if (param == nullptr) {
            thisVarRef_ = nullptr;
            NAPI_ASSERT_RETURN_VOID(env_, false, "new OperateJsRefParam failed");
        }

        auto task = [param]() {
            napi_handle_scope scope = nullptr;
            napi_status status = napi_open_handle_scope(param->env, &scope);
            if (status != napi_ok || scope == nullptr) {
                ZLOGE(LOG_LABEL, "Fail to open scope");
                delete param;
                return;
            }
            DecreaseJsObjectRef(param->env, param->thisVarRef);
            napi_close_handle_scope(param->env, scope);
            delete param;
        };
        napi_status sendRet = napi_send_event(env_, task, napi_eprio_high, "IPC_NAPIRemoteObject::~NAPIRemoteObject");
        if (sendRet != napi_ok) {
            ZLOGE(LOG_LABEL, "napi_send_event failed, ret:%{public}d", sendRet);
            delete param;
        }
    }
    thisVarRef_ = nullptr;
}

bool NAPIRemoteObject::CheckObjectLegality() const
{
    return true;
}

int NAPIRemoteObject::GetObjectType() const
{
    return OBJECT_TYPE_JAVASCRIPT;
}

napi_ref NAPIRemoteObject::GetJsObjectRef() const
{
    return thisVarRef_;
}

void NAPIRemoteObject::ResetJsEnv()
{
    env_ = nullptr;
    thisVarRef_ = nullptr;
}

void NAPI_RemoteObject_getCallingInfo(CallingInfo &newCallingInfoParam)
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) {
        newCallingInfoParam.callingPid = invoker->GetCallerPid();
        newCallingInfoParam.callingUid = invoker->GetCallerUid();
        newCallingInfoParam.callingTokenId = static_cast<uint32_t>(invoker->GetCallerTokenID());
        newCallingInfoParam.activeStatus = IRemoteInvoker::ACTIVE_INVOKER;
    } else {
        newCallingInfoParam.callingPid = getpid();
        newCallingInfoParam.callingUid = getuid();
        newCallingInfoParam.callingTokenId = static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID());
        newCallingInfoParam.activeStatus = IRemoteInvoker::IDLE_INVOKER;
    }
    newCallingInfoParam.isLocalCalling = IPCSkeleton::IsLocalCalling();
    if (!newCallingInfoParam.isLocalCalling) {
        newCallingInfoParam.callingDeviceID = IPCSkeleton::GetCallingDeviceID();
        newCallingInfoParam.localDeviceID = IPCSkeleton::GetLocalDeviceID();
    }
};

int NAPIRemoteObject::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ZLOGD(LOG_LABEL, "enter OnRemoteRequest");
    if (code == DUMP_TRANSACTION) {
        ZLOGE(LOG_LABEL, "DUMP_TRANSACTION data size:%{public}zu", data.GetReadableBytes());
    }
    std::shared_ptr<struct ThreadLockInfo> lockInfo = std::make_shared<struct ThreadLockInfo>();
    CallbackParam *param = new (std::nothrow) CallbackParam {
        .env = env_,
        .thisVarRef = thisVarRef_,
        .code = code,
        .data = &data,
        .reply = &reply,
        .option = &option,
        .lockInfo = lockInfo.get(),
        .result = 0
    };
    if (param == nullptr) {
        ZLOGE(LOG_LABEL, "new CallbackParam failed");
        return ERR_ALLOC_MEMORY;
    }

    NAPI_RemoteObject_getCallingInfo(param->callingInfo);
    ZLOGD(LOG_LABEL, "callingPid:%{public}u callingUid:%{public}u "
        "callingDeviceID:%{public}s localDeviceId:%{public}s localCalling:%{public}d",
        param->callingInfo.callingPid, param->callingInfo.callingUid,
        IPCProcessSkeleton::ConvertToSecureString(param->callingInfo.callingDeviceID).c_str(),
        IPCProcessSkeleton::ConvertToSecureString(param->callingInfo.localDeviceID).c_str(),
        param->callingInfo.isLocalCalling);
    int ret = OnJsRemoteRequest(param);
    if (ret != 0) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LOG_LABEL, "OnJsRemoteRequest failed, ret:%{public}d time:%{public}" PRIu64, ret, curTime);
    }
    delete param;
    return ret;
}

void NAPI_RemoteObject_saveOldCallingInfo(napi_env env, NAPI_CallingInfo &oldCallingInfo)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_get_named_property(env, global, "callingPid_", &oldCallingInfo.callingPid);
    napi_get_named_property(env, global, "callingUid_", &oldCallingInfo.callingUid);
    napi_get_named_property(env, global, "callingTokenId_", &oldCallingInfo.callingTokenId);
    napi_get_named_property(env, global, "callingDeviceID_", &oldCallingInfo.callingDeviceID);
    napi_get_named_property(env, global, "localDeviceID_", &oldCallingInfo.localDeviceID);
    napi_get_named_property(env, global, "isLocalCalling_", &oldCallingInfo.isLocalCalling);
    napi_get_named_property(env, global, "isLocalCalling_", &oldCallingInfo.isLocalCalling);
    napi_get_named_property(env, global, "activeStatus_", &oldCallingInfo.activeStatus);
}

void NAPI_RemoteObject_setNewCallingInfo(napi_env env, const CallingInfo &newCallingInfoParam)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value newPid = nullptr;
    napi_create_int32(env, static_cast<int32_t>(newCallingInfoParam.callingPid), &newPid);
    napi_set_named_property(env, global, "callingPid_", newPid);
    napi_value newUid = nullptr;
    napi_create_int32(env, static_cast<int32_t>(newCallingInfoParam.callingUid), &newUid);
    napi_set_named_property(env, global, "callingUid_", newUid);
    napi_value newCallingTokenId = nullptr;
    napi_create_uint32(env, newCallingInfoParam.callingTokenId, &newCallingTokenId);
    napi_set_named_property(env, global, "callingTokenId_", newCallingTokenId);
    napi_value newDeviceID = nullptr;
    napi_create_string_utf8(env, newCallingInfoParam.callingDeviceID.c_str(), NAPI_AUTO_LENGTH, &newDeviceID);
    napi_set_named_property(env, global, "callingDeviceID_", newDeviceID);
    napi_value newLocalDeviceID = nullptr;
    napi_create_string_utf8(env, newCallingInfoParam.localDeviceID.c_str(), NAPI_AUTO_LENGTH, &newLocalDeviceID);
    napi_set_named_property(env, global, "localDeviceID_", newLocalDeviceID);
    napi_value newIsLocalCalling = nullptr;
    napi_get_boolean(env, newCallingInfoParam.isLocalCalling, &newIsLocalCalling);
    napi_set_named_property(env, global, "isLocalCalling_", newIsLocalCalling);
    napi_value newActiveStatus = nullptr;
    napi_create_int32(env, newCallingInfoParam.activeStatus, &newActiveStatus);
    napi_set_named_property(env, global, "activeStatus_", newActiveStatus);
}

void NAPI_RemoteObject_resetOldCallingInfo(napi_env env, NAPI_CallingInfo &oldCallingInfo)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_set_named_property(env, global, "callingPid_", oldCallingInfo.callingPid);
    napi_set_named_property(env, global, "callingUid_", oldCallingInfo.callingUid);
    napi_set_named_property(env, global, "callingTokenId_", oldCallingInfo.callingTokenId);
    napi_set_named_property(env, global, "callingDeviceID_", oldCallingInfo.callingDeviceID);
    napi_set_named_property(env, global, "localDeviceID_", oldCallingInfo.localDeviceID);
    napi_set_named_property(env, global, "isLocalCalling_", oldCallingInfo.isLocalCalling);
    napi_set_named_property(env, global, "activeStatus_", oldCallingInfo.activeStatus);
}
}
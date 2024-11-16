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

static const size_t ARGV_LENGTH_1 = 1;
static const size_t ARGV_LENGTH_2 = 2;
static const size_t ARGV_LENGTH_4 = 4;
static const size_t ARGV_LENGTH_5 = 5;

static const size_t DEVICE_ID_LENGTH = 64;

static const uint64_t HITRACE_TAG_RPC = (1ULL << 46); // RPC and IPC tag.

static std::atomic<int32_t> bytraceId = 1000;
static NapiError napiErr;

static bool IsValidParamWithNotify(napi_value value, CallbackParam *param, const char *errDesc)
{
    if (value == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s", errDesc);
        param->result = ERR_INVALID_PARAM;
        std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
        param->lockInfo->ready = true;
        param->lockInfo->condition.notify_all();
        return false;
    }
    return true;
}

static bool GetJsOnRemoteRequestCallback(CallbackParam *param, const napi_value thisVar, napi_value &onRemoteRequest,
    bool &isOnRemoteMessageRequest)
{
    napi_get_named_property(param->env, thisVar, "onRemoteMessageRequest", &onRemoteRequest);
    if (!IsValidParamWithNotify(onRemoteRequest, param, "get function onRemoteMessageRequest failed")) {
        return false;
    }
    isOnRemoteMessageRequest = true;

    napi_valuetype type = napi_undefined;
    napi_typeof(param->env, onRemoteRequest, &type);
    if (type != napi_function) {
        napi_get_named_property(param->env, thisVar, "onRemoteRequest", &onRemoteRequest);
        if (!IsValidParamWithNotify(onRemoteRequest, param, "get function onRemoteRequest failed")) {
            return false;
        }
        isOnRemoteMessageRequest = false;
    }
    return true;
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

static bool GetJsParcelConstructor(CallbackParam *param, const napi_value global, bool isOnRemoteMessageRequest,
    napi_value &jsParcelConstructor)
{
    if (isOnRemoteMessageRequest) {
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
        param->result = ERR_INVALID_PARAM;
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
    ZLOGI(LOG_LABEL, "call js onRemoteRequest done, time:%{public}" PRIu64, curTime);
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
    ZLOGI(LOG_LABEL, "call js onRemoteRequest got exception");
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
    const napi_value *argv)
{
    NAPI_RemoteObject_saveOldCallingInfoInner(param->env, param->oldCallingInfo);
    NAPI_RemoteObject_setNewCallingInfo(param->env, param->callingInfo);

    // start to call onRemoteRequest
    napi_value returnVal;
    napi_status ret = napi_call_function(param->env, thisVar, onRemoteRequest, ARGV_LENGTH_4, argv, &returnVal);

    do {
        if (ret != napi_ok) {
            ZLOGE(LOG_LABEL, "OnRemoteRequest got exception. ret:%{public}d", ret);
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

static void OnJsRemoteRequestCallBack(uv_work_t *work, int status)
{
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());

    ZLOGI(LOG_LABEL, "enter thread pool time:%{public}" PRIu64, curTime);
    CallbackParam *param = reinterpret_cast<CallbackParam *>(work->data);

    NapiScopeHandler scopeHandler(param->env);
    if (!scopeHandler.IsValid()) {
        return;
    }

    napi_value thisVar = nullptr;
    napi_get_reference_value(param->env, param->thisVarRef, &thisVar);
    if (!IsValidParamWithNotify(thisVar, param, "thisVar is null")) {
        return;
    }

    napi_value onRemoteRequest = nullptr;
    bool isOnRemoteMessageRequest = true;
    if (!GetJsOnRemoteRequestCallback(param, thisVar, onRemoteRequest, isOnRemoteMessageRequest)) {
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
    if (!CreateJsOption(param, global, jsOption) ||
        !GetJsParcelConstructor(param, global, isOnRemoteMessageRequest, jsParcelConstructor) ||
        !CreateJsParcel(param, jsParcelConstructor, jsData, true) ||
        !CreateJsParcel(param, jsParcelConstructor, jsReply, false)) {
        return;
    }

    napi_value argv[ARGV_LENGTH_4] = { jsCode, jsData, jsReply, jsOption };
    CallJsOnRemoteRequestCallback(param, onRemoteRequest, thisVar, argv);
}

static void RemoteObjectHolderFinalizeCb(napi_env env, void *data, void *hint)
{
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
 
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(workerEnv, &loop);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    NAPI_ASSERT_RETURN_VOID(workerEnv, work != nullptr, "cb failed to new work");
    OperateJsRefParam *param = new (std::nothrow) OperateJsRefParam {
        .env = workerEnv,
        .thisVarRef = ref
    };
    if (param == nullptr) {
        delete work;
        NAPI_ASSERT_RETURN_VOID(workerEnv, false, "new OperateJsRefParam failed");
    }
    work->data = reinterpret_cast<void *>(param);
    int uvRet = uv_queue_work(loop, work, [](uv_work_t *work) {
        ZLOGD(LOG_LABEL, "enter work pool.");
    }, [](uv_work_t *work, int status) {
        ZLOGI(LOG_LABEL, "decrease on uv work thread");
        OperateJsRefParam *param = reinterpret_cast<OperateJsRefParam *>(work->data);
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        DecreaseJsObjectRef(param->env, param->thisVarRef);
        napi_close_handle_scope(param->env, scope);
        delete param;
        delete work;
    });
    if (uvRet != 0) {
        ZLOGE(LOG_LABEL, "uv_queue_work failed, ret %{public}d", uvRet);
        delete param;
        delete work;
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

NapiScopeHandler::NapiScopeHandler(napi_env env) : env_(env)
{
    napi_status status = napi_open_handle_scope(env_, &scope_);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "open handle scope failed, status:%{public}d", status);
        isValid_ = false;
    } else {
        isValid_ = true;
    }
}

NapiScopeHandler::~NapiScopeHandler()
{
    if (isValid_) {
        napi_status status = napi_close_handle_scope(env_, scope_);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "close handle scope failed, status:%{public}d", status);
        }
    }
}

bool NapiScopeHandler::IsValid()
{
    return isValid_;
}

NAPIRemoteObject::NAPIRemoteObject(std::thread::id jsThreadId, napi_env env, napi_ref jsObjectRef,
    const std::u16string &descriptor)
    : IPCObjectStub(descriptor)
{
    ZLOGD(LOG_LABEL, "created, desc:%{public}s", Str16ToStr8(descriptor_).c_str());
    env_ = env;
    jsThreadId_ = jsThreadId;
    thisVarRef_ = jsObjectRef;

    if (jsThreadId_ == std::this_thread::get_id()) {
        IncreaseJsObjectRef(env, jsObjectRef);
    } else {
        uv_loop_s *loop = nullptr;
        napi_get_uv_event_loop(env_, &loop);
        uv_work_t *work = new (std::nothrow) uv_work_t;
        NAPI_ASSERT_RETURN_VOID(env_, work != nullptr, "create NAPIRemoteObject, new work failed");
        std::shared_ptr<struct ThreadLockInfo> lockInfo = std::make_shared<struct ThreadLockInfo>();
        OperateJsRefParam *param = new (std::nothrow) OperateJsRefParam {
            .env = env_,
            .thisVarRef = jsObjectRef,
            .lockInfo = lockInfo.get()
        };
        if (param == nullptr) {
            delete work;
            NAPI_ASSERT_RETURN_VOID(env_, false, "new OperateJsRefParam failed");
        } 

        work->data = reinterpret_cast<void *>(param);
        int uvRet = uv_queue_work(loop, work, [](uv_work_t *work) {
            ZLOGD(LOG_LABEL, "enter work pool.");
        }, [](uv_work_t *work, int status) {
            OperateJsRefParam *param = reinterpret_cast<OperateJsRefParam *>(work->data);
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(param->env, &scope);
            IncreaseJsObjectRef(param->env, param->thisVarRef);
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            napi_close_handle_scope(param->env, scope);
        });
        if (uvRet != 0) {
            ZLOGE(LOG_LABEL, "uv_queue_work failed, ret %{public}d", uvRet);
        } else {
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->condition.wait(lock, [&param] { return param->lockInfo->ready; });
        }
        delete param;
        delete work;
    }
}

NAPIRemoteObject::~NAPIRemoteObject()
{
    ZLOGD(LOG_LABEL, "destoryed, desc:%{public}s", Str16ToStr8(descriptor_).c_str());
    if (thisVarRef_ != nullptr && env_ != nullptr) {
        if (jsThreadId_ == std::this_thread::get_id()) {
            DecreaseJsObjectRef(env_, thisVarRef_);
        } else {
            uv_loop_s *loop = nullptr;
            napi_get_uv_event_loop(env_, &loop);
            uv_work_t *work = new (std::nothrow) uv_work_t;
            NAPI_ASSERT_RETURN_VOID(env_, work != nullptr, "release NAPIRemoteObject, new work failed");
            OperateJsRefParam *param = new (std::nothrow) OperateJsRefParam {
                .env = env_,
                .thisVarRef = thisVarRef_
            };
            if (param == nullptr) {
                thisVarRef_ = nullptr;
                delete work;
                NAPI_ASSERT_RETURN_VOID(env_, false, "new OperateJsRefParam failed");
            }
            work->data = reinterpret_cast<void *>(param);
            int uvRet = uv_queue_work(loop, work, [](uv_work_t *work) {
                ZLOGD(LOG_LABEL, "enter work pool.");
            }, [](uv_work_t *work, int status) {
                OperateJsRefParam *param = reinterpret_cast<OperateJsRefParam *>(work->data);
                napi_handle_scope scope = nullptr;
                napi_open_handle_scope(param->env, &scope);
                DecreaseJsObjectRef(param->env, param->thisVarRef);
                napi_close_handle_scope(param->env, scope);
                delete param;
                delete work;
            });
            if (uvRet != 0) {
                ZLOGE(LOG_LABEL, "uv_queue_work failed, ret %{public}d", uvRet);
                delete param;
                delete work;
            }
        }
        thisVarRef_ = nullptr;
    }
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
    newCallingInfoParam.callingPid = IPCSkeleton::GetCallingPid();
    newCallingInfoParam.callingUid = IPCSkeleton::GetCallingUid();
    newCallingInfoParam.callingTokenId = IPCSkeleton::GetCallingTokenID();
    newCallingInfoParam.callingDeviceID = IPCSkeleton::GetCallingDeviceID();
    newCallingInfoParam.localDeviceID = IPCSkeleton::GetLocalDeviceID();
    newCallingInfoParam.isLocalCalling = IPCSkeleton::IsLocalCalling();
    newCallingInfoParam.activeStatus = IRemoteInvoker::ACTIVE_INVOKER;
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

int NAPIRemoteObject::OnJsRemoteRequest(CallbackParam *jsParam)
{
    if (jsParam == nullptr) {
        ZLOGE(LOG_LABEL, "Js Param is null");
        return ERR_UNKNOWN_REASON;
    }
    if (thisVarRef_ == nullptr || env_ == nullptr) {
        ZLOGE(LOG_LABEL, "Js env has been destructed");
        return ERR_UNKNOWN_REASON;
    }
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ZLOGE(LOG_LABEL, "failed to new uv_work_t");
        return ERR_ALLOC_MEMORY;
    }
    work->data = reinterpret_cast<void *>(jsParam);

    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    ZLOGD(LOG_LABEL, "start nv queue work loop. desc:%{public}s time:%{public}" PRIu64,
        Str16ToStr8(descriptor_).c_str(), curTime);
    int uvRet = uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGI(LOG_LABEL, "enter work pool. code:%{public}u time:%{public}" PRIu64,
            (reinterpret_cast<CallbackParam *>(work->data))->code, curTime);
    }, OnJsRemoteRequestCallBack, uv_qos_user_initiated);
    int ret = 0;
    if (uvRet != 0) {
        ZLOGE(LOG_LABEL, "uv_queue_work_with_qos failed, ret:%{public}d", uvRet); 
        ret = ERR_START_UV_WORK;
    } else {
        std::unique_lock<std::mutex> lock(jsParam->lockInfo->mutex);
        jsParam->lockInfo->condition.wait(lock, [&jsParam] { return jsParam->lockInfo->ready; });
        ret = jsParam->result;
    }
    delete work;
    return ret;
}

napi_value NAPI_ohos_rpc_CreateJsRemoteObject(napi_env env, const sptr<IRemoteObject> target)
{
    if (target == nullptr) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LOG_LABEL, "RemoteObject is null time:%{public}" PRIu64, curTime);
        return nullptr;
    }

    if (!target->IsProxyObject()) {
        IPCObjectStub *tmp = static_cast<IPCObjectStub *>(target.GetRefPtr());
        uint32_t objectType = static_cast<uint32_t>(tmp->GetObjectType());
        ZLOGD(LOG_LABEL, "create js object, type:%{public}d", objectType);
        if (objectType == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT || objectType == IPCObjectStub::OBJECT_TYPE_NATIVE) {
            // retrieve js remote object constructor
            napi_value global = nullptr;
            napi_status status = napi_get_global(env, &global);
            NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
            napi_value constructor = nullptr;
            status = napi_get_named_property(env, global, "IPCStubConstructor_", &constructor);
            NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
            NAPI_ASSERT(env, constructor != nullptr, "failed to get js RemoteObject constructor");
            // retrieve descriptor and it's length
            std::u16string descriptor = target->GetObjectDescriptor();
            std::string desc = Str16ToStr8(descriptor);
            napi_value jsDesc = nullptr;
            napi_create_string_utf8(env, desc.c_str(), desc.length(), &jsDesc);
            // create a new js remote object
            size_t argc = 1;
            napi_value argv[ARGV_LENGTH_1] = { jsDesc };
            napi_value jsRemoteObject = nullptr;
            status = napi_new_instance(env, constructor, argc, argv, &jsRemoteObject);
            NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteObject");
            // retrieve holder and set object
            NAPIRemoteObjectHolder *holder = nullptr;
            napi_unwrap(env, jsRemoteObject, (void **)&holder);
            NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
            holder->Set(target);
            return jsRemoteObject;
        }
    }

    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "IPCProxyConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get proxy constructor failed");
    napi_value jsRemoteProxy;
    status = napi_new_instance(env, constructor, 0, nullptr, &jsRemoteProxy);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteProxy");
    NAPIRemoteProxyHolder *proxyHolder = NAPI_ohos_rpc_getRemoteProxyHolder(env, jsRemoteProxy);
    if (proxyHolder == nullptr) {
        ZLOGE(LOG_LABEL, "proxyHolder null");
        return nullptr;
    }
    proxyHolder->object_ = target;
    proxyHolder->list_ = new (std::nothrow) NAPIDeathRecipientList();
    NAPI_ASSERT(env, proxyHolder->list_ != nullptr, "new NAPIDeathRecipientList failed");

    return jsRemoteProxy;
}

bool NAPI_ohos_rpc_ClearNativeRemoteProxy(napi_env env, napi_value jsRemoteProxy)
{
    NAPIRemoteProxyHolder *holder = NAPI_ohos_rpc_getRemoteProxyHolder(env, jsRemoteProxy);
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "holder null");
        return false;
    }
    ZLOGI(LOG_LABEL, "clear native remote proxy");
    holder->object_ = nullptr;
    return true;
}

sptr<IRemoteObject> NAPI_ohos_rpc_getNativeRemoteObject(napi_env env, napi_value object)
{
    if (object != nullptr) {
        napi_value global = nullptr;
        napi_status status = napi_get_global(env, &global);
        NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
        napi_value stubConstructor = nullptr;
        status = napi_get_named_property(env, global, "IPCStubConstructor_", &stubConstructor);
        NAPI_ASSERT(env, status == napi_ok, "get stub constructor failed");
        bool instanceOfStub = false;
        status = napi_instanceof(env, object, stubConstructor, &instanceOfStub);
        NAPI_ASSERT(env, status == napi_ok, "failed to check js object type");
        if (instanceOfStub) {
            NAPIRemoteObjectHolder *holder = nullptr;
            napi_unwrap(env, object, (void **)&holder);
            NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
            return holder != nullptr ? holder->Get() : nullptr;
        }

        napi_value proxyConstructor = nullptr;
        status = napi_get_named_property(env, global, "IPCProxyConstructor_", &proxyConstructor);
        NAPI_ASSERT(env, status == napi_ok, "get proxy constructor failed");
        bool instanceOfProxy = false;
        status = napi_instanceof(env, object, proxyConstructor, &instanceOfProxy);
        NAPI_ASSERT(env, status == napi_ok, "failed to check js object type");
        if (instanceOfProxy) {
            NAPIRemoteProxyHolder *holder = NAPI_ohos_rpc_getRemoteProxyHolder(env, object);
            return holder != nullptr ? holder->object_ : nullptr;
        }
    }
    return nullptr;
}

static napi_value NAPI_RemoteObject_queryLocalInterface(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    size_t expectedArgc = 1;
    napi_value argv[ARGV_LENGTH_1] = {nullptr};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 1 parameters");
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
    NAPIRemoteObjectHolder *holder = nullptr;
    napi_unwrap(env, thisVar, (void **)&holder);
    NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
    napi_value ret = holder->queryLocalInterface(descriptor);
    return ret;
}

static napi_value NAPI_RemoteObject_getLocalInterface(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    size_t expectedArgc = 1;
    napi_value argv[ARGV_LENGTH_1] = {nullptr};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
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
    std::string descriptor = stringValue;
    NAPIRemoteObjectHolder *holder = nullptr;
    napi_unwrap(env, thisVar, (void **)&holder);
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get napi remote object holder");
        return nullptr;
    }
    napi_value ret = holder->queryLocalInterface(descriptor);
    return ret;
}

static napi_value NAPI_RemoteObject_getInterfaceDescriptor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    sptr<IRemoteObject> nativeObject = NAPI_ohos_rpc_getNativeRemoteObject(env, thisVar);
    std::u16string descriptor = nativeObject->GetObjectDescriptor();
    napi_create_string_utf8(env, Str16ToStr8(descriptor).c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

static napi_value NAPI_RemoteObject_getDescriptor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    sptr<IRemoteObject> nativeObject = NAPI_ohos_rpc_getNativeRemoteObject(env, thisVar);
    if (nativeObject == nullptr) {
        ZLOGE(LOG_LABEL, "native stub object is nullptr");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    std::u16string descriptor = nativeObject->GetObjectDescriptor();
    napi_create_string_utf8(env, Str16ToStr8(descriptor).c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

static napi_value NAPI_RemoteObject_getCallingPid(napi_env env, napi_callback_info info)
{
    return NAPI_getCallingPid(env, info);
}

static napi_value NAPI_RemoteObject_getCallingUid(napi_env env, napi_callback_info info)
{
    return NAPI_getCallingUid(env, info);
}

napi_value MakeSendRequestResult(SendRequestParam *param)
{
    if (param == nullptr) {
        ZLOGE(LOG_LABEL, "send request param is null");
        return nullptr;
    }
    napi_value errCode = nullptr;
    napi_create_int32(param->env, param->errCode, &errCode);
    napi_value code = nullptr;
    napi_get_reference_value(param->env, param->jsCodeRef, &code);
    napi_value data = nullptr;
    napi_get_reference_value(param->env, param->jsDataRef, &data);
    napi_value reply = nullptr;
    napi_get_reference_value(param->env, param->jsReplyRef, &reply);
    napi_value result = nullptr;
    napi_create_object(param->env, &result);
    napi_set_named_property(param->env, result, "errCode", errCode);
    napi_set_named_property(param->env, result, "code", code);
    napi_set_named_property(param->env, result, "data", data);
    napi_set_named_property(param->env, result, "reply", reply);
    return result;
}

void StubExecuteSendRequest(napi_env env, SendRequestParam *param)
{
    if (param == nullptr) {
        ZLOGE(LOG_LABEL, "param is null");
        return;
    }
    param->errCode = param->target->SendRequest(param->code,
        *(param->data.get()), *(param->reply.get()), param->option);
    uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    ZLOGI(LOG_LABEL, "sendRequest done, errCode:%{public}d time：%{public}" PRIu64, param->errCode, curTime);
    if (param->traceId != 0) {
        FinishAsyncTrace(HITRACE_TAG_RPC, (param->traceValue).c_str(), param->traceId);
    }
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ZLOGE(LOG_LABEL, "new uv_work_t failed");
        return;
    }
    work->data = reinterpret_cast<void *>(param);
    uv_after_work_cb afterWorkCb = nullptr;
    if (param->callback != nullptr) {
        afterWorkCb = [](uv_work_t *work, int status) {
            ZLOGI(LOG_LABEL, "callback started");
            SendRequestParam *param = reinterpret_cast<SendRequestParam *>(work->data);
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(param->env, &scope);
            napi_value result = MakeSendRequestResult(param);
            napi_value callback = nullptr;
            napi_get_reference_value(param->env, param->callback, &callback);
            napi_value cbResult = nullptr;
            napi_call_function(param->env, nullptr, callback, 1, &result, &cbResult);
            napi_delete_reference(param->env, param->jsCodeRef);
            napi_delete_reference(param->env, param->jsDataRef);
            napi_delete_reference(param->env, param->jsReplyRef);
            napi_delete_reference(param->env, param->jsOptionRef);
            napi_delete_reference(param->env, param->callback);
            napi_close_handle_scope(param->env, scope);
            delete param;
            delete work;
        };
    } else {
        afterWorkCb = [](uv_work_t *work, int status) {
            uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            ZLOGI(LOG_LABEL, "promise fullfilled time:%{public}" PRIu64, curTime);
            SendRequestParam *param = reinterpret_cast<SendRequestParam *>(work->data);
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(param->env, &scope);
            napi_value result = MakeSendRequestResult(param);
            if (param->errCode == 0) {
                napi_resolve_deferred(param->env, param->deferred, result);
            } else {
                napi_reject_deferred(param->env, param->deferred, result);
            }
            napi_delete_reference(param->env, param->jsCodeRef);
            napi_delete_reference(param->env, param->jsDataRef);
            napi_delete_reference(param->env, param->jsReplyRef);
            napi_delete_reference(param->env, param->jsOptionRef);
            napi_close_handle_scope(param->env, scope);
            delete param;
            delete work;
        };
    }
    int uvRet = uv_queue_work(loop, work, [](uv_work_t *work) {
        ZLOGD(LOG_LABEL, "enter work pool.");
    }, afterWorkCb);
    if (uvRet != 0) {
        ZLOGE(LOG_LABEL, "uv_queue_work failed, ret %{public}d", uvRet);
        delete param;
        delete work;
    }
}

napi_value StubSendRequestAsync(napi_env env, sptr<IRemoteObject> target, uint32_t code,
    std::shared_ptr<MessageParcel> data, std::shared_ptr<MessageParcel> reply,
    MessageOption &option, napi_value *argv)
{
    napi_value result = nullptr;
    SendRequestParam *sendRequestParam = new (std::nothrow) SendRequestParam {
        .target = target,
        .code = code,
        .data = data,
        .reply = reply,
        .option = option,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .errCode = -1,
        .jsCodeRef = nullptr,
        .jsDataRef = nullptr,
        .jsReplyRef = nullptr,
        .jsOptionRef = nullptr,
        .callback = nullptr,
        .env = env,
        .traceId = 0,
    };
    NAPI_ASSERT(env, sendRequestParam != nullptr, "new SendRequestParam failed");
    if (target != nullptr) {
        std::string remoteDescriptor = Str16ToStr8(target->GetObjectDescriptor());
        if (!remoteDescriptor.empty()) {
            sendRequestParam->traceValue = remoteDescriptor + std::to_string(code);
            sendRequestParam->traceId = bytraceId.fetch_add(1, std::memory_order_seq_cst);
            StartAsyncTrace(HITRACE_TAG_RPC, (sendRequestParam->traceValue).c_str(), sendRequestParam->traceId);
        }
    }
    napi_create_reference(env, argv[ARGV_INDEX_0], 1, &sendRequestParam->jsCodeRef);
    napi_create_reference(env, argv[ARGV_INDEX_1], 1, &sendRequestParam->jsDataRef);
    napi_create_reference(env, argv[ARGV_INDEX_2], 1, &sendRequestParam->jsReplyRef);
    napi_create_reference(env, argv[ARGV_INDEX_3], 1, &sendRequestParam->jsOptionRef);
    napi_create_reference(env, argv[ARGV_INDEX_4], 1, &sendRequestParam->callback);
    std::thread t(StubExecuteSendRequest, env, sendRequestParam);
    t.detach();
    napi_get_undefined(env, &result);
    return result;
}

napi_value StubSendRequestPromise(napi_env env, sptr<IRemoteObject> target, uint32_t code,
    std::shared_ptr<MessageParcel> data, std::shared_ptr<MessageParcel> reply,
    MessageOption &option, napi_value *argv)
{
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    SendRequestParam *sendRequestParam = new (std::nothrow) SendRequestParam {
        .target = target,
        .code = code,
        .data = data,
        .reply = reply,
        .option = option,
        .asyncWork = nullptr,
        .deferred = deferred,
        .errCode = -1,
        .jsCodeRef = nullptr,
        .jsDataRef = nullptr,
        .jsReplyRef = nullptr,
        .jsOptionRef = nullptr,
        .callback = nullptr,
        .env = env,
        .traceId = 0,
    };
    NAPI_ASSERT(env, sendRequestParam != nullptr, "new SendRequestParam failed");
    if (target != nullptr) {
        std::string remoteDescriptor = Str16ToStr8(target->GetObjectDescriptor());
        if (!remoteDescriptor.empty()) {
            sendRequestParam->traceValue = remoteDescriptor + std::to_string(code);
            sendRequestParam->traceId = bytraceId.fetch_add(1, std::memory_order_seq_cst);
            StartAsyncTrace(HITRACE_TAG_RPC, (sendRequestParam->traceValue).c_str(), sendRequestParam->traceId);
        }
    }
    napi_create_reference(env, argv[ARGV_INDEX_0], 1, &sendRequestParam->jsCodeRef);
    napi_create_reference(env, argv[ARGV_INDEX_1], 1, &sendRequestParam->jsDataRef);
    napi_create_reference(env, argv[ARGV_INDEX_2], 1, &sendRequestParam->jsReplyRef);
    napi_create_reference(env, argv[ARGV_INDEX_3], 1, &sendRequestParam->jsOptionRef);
    std::thread t(StubExecuteSendRequest, env, sendRequestParam);
    t.detach();
    return promise;
}

static napi_value NAPI_RemoteObject_sendRequest(napi_env env, napi_callback_info info)
{
    size_t argc = 4;
    size_t argcCallback = 5;
    size_t argcPromise = 4;
    napi_value argv[ARGV_LENGTH_5] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == argcPromise || argc == argcCallback, "requires 4 or 5 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 2");
    napi_typeof(env, argv[ARGV_INDEX_2], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 3");
    napi_typeof(env, argv[ARGV_INDEX_3], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 4");

    NAPI_MessageParcel *data = nullptr;
    napi_status status = napi_unwrap(env, argv[ARGV_INDEX_1], (void **)&data);
    NAPI_ASSERT(env, status == napi_ok, "failed to get data message parcel");
    NAPI_MessageParcel *reply = nullptr;
    status = napi_unwrap(env, argv[ARGV_INDEX_2], (void **)&reply);
    NAPI_ASSERT(env, status == napi_ok, "failed to get reply message parcel");
    MessageOption *option = nullptr;
    status = napi_unwrap(env, argv[ARGV_INDEX_3], (void **)&option);
    NAPI_ASSERT(env, status == napi_ok, "failed to get message option");
    int32_t code = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &code);

    sptr<IRemoteObject> target = NAPI_ohos_rpc_getNativeRemoteObject(env, thisVar);
    if (argc == argcCallback) {
        napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[argcPromise], &valuetype);
        if (valuetype == napi_function) {
            return StubSendRequestAsync(env, target, code, data->GetMessageParcel(),
                reply->GetMessageParcel(), *option, argv);
        }
    }
    return StubSendRequestPromise(env, target, code, data->GetMessageParcel(),
        reply->GetMessageParcel(), *option, argv);
}

napi_value NAPI_RemoteObject_checkSendMessageRequestArgs(napi_env env,
                                                         size_t argc,
                                                         size_t argcCallback,
                                                         size_t argcPromise,
                                                         napi_value* argv)
{
    if (argc != argcPromise && argc != argcCallback) {
        ZLOGE(LOG_LABEL, "requires 4 or 5 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_2], &valueType);
    if (valueType != napi_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 3");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_3], &valueType);
    if (valueType != napi_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 4");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value NAPI_RemoteObject_sendMessageRequest(napi_env env, napi_callback_info info)
{
    size_t argc = 4;
    size_t argcCallback = 5;
    size_t argcPromise = 4;
    napi_value argv[ARGV_LENGTH_5] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = NAPI_RemoteObject_checkSendMessageRequestArgs(env, argc, argcCallback, argcPromise,
                                                                               argv);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }
    NAPI_MessageSequence *data = nullptr;
    napi_status status = napi_unwrap(env, argv[ARGV_INDEX_1], (void **)&data);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get data message sequence");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    NAPI_MessageSequence *reply = nullptr;
    status = napi_unwrap(env, argv[ARGV_INDEX_2], (void **)&reply);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get data message sequence");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    MessageOption *option = nullptr;
    status = napi_unwrap(env, argv[ARGV_INDEX_3], (void **)&option);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get message option");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t code = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &code);

    sptr<IRemoteObject> target = NAPI_ohos_rpc_getNativeRemoteObject(env, thisVar);
    if (argc == argcCallback) {
        napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[argcPromise], &valuetype);
        if (valuetype == napi_function) {
            return StubSendRequestAsync(env, target, code, data->GetMessageParcel(),
                reply->GetMessageParcel(), *option, argv);
        }
    }
    return StubSendRequestPromise(env, target, code, data->GetMessageParcel(),
        reply->GetMessageParcel(), *option, argv);
}

static napi_value NAPI_RemoteObject_attachLocalInterface(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    size_t expectedArgc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 1");
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 2");
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_1], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_1], stringValue, bufferSize + 1, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");
    std::string descriptor = stringValue;

    NAPIRemoteObjectHolder *holder = nullptr;
    napi_unwrap(env, thisVar, (void* *)&holder);
    NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
    holder->attachLocalInterface(argv[ARGV_INDEX_0], descriptor);

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_RemoteObject_checkModifyLocalInterfaceArgs(napi_env env, size_t argc, napi_value* argv)
{
    size_t expectedArgc = 2;

    if (argc != expectedArgc) {
        ZLOGE(LOG_LABEL, "requires 2 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value NAPI_RemoteObject_modifyLocalInterface(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = NAPI_RemoteObject_checkModifyLocalInterfaceArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_1], nullptr, 0, &bufferSize);
    if (bufferSize >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_1], stringValue, bufferSize + 1, &jsStringLength);
    if (jsStringLength != bufferSize) {
        ZLOGE(LOG_LABEL, "string length wrong");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    std::string descriptor = stringValue;

    NAPIRemoteObjectHolder *holder = nullptr;
    napi_unwrap(env, thisVar, (void* *)&holder);
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get napi remote object holder");
        return nullptr;
    }
    holder->attachLocalInterface(argv[ARGV_INDEX_0], descriptor);

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value NAPI_RemoteObject_addDeathRecipient(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_boolean(env, false, &result);
    return result;
}

static napi_value NAPI_RemoteObject_registerDeathRecipient(napi_env env, napi_callback_info info)
{
    ZLOGE(LOG_LABEL, "only proxy object permitted");
    return napiErr.ThrowError(env, errorDesc::ONLY_PROXY_OBJECT_PERMITTED_ERROR);
}

static napi_value NAPI_RemoteObject_removeDeathRecipient(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_boolean(env, false, &result);
    return result;
}

static napi_value NAPI_RemoteObject_unregisterDeathRecipient(napi_env env, napi_callback_info info)
{
    ZLOGE(LOG_LABEL, "only proxy object permitted");
    return napiErr.ThrowError(env, errorDesc::ONLY_PROXY_OBJECT_PERMITTED_ERROR);
}

static napi_value NAPI_RemoteObject_isObjectDead(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_boolean(env, false, &result);
    return result;
}

static napi_value NAPI_RemoteObject_Reclaim(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

EXTERN_C_START
/*
 * function for module exports
 */
napi_value NAPIRemoteObjectExport(napi_env env, napi_value exports)
{
    const std::string className = "RemoteObject";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("sendRequest", NAPI_RemoteObject_sendRequest),
        DECLARE_NAPI_FUNCTION("sendMessageRequest", NAPI_RemoteObject_sendMessageRequest),
        DECLARE_NAPI_FUNCTION("getCallingPid", NAPI_RemoteObject_getCallingPid),
        DECLARE_NAPI_FUNCTION("getCallingUid", NAPI_RemoteObject_getCallingUid),
        DECLARE_NAPI_FUNCTION("getInterfaceDescriptor", NAPI_RemoteObject_getInterfaceDescriptor),
        DECLARE_NAPI_FUNCTION("getDescriptor", NAPI_RemoteObject_getDescriptor),
        DECLARE_NAPI_FUNCTION("attachLocalInterface", NAPI_RemoteObject_attachLocalInterface),
        DECLARE_NAPI_FUNCTION("modifyLocalInterface", NAPI_RemoteObject_modifyLocalInterface),
        DECLARE_NAPI_FUNCTION("queryLocalInterface", NAPI_RemoteObject_queryLocalInterface),
        DECLARE_NAPI_FUNCTION("getLocalInterface", NAPI_RemoteObject_getLocalInterface),
        DECLARE_NAPI_FUNCTION("addDeathRecipient", NAPI_RemoteObject_addDeathRecipient),
        DECLARE_NAPI_FUNCTION("registerDeathRecipient", NAPI_RemoteObject_registerDeathRecipient),
        DECLARE_NAPI_FUNCTION("removeDeathRecipient", NAPI_RemoteObject_removeDeathRecipient),
        DECLARE_NAPI_FUNCTION("unregisterDeathRecipient", NAPI_RemoteObject_unregisterDeathRecipient),
        DECLARE_NAPI_FUNCTION("isObjectDead", NAPI_RemoteObject_isObjectDead),
        DECLARE_NAPI_FUNCTION("reclaim", NAPI_RemoteObject_Reclaim),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), RemoteObject_JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class RemoteObject failed");
    napi_status status = napi_set_named_property(env, exports, "RemoteObject", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property RemoteObject to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "IPCStubConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
    return exports;
}
EXTERN_C_END
} // namespace OHOS

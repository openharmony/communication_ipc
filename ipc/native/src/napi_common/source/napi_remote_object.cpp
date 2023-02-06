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

#include "napi_remote_object_internal.h"

#include <uv.h>
#include <string_ex.h>
#include <thread>
#include <hitrace_meter.h>

#include "iremote_invoker.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "napi_process_skeleton.h"
#include "napi_message_parcel.h"
#include "napi_message_sequence.h"
#include "napi_remote_object_holder.h"
#include "napi_remote_proxy_holder.h"
#include "napi_rpc_error.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "native_engine/native_value.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "napi_remoteObject" };

static const size_t ARGV_INDEX_0 = 0;
static const size_t ARGV_INDEX_1 = 1;
static const size_t ARGV_INDEX_2 = 2;
static const size_t ARGV_INDEX_3 = 3;
static const uint64_t HITRACE_TAG_RPC = (1ULL << 46); // RPC and IPC tag.

static std::atomic<int32_t> bytraceId = 1000;
static NapiError napiErr;

template<class T>
inline T *ConvertNativeValueTo(NativeValue *value)
{
    return (value != nullptr) ? static_cast<T *>(value->GetInterface(T::INTERFACE_ID)) : nullptr;
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
    if (curAttachCount == 0) {
        delete holder;
    }
}

static void *RemoteObjectDetachCb(NativeEngine *engine, void *value, void *hint)
{
    (void)engine;
    (void)hint;
    return value;
}

static NativeValue *RemoteObjectAttachCb(NativeEngine *engine, void *value, void *hint)
{
    (void)hint;
    NAPIRemoteObjectHolder *holder = reinterpret_cast<NAPIRemoteObjectHolder *>(value);
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "holder is nullptr when attach");
        return nullptr;
    }
    holder->Lock();
    ZLOGI(LOG_LABEL, "create js remote object when attach");
    napi_env env = reinterpret_cast<napi_env>(engine);
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
    napi_value argv[1] = { jsDesc };
    napi_value jsRemoteObject = nullptr;
    status = napi_new_instance(env, constructor, argc, argv, &jsRemoteObject);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteObject when attach");
    // retrieve and remove create holder
    NAPIRemoteObjectHolder *createHolder = nullptr;
    status = napi_remove_wrap(env, jsRemoteObject, (void **)&createHolder);
    NAPI_ASSERT(env, status == napi_ok && createHolder != nullptr, "failed to remove create holder when attach");
    status = napi_wrap(env, jsRemoteObject, holder, RemoteObjectHolderFinalizeCb, nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js RemoteObject and native holder failed when attach");
    holder->IncAttachCount();
    holder->Unlock();
    return reinterpret_cast<NativeValue *>(jsRemoteObject);
}

napi_value RemoteObject_JS_Constructor(napi_env env, napi_callback_info info)
{
    // new napi remote object
    size_t argc = 2;
    size_t expectedArgc = 1;
    napi_value argv[2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc >= expectedArgc, "requires at least 1 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, bufferSize + 1, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");
    std::string descriptor = stringValue;
    auto holder = new NAPIRemoteObjectHolder(env, Str8ToStr16(descriptor));
    auto nativeObj = ConvertNativeValueTo<NativeObject>(reinterpret_cast<NativeValue *>(thisVar));
    if (nativeObj == nullptr) {
        ZLOGE(LOG_LABEL, "Failed to get RemoteObject native object");
        delete holder;
        return nullptr;
    }
    nativeObj->ConvertToNativeBindingObject(env, RemoteObjectDetachCb, RemoteObjectAttachCb, holder, nullptr);
    // connect native object to js thisVar
    napi_status status = napi_wrap(env, thisVar, holder, RemoteObjectHolderFinalizeCb, nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js RemoteObject and native holder failed");
    if (NAPI_ohos_rpc_getNativeRemoteObject(env, thisVar) == nullptr) {
        ZLOGE(LOG_LABEL, "RemoteObject_JS_Constructor create native object failed");
        return nullptr;
    }
    return thisVar;
}

NAPIRemoteObject::NAPIRemoteObject(napi_env env, napi_value thisVar, const std::u16string &descriptor)
    : IPCObjectStub(descriptor)
{
    env_ = env;
    thisVar_ = thisVar;
    napi_create_reference(env, thisVar_, 1, &thisVarRef_);
    NAPI_ASSERT_RETURN_VOID(env, thisVarRef_ != nullptr, "failed to create ref to js RemoteObject");
}

NAPIRemoteObject::~NAPIRemoteObject()
{
    ZLOGI(LOG_LABEL, "NAPIRemoteObject Destructor");
    if (thisVarRef_ != nullptr) {
        napi_status status = napi_delete_reference(env_, thisVarRef_);
        NAPI_ASSERT_RETURN_VOID(env_, status == napi_ok, "failed to delete ref to js RemoteObject");
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
    ZLOGI(LOG_LABEL, "enter OnRemoteRequest");
    if (code == DUMP_TRANSACTION) {
        ZLOGE(LOG_LABEL, "DUMP_TRANSACTION data size:%zu", data.GetReadableBytes());
    }
    std::shared_ptr<struct ThreadLockInfo> lockInfo = std::make_shared<struct ThreadLockInfo>();
    CallbackParam *param = new CallbackParam {
        .env = env_,
        .thisVarRef = thisVarRef_,
        .code = code,
        .data = &data,
        .reply = &reply,
        .option = &option,
        .lockInfo = lockInfo.get(),
        .result = 0
    };

    NAPI_RemoteObject_getCallingInfo(param->callingInfo);
    ZLOGI(LOG_LABEL, "callingPid:%{public}u, callingUid:%{public}u,"
        "callingDeviceID:%{public}s, localDeviceId:%{public}s, localCalling:%{public}d",
        param->callingInfo.callingPid, param->callingInfo.callingUid,
        param->callingInfo.callingDeviceID.c_str(), param->callingInfo.localDeviceID.c_str(),
        param->callingInfo.isLocalCalling);
    int ret = OnJsRemoteRequest(param);
    ZLOGI(LOG_LABEL, "OnJsRemoteRequest done, ret:%{public}d", ret);
    return ret;
}

napi_value NAPIRemoteObject::ThenCallback(napi_env env, napi_callback_info info)
{
    ZLOGI(LOG_LABEL, "call js onRemoteRequest done");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    void* data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, nullptr, &data);
    CallbackParam *param = static_cast<CallbackParam *>(data);
    bool result = false;
    napi_get_value_bool(param->env, argv[0], &result);
    if (!result) {
        ZLOGE(LOG_LABEL, "OnRemoteRequest res:%{public}s", result ? "true" : "false");
        param->result = ERR_UNKNOWN_TRANSACTION;
    } else {
        param->result = ERR_NONE;
    }
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->ready = true;
    param->lockInfo->condition.notify_all();
    napi_value res;
    napi_get_undefined(env, &res);
    return res;
}

napi_value NAPIRemoteObject::CatchCallback(napi_env env, napi_callback_info info)
{
    ZLOGI(LOG_LABEL, "Async onReomteReuqest's returnVal is rejected");
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    void* data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, nullptr, &data);
    CallbackParam *param = static_cast<CallbackParam *>(data);
    param->result = ERR_UNKNOWN_TRANSACTION;
    std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
    param->lockInfo->ready = true;
    param->lockInfo->condition.notify_all();
    napi_value res;
    napi_get_undefined(env, &res);
    return res;
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
    napi_value newPid;
    napi_create_int32(env, static_cast<int32_t>(newCallingInfoParam.callingPid), &newPid);
    napi_set_named_property(env, global, "callingPid_", newPid);
    napi_value newUid;
    napi_create_int32(env, static_cast<int32_t>(newCallingInfoParam.callingUid), &newUid);
    napi_set_named_property(env, global, "callingUid_", newUid);
    napi_value newCallingTokenId;
    napi_create_uint32(env, newCallingInfoParam.callingTokenId, &newCallingTokenId);
    napi_set_named_property(env, global, "callingTokenId_", newCallingTokenId);
    napi_value newDeviceID;
    napi_create_string_utf8(env, newCallingInfoParam.callingDeviceID.c_str(), NAPI_AUTO_LENGTH, &newDeviceID);
    napi_set_named_property(env, global, "callingDeviceID_", newDeviceID);
    napi_value newLocalDeviceID;
    napi_create_string_utf8(env, newCallingInfoParam.localDeviceID.c_str(), NAPI_AUTO_LENGTH, &newLocalDeviceID);
    napi_set_named_property(env, global, "localDeviceID_", newLocalDeviceID);
    napi_value newIsLocalCalling;
    napi_get_boolean(env, newCallingInfoParam.isLocalCalling, &newIsLocalCalling);
    napi_set_named_property(env, global, "isLocalCalling_", newIsLocalCalling);
    napi_value newActiveStatus;
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
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);

    uv_work_t *work = new(std::nothrow) uv_work_t;
    if (work == nullptr) {
        ZLOGE(LOG_LABEL, "failed to new uv_work_t");
        delete jsParam;
        return -1;
    }
    work->data = reinterpret_cast<void *>(jsParam);
    ZLOGI(LOG_LABEL, "start nv queue work loop");
    uv_queue_work(loop, work, [](uv_work_t *work) {}, [](uv_work_t *work, int status) {
        ZLOGI(LOG_LABEL, "enter thread pool");
        CallbackParam *param = reinterpret_cast<CallbackParam *>(work->data);
        napi_value onRemoteRequest = nullptr;
        napi_value thisVar = nullptr;
        napi_get_reference_value(param->env, param->thisVarRef, &thisVar);
        if (thisVar == nullptr) {
            ZLOGE(LOG_LABEL, "thisVar is null");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_get_named_property(param->env, thisVar, "onRemoteMessageRequest", &onRemoteRequest);
        if (onRemoteRequest == nullptr) {
            ZLOGE(LOG_LABEL, "get founction onRemoteRequest failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_valuetype type = napi_undefined;
        napi_typeof(param->env, onRemoteRequest, &type);
        bool isOnRemoteMessageRequest = true;
        if (type != napi_function) {
            napi_get_named_property(param->env, thisVar, "onRemoteRequest", &onRemoteRequest);
            if (onRemoteRequest == nullptr) {
                ZLOGE(LOG_LABEL, "get founction onRemoteRequest failed");
                param->result = -1;
                std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
                param->lockInfo->ready = true;
                param->lockInfo->condition.notify_all();
                return;
            }
            isOnRemoteMessageRequest = false;
        }
        napi_value jsCode;
        napi_create_uint32(param->env, param->code, &jsCode);

        napi_value global = nullptr;
        napi_get_global(param->env, &global);
        if (global == nullptr) {
            ZLOGE(LOG_LABEL, "get napi global failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsOptionConstructor = nullptr;
        napi_get_named_property(param->env, global, "IPCOptionConstructor_", &jsOptionConstructor);
        if (jsOptionConstructor == nullptr) {
            ZLOGE(LOG_LABEL, "jsOption constructor is null");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsOption;
        size_t argc = 2;
        napi_value flags = nullptr;
        napi_create_int32(param->env, param->option->GetFlags(), &flags);
        napi_value waittime = nullptr;
        napi_create_int32(param->env, param->option->GetWaitTime(), &waittime);
        napi_value argv[2] = { flags, waittime };
        napi_new_instance(param->env, jsOptionConstructor, argc, argv, &jsOption);
        if (jsOption == nullptr) {
            ZLOGE(LOG_LABEL, "new jsOption failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsParcelConstructor = nullptr;
        if (isOnRemoteMessageRequest) {
            napi_get_named_property(param->env, global, "IPCSequenceConstructor_", &jsParcelConstructor);
        } else {
            napi_get_named_property(param->env, global, "IPCParcelConstructor_", &jsParcelConstructor);
        }
        if (jsParcelConstructor == nullptr) {
            ZLOGE(LOG_LABEL, "jsParcel constructor is null");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsData;
        napi_value dataParcel;
        napi_create_object(param->env, &dataParcel);
        napi_wrap(param->env, dataParcel, param->data,
            [](napi_env env, void *data, void *hint) {}, nullptr, nullptr);
        if (dataParcel == nullptr) {
            ZLOGE(LOG_LABEL, "create js object for data parcel address failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        size_t argc3 = 1;
        napi_value argv3[1] = { dataParcel };
        napi_new_instance(param->env, jsParcelConstructor, argc3, argv3, &jsData);
        if (jsData == nullptr) {
            ZLOGE(LOG_LABEL, "create js data parcel failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        napi_value jsReply;
        napi_value replyParcel;
        napi_create_object(param->env, &replyParcel);
        napi_wrap(param->env, replyParcel, param->reply,
            [](napi_env env, void *data, void *hint) {}, nullptr, nullptr);
        if (replyParcel == nullptr) {
            ZLOGE(LOG_LABEL, "create js object for reply parcel address failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        size_t argc4 = 1;
        napi_value argv4[1] = { replyParcel };
        napi_new_instance(param->env, jsParcelConstructor, argc4, argv4, &jsReply);
        if (jsReply == nullptr) {
            ZLOGE(LOG_LABEL, "create js reply parcel failed");
            param->result = -1;
            std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
            param->lockInfo->ready = true;
            param->lockInfo->condition.notify_all();
            return;
        }
        NAPI_CallingInfo oldCallingInfo;
        NAPI_RemoteObject_saveOldCallingInfo(param->env, oldCallingInfo);
        NAPI_RemoteObject_setNewCallingInfo(param->env, param->callingInfo);
        // start to call onRemoteRequest
        size_t argc2 = 4;
        napi_value argv2[] = { jsCode, jsData, jsReply, jsOption };
        napi_value returnVal;
        napi_status ret = napi_call_function(param->env, thisVar, onRemoteRequest, argc2, argv2, &returnVal);
        // Reset old calling pid, uid, device id
        NAPI_RemoteObject_resetOldCallingInfo(param->env, oldCallingInfo);

        do {
            if (ret != napi_ok) {
                ZLOGE(LOG_LABEL, "OnRemoteRequest got exception");
                param->result = ERR_UNKNOWN_TRANSACTION;
                break;
            }

            ZLOGD(LOG_LABEL, "call js onRemoteRequest done");
            // Check whether return_val is Promise
            bool returnIsPromise = false;//
            napi_is_promise(param->env, returnVal, &returnIsPromise);
            if (!returnIsPromise) {
                ZLOGD(LOG_LABEL, "onRemoteRequest is synchronous");
                bool result = false;
                napi_get_value_bool(param->env, returnVal, &result);
                if (!result) {
                    ZLOGE(LOG_LABEL, "OnRemoteRequest res:%{public}s", result ? "true" : "false");
                    param->result = ERR_UNKNOWN_TRANSACTION;
                } else {
                    param->result = ERR_NONE;
                }
                break;
            }

            ZLOGD(LOG_LABEL, "onRemoteRequest is asynchronous");
            // Create promiseThen
            napi_value promiseThen = nullptr;
            napi_get_named_property(param->env, returnVal, "then", &promiseThen);
            if (promiseThen == nullptr) {
                ZLOGE(LOG_LABEL, "get promiseThen failed");
                param->result = -1;
                break;
            }
            napi_value thenValue;
            ret = napi_create_function(param->env, "thenCallback", NAPI_AUTO_LENGTH, ThenCallback, param, &thenValue);
            if (ret != napi_ok) {
                ZLOGE(LOG_LABEL, "thenCallback got exception");
                param->result = ERR_UNKNOWN_TRANSACTION;
                break;
            }
            // Start to call promiseThen
            napi_value thenReturnValue;
            ret = napi_call_function(param->env, returnVal, promiseThen, 1, &thenValue, &thenReturnValue);
            if (ret != napi_ok) {
                ZLOGE(LOG_LABEL, "PromiseThen got exception");
                param->result = ERR_UNKNOWN_TRANSACTION;
                break;
            }
            // Create promiseCatch
            napi_value promiseCatch = nullptr;
            napi_get_named_property(param->env, returnVal, "catch", &promiseCatch);
            if (promiseCatch == nullptr) {
                ZLOGE(LOG_LABEL, "get promiseCatch failed");
                param->result = -1;
                break;
            }
            napi_value catchValue;
            ret = napi_create_function(param->env, "catchCallback",
                NAPI_AUTO_LENGTH, CatchCallback, param, &catchValue);
            if (ret != napi_ok) {
                ZLOGE(LOG_LABEL, "catchCallback got exception");
                param->result = ERR_UNKNOWN_TRANSACTION;
                break;
            }
            // Start to call promiseCatch
            napi_value catchReturnValue;
            ret = napi_call_function(param->env, returnVal, promiseCatch, 1, &catchValue, &catchReturnValue);
            if (ret != napi_ok) {
                ZLOGE(LOG_LABEL, "PromiseCatch got exception");
                param->result = ERR_UNKNOWN_TRANSACTION;
                break;
            }
            return;
        } while (0);

        std::unique_lock<std::mutex> lock(param->lockInfo->mutex);
        param->lockInfo->ready = true;
        param->lockInfo->condition.notify_all();
    });
    std::unique_lock<std::mutex> lock(jsParam->lockInfo->mutex);
    jsParam->lockInfo->condition.wait(lock, [&jsParam] { return jsParam->lockInfo->ready; });
    int ret = jsParam->result;
    delete jsParam;
    delete work;
    return ret;
}

napi_value NAPI_ohos_rpc_CreateJsRemoteObject(napi_env env, const sptr<IRemoteObject> target)
{
    if (target == nullptr) {
        ZLOGE(LOG_LABEL, "RemoteObject is null");
        return nullptr;
    }

    if (target->CheckObjectLegality()) {
        IPCObjectStub *tmp = static_cast<IPCObjectStub *>(target.GetRefPtr());
        ZLOGI(LOG_LABEL, "object type:%{public}d", tmp->GetObjectType());
        if (tmp->GetObjectType() == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT) {
            ZLOGI(LOG_LABEL, "napi create js remote object");
            sptr<NAPIRemoteObject> object = static_cast<NAPIRemoteObject *>(target.GetRefPtr());
            // retrieve js remote object constructor
            napi_value global = nullptr;
            napi_status status = napi_get_global(env, &global);
            NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
            napi_value constructor = nullptr;
            status = napi_get_named_property(env, global, "IPCStubConstructor_", &constructor);
            NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
            NAPI_ASSERT(env, constructor != nullptr, "failed to get js RemoteObject constructor");
            // retrieve descriptor and it's length
            std::u16string descriptor = object->GetObjectDescriptor();
            std::string desc = Str16ToStr8(descriptor);
            napi_value jsDesc = nullptr;
            napi_create_string_utf8(env, desc.c_str(), desc.length(), &jsDesc);
            // create a new js remote object
            size_t argc = 1;
            napi_value argv[1] = { jsDesc };
            napi_value jsRemoteObject = nullptr;
            status = napi_new_instance(env, constructor, argc, argv, &jsRemoteObject);
            NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteObject");
            // retrieve holder and set object
            NAPIRemoteObjectHolder *holder = nullptr;
            napi_unwrap(env, jsRemoteObject, (void **)&holder);
            NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
            holder->Set(object);
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
    proxyHolder->object_ = target;
    proxyHolder->list_ = new NAPIDeathRecipientList();

    return jsRemoteProxy;
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
            return holder != nullptr ? holder->Get(object) : nullptr;
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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 1 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, bufferSize + 1, &jsStringLength);
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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &bufferSize);
    if (bufferSize >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, bufferSize + 1, &jsStringLength);
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
    param->errCode = param->target->SendRequest(param->code,
        *(param->data.get()), *(param->reply.get()), param->option);
    ZLOGI(LOG_LABEL, "sendRequest done, errCode:%{public}d", param->errCode);
    if (param->traceId != 0) {
        FinishAsyncTrace(HITRACE_TAG_RPC, (param->traceValue).c_str(), param->traceId);
    }
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    uv_work_t *work = new uv_work_t;
    work->data = reinterpret_cast<void *>(param);
    uv_after_work_cb afterWorkCb = nullptr;
    if (param->callback != nullptr) {
        afterWorkCb = [](uv_work_t *work, int status) {
            ZLOGI(LOG_LABEL, "callback started");
            SendRequestParam *param = reinterpret_cast<SendRequestParam *>(work->data);
            napi_value result = MakeSendRequestResult(param);
            napi_value callback = nullptr;
            napi_get_reference_value(param->env, param->callback, &callback);
            napi_value cbResult = nullptr;
            napi_call_function(param->env, nullptr, callback, 1, &result, &cbResult);
            napi_delete_reference(param->env, param->jsCodeRef);
            napi_delete_reference(param->env, param->jsDataRef);
            napi_delete_reference(param->env, param->jsReplyRef);
            napi_delete_reference(param->env, param->callback);
            delete param;
            delete work;
        };
    } else {
        afterWorkCb = [](uv_work_t *work, int status) {
            ZLOGI(LOG_LABEL, "promise fullfilled");
            SendRequestParam *param = reinterpret_cast<SendRequestParam *>(work->data);
            napi_value result = MakeSendRequestResult(param);
            if (param->errCode == 0) {
                napi_resolve_deferred(param->env, param->deferred, result);
            } else {
                napi_reject_deferred(param->env, param->deferred, result);
            }
            napi_delete_reference(param->env, param->jsCodeRef);
            napi_delete_reference(param->env, param->jsDataRef);
            napi_delete_reference(param->env, param->jsReplyRef);
            delete param;
            delete work;
        };
    }
    uv_queue_work(loop, work, [](uv_work_t *work) {}, afterWorkCb);
}

napi_value StubSendRequestAsync(napi_env env, sptr<IRemoteObject> target, uint32_t code,
    std::shared_ptr<MessageParcel> data, std::shared_ptr<MessageParcel> reply,
    MessageOption &option, napi_value *argv)
{
    SendRequestParam *sendRequestParam = new SendRequestParam {
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
        .callback = nullptr,
        .env = env,
        .traceId = 0,
    };
    if (target != nullptr) {
        std::string remoteDescriptor = Str16ToStr8(target->GetObjectDescriptor());
        if (!remoteDescriptor.empty()) {
            sendRequestParam->traceValue = remoteDescriptor + std::to_string(code);
            sendRequestParam->traceId = bytraceId.fetch_add(1, std::memory_order_seq_cst);
            StartAsyncTrace(HITRACE_TAG_RPC, (sendRequestParam->traceValue).c_str(), sendRequestParam->traceId);
        }
    }
    napi_create_reference(env, argv[0], 1, &sendRequestParam->jsCodeRef);
    napi_create_reference(env, argv[1], 1, &sendRequestParam->jsDataRef);
    napi_create_reference(env, argv[2], 1, &sendRequestParam->jsReplyRef);
    napi_create_reference(env, argv[4], 1, &sendRequestParam->callback);
    std::thread t(StubExecuteSendRequest, env, sendRequestParam);
    t.detach();
    napi_value result = nullptr;
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
    SendRequestParam *sendRequestParam = new SendRequestParam {
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
        .callback = nullptr,
        .env = env,
        .traceId = 0,
    };
    if (target != nullptr) {
        std::string remoteDescriptor = Str16ToStr8(target->GetObjectDescriptor());
        if (!remoteDescriptor.empty()) {
            sendRequestParam->traceValue = remoteDescriptor + std::to_string(code);
            sendRequestParam->traceId = bytraceId.fetch_add(1, std::memory_order_seq_cst);
            StartAsyncTrace(HITRACE_TAG_RPC, (sendRequestParam->traceValue).c_str(), sendRequestParam->traceId);
        }
    }
    napi_create_reference(env, argv[0], 1, &sendRequestParam->jsCodeRef);
    napi_create_reference(env, argv[1], 1, &sendRequestParam->jsDataRef);
    napi_create_reference(env, argv[2], 1, &sendRequestParam->jsReplyRef);
    std::thread t(StubExecuteSendRequest, env, sendRequestParam);
    t.detach();
    return promise;
}

static napi_value NAPI_RemoteObject_sendRequest(napi_env env, napi_callback_info info)
{
    size_t argc = 4;
    size_t argcCallback = 5;
    size_t argcPromise = 4;
    napi_value argv[5] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == argcPromise || argc == argcCallback, "requires 4 or 5 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 2");
    napi_typeof(env, argv[2], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 3");
    napi_typeof(env, argv[3], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 4");

    NAPI_MessageParcel *data = nullptr;
    napi_status status = napi_unwrap(env, argv[1], (void **)&data);
    NAPI_ASSERT(env, status == napi_ok, "failed to get data message parcel");
    NAPI_MessageParcel *reply = nullptr;
    status = napi_unwrap(env, argv[2], (void **)&reply);
    NAPI_ASSERT(env, status == napi_ok, "failed to get reply message parcel");
    MessageOption *option = nullptr;
    status = napi_unwrap(env, argv[3], (void **)&option);
    NAPI_ASSERT(env, status == napi_ok, "failed to get message option");
    int32_t code = 0;
    napi_get_value_int32(env, argv[0], &code);

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
    napi_value argv[5] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = NAPI_RemoteObject_checkSendMessageRequestArgs(env, argc, argcCallback, argcPromise,
                                                                               argv);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }
    NAPI_MessageSequence *data = nullptr;
    napi_status status = napi_unwrap(env, argv[1], (void **)&data);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get data message sequence");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    NAPI_MessageSequence *reply = nullptr;
    status = napi_unwrap(env, argv[2], (void **)&reply);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get data message sequence");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    MessageOption *option = nullptr;
    status = napi_unwrap(env, argv[3], (void **)&option);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get message option");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t code = 0;
    napi_get_value_int32(env, argv[0], &code);

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
    napi_value argv[2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 1");
    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 2");
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[1], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[1], stringValue, bufferSize + 1, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");
    std::string descriptor = stringValue;

    NAPIRemoteObjectHolder *holder = nullptr;
    napi_unwrap(env, thisVar, (void* *)&holder);
    NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
    holder->attachLocalInterface(argv[0], descriptor);

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
    napi_value argv[2] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = NAPI_RemoteObject_checkModifyLocalInterfaceArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }
    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[1], nullptr, 0, &bufferSize);
    if (bufferSize >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[1], stringValue, bufferSize + 1, &jsStringLength);
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
    holder->attachLocalInterface(argv[0], descriptor);

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

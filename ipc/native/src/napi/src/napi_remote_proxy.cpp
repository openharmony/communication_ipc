/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <hilog/log.h>
#include <hitrace_meter.h>
#include <string_ex.h>

#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "napi_message_parcel.h"
#include "napi_message_sequence.h"
#include "napi_remote_proxy_holder.h"
#include "napi_remote_object_internal.h"
#include "napi_rpc_error.h"


static std::atomic<int32_t> bytraceId = 1000;
namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "napi_remoteObject" };

static const uint64_t HITRACE_TAG_RPC = (1ULL << 46); // RPC and IPC tag.

static NapiError napiErr;

static const size_t ARGV_INDEX_0 = 0;
static const size_t ARGV_INDEX_1 = 1;
static const size_t ARGV_INDEX_2 = 2;
static const size_t ARGV_INDEX_3 = 3;
static const size_t ARGV_INDEX_4 = 4;

static const size_t ARGV_LENGTH_2 = 2;
static const size_t ARGV_LENGTH_5 = 5;
void ExecuteSendRequest(napi_env env, void *data)
{
    SendRequestParam *param = reinterpret_cast<SendRequestParam *>(data);
    param->errCode = param->target->SendRequest(param->code,
        *(param->data.get()), *(param->reply.get()), param->option);
    ZLOGD(LOG_LABEL, "sendRequest done, errCode:%{public}d", param->errCode);
    if (param->traceId != 0) {
        FinishAsyncTrace(HITRACE_TAG_RPC, (param->traceValue).c_str(), param->traceId);
    }
}

// This method runs on the main thread after 'ExecuteSendRequest' exits
void SendRequestCbComplete(napi_env env, napi_status status, void *data)
{
    SendRequestParam *param = reinterpret_cast<SendRequestParam *>(data);
    ZLOGI(LOG_LABEL, "sendRequestCallback completed, errCode:%{public}d", param->errCode);
    napi_value result = MakeSendRequestResult(param);
    napi_value callback = nullptr;
    napi_get_reference_value(env, param->callback, &callback);
    napi_value cbResult = nullptr;
    napi_call_function(env, nullptr, callback, 1, &result, &cbResult);
    napi_delete_reference(env, param->jsCodeRef);
    napi_delete_reference(env, param->jsDataRef);
    napi_delete_reference(env, param->jsReplyRef);
    napi_delete_reference(env, param->jsOptionRef);
    napi_delete_reference(env, param->callback);
    napi_delete_async_work(env, param->asyncWork);
    delete param;
}

// This method runs on the main thread after 'ExecuteSendRequest' exits
void SendRequestPromiseComplete(napi_env env, napi_status status, void *data)
{
    SendRequestParam *param = reinterpret_cast<SendRequestParam *>(data);
    ZLOGD(LOG_LABEL, "sendRequestPromise completed, errCode:%{public}d", param->errCode);
    napi_value result = MakeSendRequestResult(param);
    if (param->errCode == 0) {
        napi_resolve_deferred(env, param->deferred, result);
    } else {
        napi_reject_deferred(env, param->deferred, result);
    }
    napi_delete_reference(env, param->jsCodeRef);
    napi_delete_reference(env, param->jsDataRef);
    napi_delete_reference(env, param->jsReplyRef);
    napi_delete_reference(env, param->jsOptionRef);
    napi_delete_async_work(env, param->asyncWork);
    delete param;
}

napi_value SendRequestAsync(napi_env env, sptr<IRemoteObject> target, uint32_t code,
    std::shared_ptr<MessageParcel> data, std::shared_ptr<MessageParcel> reply,
    MessageOption &option, napi_value *argv)
{
    napi_value result = nullptr;
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
        .jsOptionRef = nullptr,
        .callback = nullptr,
        .env = env,
        .traceId = 0,
    };
    IPCObjectProxy *targetProxy = reinterpret_cast<IPCObjectProxy *>(target.GetRefPtr());
    if (targetProxy != nullptr) {
        std::string remoteDescriptor = Str16ToStr8(targetProxy->GetInterfaceDescriptor());
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
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, ExecuteSendRequest,
        SendRequestCbComplete, reinterpret_cast<void *>(sendRequestParam), &sendRequestParam->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, sendRequestParam->asyncWork));
    napi_get_undefined(env, &result);
    return result;
}

napi_value SendRequestPromise(napi_env env, sptr<IRemoteObject> target, uint32_t code,
    std::shared_ptr<MessageParcel> data, std::shared_ptr<MessageParcel> reply,
    MessageOption &option, napi_value *argv)
{
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);
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
        .jsOptionRef = nullptr,
        .callback = nullptr,
        .env = env,
        .traceId = 0,
    };
    IPCObjectProxy *targetProxy = reinterpret_cast<IPCObjectProxy *>(target.GetRefPtr());
    if (targetProxy != nullptr) {
        std::string remoteDescriptor = Str16ToStr8(targetProxy->GetInterfaceDescriptor());
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
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, ExecuteSendRequest,
        SendRequestPromiseComplete, (void *)sendRequestParam, &sendRequestParam->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, sendRequestParam->asyncWork));
    return promise;
}

napi_value NAPI_RemoteProxy_sendRequest(napi_env env, napi_callback_info info)
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
    napi_status status = napi_unwrap(env, argv[ARGV_INDEX_1], reinterpret_cast<void **>(&data));
    NAPI_ASSERT(env, status == napi_ok, "failed to get data message parcel");
    NAPI_MessageParcel *reply = nullptr;
    status = napi_unwrap(env, argv[ARGV_INDEX_2], reinterpret_cast<void **>(&reply));
    NAPI_ASSERT(env, status == napi_ok, "failed to get reply message parcel");
    MessageOption *option = nullptr;
    status = napi_unwrap(env, argv[ARGV_INDEX_3], reinterpret_cast<void **>(&option));
    NAPI_ASSERT(env, status == napi_ok, "failed to get message option");
    int32_t code = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &code);

    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&proxyHolder));
    NAPI_ASSERT(env, proxyHolder != nullptr, "failed to get proxy holder");
    sptr<IRemoteObject> target = proxyHolder->object_;
    NAPI_ASSERT(env, target != nullptr, "invalid proxy object");
    if (argc == argcCallback) {
        napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[argcPromise], &valuetype);
        if (valuetype == napi_function) {
            return SendRequestAsync(env, target, code, data->GetMessageParcel(),
                reply->GetMessageParcel(), *option, argv);
        }
    }
    return SendRequestPromise(env, target, code, data->GetMessageParcel(),
        reply->GetMessageParcel(), *option, argv);
}

napi_value NAPI_RemoteProxy_checkSendMessageRequestArgs(napi_env env,
                                                        napi_value* argv,
                                                        NAPI_MessageSequence* &data,
                                                        NAPI_MessageSequence* &reply,
                                                        MessageOption* &option)
{
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

    napi_status status = napi_unwrap(env, argv[ARGV_INDEX_1], reinterpret_cast<void **>(&data));
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get data message parcel");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    status = napi_unwrap(env, argv[ARGV_INDEX_2], reinterpret_cast<void **>(&reply));
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get reply message parcel");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    status = napi_unwrap(env, argv[ARGV_INDEX_3], reinterpret_cast<void **>(&option));
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get message option");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_RemoteProxy_sendMessageRequest(napi_env env, napi_callback_info info)
{
    size_t argc = 4;
    size_t argcCallback = 5;
    size_t argcPromise = 4;
    napi_value argv[ARGV_LENGTH_5] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != argcPromise && argc != argcCallback) {
        ZLOGE(LOG_LABEL, "requires 4 or 5 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    NAPI_MessageSequence *data = nullptr;
    NAPI_MessageSequence *reply = nullptr;
    MessageOption *option = nullptr;
    napi_value checkArgsResult = NAPI_RemoteProxy_checkSendMessageRequestArgs(env, argv, data, reply, option);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }
    int32_t code = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &code);

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&proxyHolder));
    if (proxyHolder == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get proxy holder");
        return result;
    }
    sptr<IRemoteObject> target = proxyHolder->object_;
    if (target == nullptr) {
        ZLOGE(LOG_LABEL, "invalid proxy object");
        return result;
    }
    if (argc == argcCallback) {
        napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[argcPromise], &valuetype);
        if (valuetype == napi_function) {
            return SendRequestAsync(env, target, code, data->GetMessageParcel(),
                reply->GetMessageParcel(), *option, argv);
        }
    }
    return SendRequestPromise(env, target, code, data->GetMessageParcel(),
        reply->GetMessageParcel(), *option, argv);
}

napi_value NAPI_RemoteProxy_queryLocalInterface(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value NAPI_RemoteProxy_getLocalInterface(napi_env env, napi_callback_info info)
{
    ZLOGE(LOG_LABEL, "only remote object permitted");
    return napiErr.ThrowError(env, errorDesc::ONLY_REMOTE_OBJECT_PERMITTED_ERROR);
}

napi_value NAPI_RemoteProxy_addDeathRecipient(napi_env env, napi_callback_info info)
{
    ZLOGI(LOG_LABEL, "add death recipient");
    size_t argc = 2;
    size_t expectedArgc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 1");
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    int32_t flag = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &flag);

    napi_value result;
    if (argv[ARGV_INDEX_0] == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }

    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&proxyHolder));
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    if (proxyHolder == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }
    sptr<IRemoteObject> target = proxyHolder->object_;
    if ((target == nullptr) || !target->IsProxyObject()) {
        ZLOGE(LOG_LABEL, "could not add recipient from invalid target");
        napi_get_boolean(env, false, &result);
        return result;
    }

    sptr<NAPIDeathRecipient> nativeRecipient = new NAPIDeathRecipient(env, argv[ARGV_INDEX_0]);
    if (target->AddDeathRecipient(nativeRecipient)) {
        NAPIDeathRecipientList *list = proxyHolder->list_;
        if (list->Add(nativeRecipient)) {
            napi_get_boolean(env, true, &result);
            return result;
        }
    }
    napi_get_boolean(env, false, &result);
    return result;
}

napi_value NAPI_RemoteProxy_checkRegisterDeathRecipientArgs(napi_env env, size_t argc, napi_value* argv)
{
    size_t expectedArgc = 2;

    if (argc != expectedArgc) {
        ZLOGE(LOG_LABEL, "requires 2 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_RemoteProxy_registerDeathRecipient(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    napi_value checkArgsResult = NAPI_RemoteProxy_checkRegisterDeathRecipientArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }
    int32_t flag = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &flag);

    if (argv[ARGV_INDEX_0] == nullptr) {
        ZLOGE(LOG_LABEL, "invalid parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&proxyHolder));
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get proxy holder");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    if (proxyHolder == nullptr) {
        ZLOGE(LOG_LABEL, "proxy holder is nullptr");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    sptr<IRemoteObject> target = proxyHolder->object_;
    if ((target == nullptr) || !target->IsProxyObject()) {
        ZLOGE(LOG_LABEL, "could not add recipient from invalid target");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }

    sptr<NAPIDeathRecipient> nativeRecipient = new NAPIDeathRecipient(env, argv[ARGV_INDEX_0]);
    bool ret = target->AddDeathRecipient(nativeRecipient);
    if (ret) {
        NAPIDeathRecipientList *list = proxyHolder->list_;
        list->Add(nativeRecipient);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    ZLOGI(LOG_LABEL, "%{public}s", ret ? "succ" : "fail");
    return result;
}

napi_value NAPI_RemoteProxy_removeDeathRecipient(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    size_t expectedArgc = 2;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "type mismatch for parameter 1");
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    napi_value result;
    if (argv[ARGV_INDEX_0] == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }
    int32_t flag = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &flag);

    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&proxyHolder));
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    if (proxyHolder == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }
    sptr<IRemoteObject> target = proxyHolder->object_;
    if ((target == nullptr) || !target->IsProxyObject()) {
        ZLOGE(LOG_LABEL, "could not remove recipient from invalid target");
        napi_get_boolean(env, false, &result);
        return result;
    }
    sptr<NAPIDeathRecipientList> list = proxyHolder->list_;
    sptr<NAPIDeathRecipient> nativeRecipient = list->Find(argv[ARGV_INDEX_0]);
    if (nativeRecipient == nullptr) {
        ZLOGE(LOG_LABEL, "recipient not found");
        napi_get_boolean(env, false, &result);
        return result;
    }
    bool ret = target->RemoveDeathRecipient(nativeRecipient);
    if (list->Remove(nativeRecipient)) {
        napi_get_boolean(env, true, &result);
    } else {
        napi_get_boolean(env, false, &result);
    }
    ZLOGI(LOG_LABEL, "%{public}s", ret ? "succ" : "fail");
    return result;
}

napi_value NAPI_RemoteProxy_checkUnregisterDeathRecipientArgs(napi_env env, size_t argc, napi_value* argv)
{
    size_t expectedArgc = 2;
    if (argc != expectedArgc) {
        ZLOGE(LOG_LABEL, "requires 2 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    if (argv[ARGV_INDEX_0] == nullptr) {
        ZLOGE(LOG_LABEL, "invalid parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_RemoteProxy_unregisterDeathRecipient(napi_env env, napi_callback_info info)
{
    ZLOGI(LOG_LABEL, "unregister death recipient");
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    napi_value checkArgsResult = NAPI_RemoteProxy_checkUnregisterDeathRecipientArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }
    int32_t flag = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &flag);

    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&proxyHolder));
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get proxy holder");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    if (proxyHolder == nullptr) {
        ZLOGE(LOG_LABEL, "proxy holder is nullptr");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    sptr<IRemoteObject> target = proxyHolder->object_;
    if ((target == nullptr) || !target->IsProxyObject()) {
        ZLOGE(LOG_LABEL, "could not remove recipient from invalid target");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    sptr<NAPIDeathRecipientList> list = proxyHolder->list_;
    sptr<NAPIDeathRecipient> nativeRecipient = list->Find(argv[ARGV_INDEX_0]);
    if (nativeRecipient == nullptr) {
        ZLOGE(LOG_LABEL, "recipient not found");
        return result;
    }
    target->RemoveDeathRecipient(nativeRecipient);
    if (list->Remove(nativeRecipient)) {
        ZLOGD(LOG_LABEL, "remove recipient from list success");
        return result;
    } else {
        ZLOGE(LOG_LABEL, "remove recipient from list failed");
        return result;
    }
}

napi_value NAPI_RemoteProxy_getInterfaceDescriptor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIRemoteProxyHolder *holder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    napi_value result;
    if (holder == nullptr) {
        napi_create_string_utf8(env, "", 0, &result);
        return result;
    }
    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        ZLOGE(LOG_LABEL, "Invalid proxy object");
        napi_create_string_utf8(env, "", 0, &result);
        return result;
    }
    std::u16string remoteDescriptor = target->GetInterfaceDescriptor();
    napi_create_string_utf8(env, Str16ToStr8(remoteDescriptor).c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value NAPI_RemoteProxy_getDescriptor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIRemoteProxyHolder *holder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to get proxy holder");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    napi_value result;
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "proxy holder is nullptr");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        ZLOGE(LOG_LABEL, "proxy object is nullptr");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    std::u16string remoteDescriptor = target->GetInterfaceDescriptor();
    if (remoteDescriptor == std::u16string()) {
        ZLOGE(LOG_LABEL, "failed to get interface descriptor");
        return napiErr.ThrowError(env, errorDesc::COMMUNICATION_ERROR);
    }
    napi_create_string_utf8(env, Str16ToStr8(remoteDescriptor).c_str(), NAPI_AUTO_LENGTH, &result);
    return result;
}

napi_value NAPI_RemoteProxy_isObjectDead(napi_env env, napi_callback_info info)
{
    ZLOGD(LOG_LABEL, "call isObjectDead");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIRemoteProxyHolder *holder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    NAPI_ASSERT(env, status == napi_ok, "failed to get proxy holder");
    napi_value result;
    if (holder == nullptr) {
        napi_get_boolean(env, false, &result);
        return result;
    }
    IPCObjectProxy *target = reinterpret_cast<IPCObjectProxy *>(holder->object_.GetRefPtr());
    if (target == nullptr) {
        ZLOGE(LOG_LABEL, "Invalid proxy object");
        napi_get_boolean(env, false, &result);
        return result;
    }

    if (target->IsObjectDead()) {
        napi_get_boolean(env, true, &result);
        return result;
    } else {
        napi_get_boolean(env, false, &result);
        return result;
    }
}

napi_value RemoteProxy_JS_Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    // new napi proxy holder instance
    auto proxyHolder = new NAPIRemoteProxyHolder();
    // connect native object to js thisVar
    napi_status status = napi_wrap(
        env, thisVar, proxyHolder,
        [](napi_env env, void *data, void *hint) {
            ZLOGD(LOG_LABEL, "proxy holder destructed by js callback");
            delete (reinterpret_cast<NAPIRemoteProxyHolder *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js RemoteProxy and native holder failed");
    return thisVar;
}

EXTERN_C_START
/*
 * function for module exports
 */
napi_value NAPIRemoteProxyExport(napi_env env, napi_value exports)
{
    const std::string className = "RemoteProxy";
    napi_value pingTransaction = nullptr;
    napi_create_int32(env, PING_TRANSACTION, &pingTransaction);
    napi_value dumpTransaction = nullptr;
    napi_create_int32(env, DUMP_TRANSACTION, &dumpTransaction);
    napi_value interfaceTransaction = nullptr;
    napi_create_int32(env, INTERFACE_TRANSACTION, &interfaceTransaction);
    napi_value minTransactionId = nullptr;
    napi_create_int32(env, MIN_TRANSACTION_ID, &minTransactionId);
    napi_value maxTransactionId = nullptr;
    napi_create_int32(env, MAX_TRANSACTION_ID, &maxTransactionId);
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("queryLocalInterface", NAPI_RemoteProxy_queryLocalInterface),
        DECLARE_NAPI_FUNCTION("getLocalInterface", NAPI_RemoteProxy_getLocalInterface),
        DECLARE_NAPI_FUNCTION("addDeathRecipient", NAPI_RemoteProxy_addDeathRecipient),
        DECLARE_NAPI_FUNCTION("registerDeathRecipient", NAPI_RemoteProxy_registerDeathRecipient),
        DECLARE_NAPI_FUNCTION("removeDeathRecipient", NAPI_RemoteProxy_removeDeathRecipient),
        DECLARE_NAPI_FUNCTION("unregisterDeathRecipient", NAPI_RemoteProxy_unregisterDeathRecipient),
        DECLARE_NAPI_FUNCTION("getInterfaceDescriptor", NAPI_RemoteProxy_getInterfaceDescriptor),
        DECLARE_NAPI_FUNCTION("getDescriptor", NAPI_RemoteProxy_getDescriptor),
        DECLARE_NAPI_FUNCTION("sendRequest", NAPI_RemoteProxy_sendRequest),
        DECLARE_NAPI_FUNCTION("sendMessageRequest", NAPI_RemoteProxy_sendMessageRequest),
        DECLARE_NAPI_FUNCTION("isObjectDead", NAPI_RemoteProxy_isObjectDead),
        DECLARE_NAPI_STATIC_PROPERTY("PING_TRANSACTION", pingTransaction),
        DECLARE_NAPI_STATIC_PROPERTY("DUMP_TRANSACTION", dumpTransaction),
        DECLARE_NAPI_STATIC_PROPERTY("INTERFACE_TRANSACTION", interfaceTransaction),
        DECLARE_NAPI_STATIC_PROPERTY("MIN_TRANSACTION_ID", minTransactionId),
        DECLARE_NAPI_STATIC_PROPERTY("MAX_TRANSACTION_ID", maxTransactionId),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), RemoteProxy_JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class RemoteProxy failed");
    napi_status status = napi_set_named_property(env, exports, "RemoteProxy", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property RemoteProxy to exports failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "IPCProxyConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set proxy constructor failed");
    return exports;
}
EXTERN_C_END
} // namespace OHOS
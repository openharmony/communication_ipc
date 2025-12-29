/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
     NAPI_ASSERT(env, sendRequestParam != nullptr, "new sendRequestParam failed");
     std::string remoteDescriptor = Str16ToStr8(target->GetObjectDescriptor());
     if (!remoteDescriptor.empty()) {
         sendRequestParam->traceValue = remoteDescriptor + std::to_string(code);
         sendRequestParam->traceId = bytraceId.fetch_add(1, std::memory_order_seq_cst);
         StartAsyncTrace(HITRACE_TAG_RPC, (sendRequestParam->traceValue).c_str(), sendRequestParam->traceId);
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
     NAPI_ASSERT(env, sendRequestParam != nullptr, "new sendRequestParam failed");
     std::string remoteDescriptor = Str16ToStr8(target->GetObjectDescriptor());
     if (!remoteDescriptor.empty()) {
         sendRequestParam->traceValue = remoteDescriptor + std::to_string(code);
         sendRequestParam->traceId = bytraceId.fetch_add(1, std::memory_order_seq_cst);
         StartAsyncTrace(HITRACE_TAG_RPC, (sendRequestParam->traceValue).c_str(), sendRequestParam->traceId);
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
     ZLOGD(LOG_LABEL, "only remote object permitted");
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
 
     sptr<NAPIDeathRecipient> nativeRecipient = new (std::nothrow) NAPIDeathRecipient(env, argv[ARGV_INDEX_0]);
     NAPI_ASSERT(env, nativeRecipient != nullptr, "new NAPIDeathRecipient failed");
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
 
     napi_value result = nullptr;
     napi_get_undefined(env, &result);
     sptr<NAPIDeathRecipient> nativeRecipient = new (std::nothrow) NAPIDeathRecipient(env, argv[ARGV_INDEX_0]);
     NAPI_ASSERT(env, nativeRecipient != nullptr, "new NAPIDeathRecipient failed");
     bool ret = target->AddDeathRecipient(nativeRecipient);
     if (ret) {
         NAPIDeathRecipientList *list = proxyHolder->list_;
         list->Add(nativeRecipient);
     } else {
         ZLOGE(LOG_LABEL, "register death recipent failed");
     }
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
     if (!list->Remove(nativeRecipient)) {
         ZLOGE(LOG_LABEL, "unregister death recipent failed");
     }
     return result;
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
     sptr<IRemoteObject> target = holder->object_;
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
     sptr<IRemoteObject> target = holder->object_;
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
     sptr<IRemoteObject> target = holder->object_;
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
 
 napi_value NAPI_RemoteProxy_Reclaim(napi_env env, napi_callback_info info)
 {
     napi_value thisVar = nullptr;
     napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
 
     napi_value result = nullptr;
     napi_get_undefined(env, &result);
     NAPIRemoteProxyHolder *proxyHolder = nullptr;
     napi_unwrap(env, thisVar, reinterpret_cast<void **>(&proxyHolder));
     if (proxyHolder == nullptr) {
         ZLOGE(LOG_LABEL, "failed to get proxy holder");
         return result;
     }
 
     ZLOGI(LOG_LABEL, "remoteProxy reclaim");
     proxyHolder->object_ = nullptr;
     return result;
 }
 
 napi_value RemoteProxy_JS_Constructor(napi_env env, napi_callback_info info)
 {
     napi_value thisVar = nullptr;
     napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
     // new napi proxy holder instance
     auto proxyHolder = new (std::nothrow) NAPIRemoteProxyHolder();
     NAPI_ASSERT(env, proxyHolder != nullptr, "new NAPIRemoteProxyHolder failed");
     // connect native object to js thisVar
     napi_status status = napi_wrap(
         env, thisVar, proxyHolder,
         [](napi_env env, void *data, void *hint) {
             ZLOGD(LOG_LABEL, "proxy holder destructed by js callback");
             delete (reinterpret_cast<NAPIRemoteProxyHolder *>(data));
         },
         nullptr, nullptr);
     if (status != napi_ok) {
         delete proxyHolder;
         NAPI_ASSERT(env, false, "wrap js RemoteProxy and native holder failed");
     }
     return thisVar;
 }
 
 ::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt32ArrayBuffer()
{
    std::vector<uint32_t> uint32Vector;
    if (!nativeParcel_->ReadUInt32Vector(&uint32Vector)) {
        ZLOGE(LOG_LABEL, "read uint32Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(uint32Vector.data());
    size_t byteLength = uint32Vector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadFloatArrayBuffer()
{
    std::vector<float> floatVector;
    if (!nativeParcel_->ReadFloatVector(&floatVector)) {
        ZLOGE(LOG_LABEL, "read floatVector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(floatVector.data());
    size_t byteLength = floatVector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadDoubleArrayBuffer()
{
    std::vector<double> doubleVector;
    if (!nativeParcel_->ReadDoubleVector(&doubleVector)) {
        ZLOGE(LOG_LABEL, "read doubleVector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(doubleVector.data());
    size_t byteLength = doubleVector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt64ArrayBuffer()
{
    std::vector<int64_t> int64Vector;
    if (!nativeParcel_->ReadInt64Vector(&int64Vector)) {
        ZLOGE(LOG_LABEL, "read int64Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int64Vector.data());
    size_t byteLength = int64Vector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt64ArrayBuffer()
{
    std::vector<uint64_t> uint64Vector;
    if (!nativeParcel_->ReadUInt64Vector(&uint64Vector)) {
        ZLOGE(LOG_LABEL, "read uint64Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(uint64Vector.data());
    size_t byteLength = uint64Vector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

int32_t MessageSequenceImpl::GetSize()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetDataSize());
    return result;
}

int32_t MessageSequenceImpl::GetWritableBytes()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetWritableBytes());
    return result;
}

int32_t MessageSequenceImpl::GetReadableBytes()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetReadableBytes());
    return result;
}

int32_t MessageSequenceImpl::GetReadPosition()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetReadPosition());
    return result;
}

int32_t MessageSequenceImpl::GetWritePosition()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetWritePosition());
    return result;
}

bool MessageSequenceImpl::ContainFileDescriptors()
{
    bool result = nativeParcel_->ContainFileDescriptors();
    return result;
}

int32_t MessageSequenceImpl::GetRawDataCapacity()
{
    int32_t result = static_cast<int32_t>(nativeParcel_->GetRawDataCapacity());
    return result;
}

void MessageSequenceImpl::WriteByte(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt8(static_cast<int8_t>(val));
    if (!result) {
        ZLOGE(LOG_LABEL, "write int8 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteShort(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt16(static_cast<int16_t>(val));
    if (!result) {
        ZLOGE(LOG_LABEL, "write int16 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteFloat(double val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteDouble(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write float failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteDouble(double val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteDouble(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write double failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

// MessageOptionImpl
MessageOptionImpl::MessageOptionImpl(int32_t syncFlags, int32_t waitTime)
{
    messageOption_ = std::make_shared<OHOS::MessageOption>(syncFlags, waitTime);
}

bool MessageOptionImpl::IsAsync()
{
    if (messageOption_ == nullptr) {
        ZLOGE(LOG_LABEL, "messageOption_ is null");
        taihe::set_error("failed to get native message option");
        return false;
    }
    int flags = messageOption_->GetFlags();
    return (static_cast<int32_t>(flags) & OHOS::MessageOption::TF_ASYNC) != 0;
}

void MessageOptionImpl::SetAsync(bool isAsync)
{
    if (messageOption_ == nullptr) {
        ZLOGE(LOG_LABEL, "messageOption_ is null");
        taihe::set_error("failed to get native message option");
        return;
    }
    messageOption_->SetFlags(static_cast<int32_t>(isAsync));
}

int64_t MessageOptionImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(messageOption_.get());
}

int32_t MessageOptionImpl::GetFlags()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(messageOption_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return messageOption_->GetFlags();
}

void MessageOptionImpl::SetFlags(int32_t flags)
{
    CHECK_NATIVE_OBJECT(messageOption_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    messageOption_->SetFlags(flags);
}

int32_t MessageOptionImpl::GetWaitTime()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(messageOption_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return messageOption_->GetWaitTime();
}

void MessageOptionImpl::SetWaitTime(int32_t waitTime)
{
    CHECK_NATIVE_OBJECT(messageOption_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    messageOption_->SetWaitTime(waitTime);
}

void MessageOptionImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::MessageOption obj)
{
    jsObjRef_ = std::optional<::ohos::rpc::rpc::MessageOption>(std::in_place, obj);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption_WithTwoParam(int32_t syncFlags,
    int32_t waitTime)
{
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(syncFlags, waitTime);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption_WithOneParam(bool isAsync)
{
    int flags = isAsync ? OHOS::MessageOption::TF_ASYNC : OHOS::MessageOption::TF_SYNC;
    int waitTime = OHOS::MessageOption::TF_WAIT_TIME;
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(flags, waitTime);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption_WithOneIntParam(int32_t syncFlags)
{
    int flags = (syncFlags == 0) ? OHOS::MessageOption::TF_SYNC : OHOS::MessageOption::TF_ASYNC;
    int waitTime = OHOS::MessageOption::TF_WAIT_TIME;
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(flags, waitTime);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption()
{
    int flags = OHOS::MessageOption::TF_SYNC;
    int waitTime = OHOS::MessageOption::TF_WAIT_TIME;
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(flags, waitTime);
}

int32_t MessageOptionImpl::GetTfSync()
{
    return static_cast<int32_t>(OHOS::MessageOption::TF_SYNC);
}

int32_t MessageOptionImpl::GetTfAsync()
{
    return static_cast<int32_t>(OHOS::MessageOption::TF_ASYNC);
}

int32_t MessageOptionImpl::GetTfAcceptFds()
{
    return static_cast<int32_t>(OHOS::MessageOption::TF_ACCEPT_FDS);
}

int32_t MessageOptionImpl::GetTfWaitTime()
{
    return static_cast<int32_t>(OHOS::MessageOption::TF_WAIT_TIME);
}

// IPCSkeletonImpl
int32_t IPCSkeletonImpl::GetCallingPid()
{
    return OHOS::IPCSkeleton::GetCallingPid();
}

int32_t IPCSkeletonImpl::GetCallingUid()
{
    return OHOS::IPCSkeleton::GetCallingUid();
}

int64_t IPCSkeletonImpl::GetCallingTokenId()
{
    return static_cast<int64_t>(OHOS::IPCSkeleton::GetCallingTokenID());
}

::taihe::string IPCSkeletonImpl::ResetCallingIdentity()
{
    return static_cast<::taihe::string>(OHOS::IPCSkeleton::ResetCallingIdentity());
}

void IPCSkeletonImpl::RestoreCallingIdentity(::taihe::string_view identity)
{
    std::string temp = std::string(identity);
    size_t maxLen = 40960;
    if (temp.size() >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    OHOS::IPCSkeleton::SetCallingIdentity(temp);
}

void IPCSkeletonImpl::FlushCmdBuffer(::ohos::rpc::rpc::IRemoteObjectUnion const& object)
{
    if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
        auto &remoteStub = object.get_remoteObject_ref();
        OHOS::sptr<OHOS::IRemoteObject> nativeStub =
            reinterpret_cast<OHOS::IRemoteObject *>(remoteStub->GetNativePtr());
        if (nativeStub == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast to IRemoteObject failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
        }
        OHOS::IPCSkeleton::FlushCommands(nativeStub);
    } else if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
        auto &remoteProxy = object.get_remoteProxy_ref();
        auto nativeProxy = reinterpret_cast<OHOS::IPCObjectProxy *>(remoteProxy->GetNativePtr());
        if (nativeProxy == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast to IPCObjectProxy failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
        }
        OHOS::IPCSkeleton::FlushCommands(nativeProxy);
    } else {
        ZLOGE(LOG_LABEL, "unknown tag: %{public}d", object.get_tag());
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
}

::taihe::string IPCSkeletonImpl::GetCallingDeviceID()
{
    return static_cast<::taihe::string>(OHOS::IPCSkeleton::GetCallingDeviceID());
}

::taihe::string IPCSkeletonImpl::GetLocalDeviceID()
{
    return static_cast<::taihe::string>(OHOS::IPCSkeleton::GetLocalDeviceID());
}

bool IPCSkeletonImpl::IsLocalCalling()
{
    return OHOS::IPCSkeleton::IsLocalCalling();
}

::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion> MessageSequenceImpl::ReadRemoteObjectArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(int32_t),
        nativeParcel_, (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
    if (!(nativeParcel_->WriteUint32(arrayLength))) {
        ZLOGE(LOG_LABEL, "write array length failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
    }
    std::vector<::ohos::rpc::rpc::IRemoteObjectUnion> res;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        ::ohos::rpc::rpc::IRemoteObjectUnion temp = ReadRemoteObject();
        if (temp.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::errRet) {
            ZLOGE(LOG_LABEL, "read RemoteObject failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
        }
        res.push_back(temp);
    }
    return ::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(res);
}
void MessageSequenceImpl::WriteArrayBuffer(::taihe::array_view<uint8_t> buf, ::ohos::rpc::rpc::TypeCode typeCode)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (typeCode.get_key() < ohos::rpc::rpc::TypeCode::key_t::INT8_ARRAY
        || typeCode.get_key() > ohos::rpc::rpc::TypeCode::key_t::BIGUINT64_ARRAY) {
        ZLOGE(LOG_LABEL, "typeCode is out of range. typeCode:%{public}d", typeCode.get_value());
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    size_t byteLength = buf.size();
    void *data = nullptr;
    data = static_cast<void*>(buf.data());
    if (!WriteVectorByTypeCode(data, typeCode, byteLength)) {
        ZLOGE(LOG_LABEL, "write array buffer failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

template<typename T>
static std::vector<T> BufferToVector(void *data, size_t byteLength)
{
    const T* dataPtr = reinterpret_cast<const T*>(data);
    std::vector<T> vec;
    std::copy(dataPtr, dataPtr + byteLength / sizeof(T), std::back_inserter(vec));
    return vec;
}

bool MessageSequenceImpl::WriteVectorByTypeCode(void *data, ::ohos::rpc::rpc::TypeCode typeCode, int32_t byteLength)
{
    switch (typeCode.get_key()) {
        case ohos::rpc::rpc::TypeCode::key_t::INT8_ARRAY: {
            return nativeParcel_->WriteInt8Vector(BufferToVector<int8_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT8_ARRAY: {
            return nativeParcel_->WriteUInt8Vector(BufferToVector<uint8_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::INT16_ARRAY: {
            return nativeParcel_->WriteInt16Vector(BufferToVector<int16_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT16_ARRAY: {
            return nativeParcel_->WriteUInt16Vector(BufferToVector<uint16_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::INT32_ARRAY: {
            return nativeParcel_->WriteInt32Vector(BufferToVector<int32_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT32_ARRAY: {
            return nativeParcel_->WriteUInt32Vector(BufferToVector<uint32_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::FLOAT32_ARRAY: {
            return nativeParcel_->WriteFloatVector(BufferToVector<float>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::FLOAT64_ARRAY: {
            return nativeParcel_->WriteDoubleVector(BufferToVector<double>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::BIGINT64_ARRAY: {
            return nativeParcel_->WriteInt64Vector(BufferToVector<int64_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::BIGUINT64_ARRAY: {
            return nativeParcel_->WriteUInt64Vector(BufferToVector<uint64_t>(data, byteLength));
        }
        default:
            ZLOGE(LOG_LABEL, "unsupported typeCode:%{public}d", typeCode.get_value());
            return false;
    }
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadArrayBuffer(::ohos::rpc::rpc::TypeCode typeCode)
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<uint8_t>(nullptr, 0));
    if (typeCode.get_key() < ohos::rpc::rpc::TypeCode::key_t::INT8_ARRAY
        || typeCode.get_key() > ohos::rpc::rpc::TypeCode::key_t::BIGUINT64_ARRAY) {
        ZLOGE(LOG_LABEL, "typeCode is out of range. typeCode:%{public}d", typeCode.get_value());
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    switch (typeCode.get_key()) {
        case ohos::rpc::rpc::TypeCode::key_t::INT8_ARRAY: {
            return ReadInt8ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT8_ARRAY: {
            return ReadUInt8ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::INT16_ARRAY: {
            return ReadInt16ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT16_ARRAY: {
            return ReadUInt16ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::INT32_ARRAY: {
            return ReadInt32ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT32_ARRAY: {
            return ReadUInt32ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::FLOAT32_ARRAY: {
            return ReadFloatArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::FLOAT64_ARRAY: {
            return ReadDoubleArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::BIGINT64_ARRAY: {
            return ReadInt64ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::BIGUINT64_ARRAY: {
            return ReadUInt64ArrayBuffer();
        }
        default:
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
                ::taihe::array<uint8_t>(nullptr, 0));
    }
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt8ArrayBuffer()
{
    std::vector<int8_t> int8Vector;
    if (!nativeParcel_->ReadInt8Vector(&int8Vector)) {
        ZLOGE(LOG_LABEL, "read Int8Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int8Vector.data());
    size_t byteLength = int8Vector.size();

    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt8ArrayBuffer()
{
    std::vector<uint8_t> uint8Vector;
    if (!nativeParcel_->ReadUInt8Vector(&uint8Vector)) {
        ZLOGE(LOG_LABEL, "read int16Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    return ::taihe::array<uint8_t>(uint8Vector);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt16ArrayBuffer()
{
    std::vector<int16_t> int16Vector;
    if (!nativeParcel_->ReadInt16Vector(&int16Vector)) {
        ZLOGE(LOG_LABEL, "read int16Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int16Vector.data());
    size_t byteLength = int16Vector.size() * BYTE_SIZE_16;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt16ArrayBuffer()
{
    std::vector<uint16_t> uint16Vector;
    if (!nativeParcel_->ReadUInt16Vector(&uint16Vector)) {
        ZLOGE(LOG_LABEL, "read uint16Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(uint16Vector.data());
    size_t byteLength = uint16Vector.size() * BYTE_SIZE_16;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt32ArrayBuffer()
{
    std::vector<int32_t> int32Vector;
    if (!nativeParcel_->ReadInt32Vector(&int32Vector)) {
        ZLOGE(LOG_LABEL, "read int32Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int32Vector.data());
    size_t byteLength = int32Vector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt32ArrayBuffer()
{
    std::vector<uint32_t> uint32Vector;
    if (!nativeParcel_->ReadUInt32Vector(&uint32Vector)) {
        ZLOGE(LOG_LABEL, "read uint32Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(uint32Vector.data());
    size_t byteLength = uint32Vector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadFloatArrayBuffer()
{
    std::vector<float> floatVector;
    if (!nativeParcel_->ReadFloatVector(&floatVector)) {
        ZLOGE(LOG_LABEL, "read floatVector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(floatVector.data());
    size_t byteLength = floatVector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadDoubleArrayBuffer()
{
    std::vector<double> doubleVector;
    if (!nativeParcel_->ReadDoubleVector(&doubleVector)) {
        ZLOGE(LOG_LABEL, "read doubleVector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(doubleVector.data());
    size_t byteLength = doubleVector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt64ArrayBuffer()
{
    std::vector<int64_t> int64Vector;
    if (!nativeParcel_->ReadInt64Vector(&int64Vector)) {
        ZLOGE(LOG_LABEL, "read int64Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int64Vector.data());
    size_t byteLength = int64Vector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt64ArrayBuffer()
{
    std::vector<uint64_t> uint64Vector;
    if (!nativeParcel_->ReadUInt64Vector(&uint64Vector)) {
        ZLOGE(LOG_LABEL, "read uint64Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(uint64Vector.data());
    size_t byteLength = uint64Vector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

int32_t MessageSequenceImpl::GetSize()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetDataSize());
    return result;
}

int32_t MessageSequenceImpl::GetWritableBytes()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetWritableBytes());
    return result;
}

int32_t MessageSequenceImpl::GetReadableBytes()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetReadableBytes());
    return result;
}

int32_t MessageSequenceImpl::GetReadPosition()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetReadPosition());
    return result;
}

int32_t MessageSequenceImpl::GetWritePosition()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetWritePosition());
    return result;
}

bool MessageSequenceImpl::ContainFileDescriptors()
{
    bool result = nativeParcel_->ContainFileDescriptors();
    return result;
}

int32_t MessageSequenceImpl::GetRawDataCapacity()
{
    int32_t result = static_cast<int32_t>(nativeParcel_->GetRawDataCapacity());
    return result;
}

void MessageSequenceImpl::RewindRead(int32_t pos)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    nativeParcel_->RewindRead(static_cast<size_t>(pos));
}

void MessageSequenceImpl::RewindWrite(int32_t pos)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    nativeParcel_->RewindWrite(static_cast<size_t>(pos));
}

void MessageSequenceImpl::SetSize(int32_t size)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    nativeParcel_->SetDataSize(static_cast<size_t>(size));
}

::ohos::rpc::rpc::IRemoteObjectUnion IPCSkeletonImpl::GetContextObject()
{
    auto object = OHOS::IPCSkeleton::GetContextObject();
    uintptr_t addr = reinterpret_cast<uintptr_t>(object.GetRefPtr());
    auto jsProxy = RemoteProxyImpl::CreateRemoteProxyFromNative(addr);
    return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteProxy(jsProxy);
}

::taihe::array<int32_t> MessageSequenceImpl::ReadByteArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<int32_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<int32_t>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(int8_t),
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
    ::taihe::array<int32_t> res(arrayLength);
    int8_t value = 0;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt8(value)) {
            ZLOGE(LOG_LABEL, "read int8 failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<int32_t>(nullptr, 0)));
        }
        res[i] = static_cast<int32_t>(value);
    }
    return res;
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateRemoteObject(OHOS::RemoteObjectImpl::CreateRemoteObject);
TH_EXPORT_CPP_API_CreateRemoteObjectFromNative(OHOS::RemoteObjectImpl::CreateRemoteObjectFromNative);
TH_EXPORT_CPP_API_CreateRemoteProxyFromNative(OHOS::RemoteProxyImpl::CreateRemoteProxyFromNative);
TH_EXPORT_CPP_API_GetPingTransaction(OHOS::RemoteProxyImpl::GetPingTransaction);
TH_EXPORT_CPP_API_GetDumpTransaction(OHOS::RemoteProxyImpl::GetDumpTransaction);
TH_EXPORT_CPP_API_GetInterfaceTransaction(OHOS::RemoteProxyImpl::GetInterfaceTransaction);
TH_EXPORT_CPP_API_GetMinTransactionId(OHOS::RemoteProxyImpl::GetMinTransactionId);
TH_EXPORT_CPP_API_GetMaxTransactionId(OHOS::RemoteProxyImpl::GetMaxTransactionId);
TH_EXPORT_CPP_API_CreateMessageSequence(OHOS::MessageSequenceImpl::CreateMessageSequence);
TH_EXPORT_CPP_API_CloseFileDescriptor(OHOS::MessageSequenceImpl::CloseFileDescriptor);
TH_EXPORT_CPP_API_RpcTransferStaicImpl(OHOS::MessageSequenceImpl::RpcTransferStaicImpl);
TH_EXPORT_CPP_API_RpcTransferDynamicImpl(OHOS::MessageSequenceImpl::RpcTransferDynamicImpl);
TH_EXPORT_CPP_API_CreateMessageOption_WithTwoParam(OHOS::MessageOptionImpl::CreateMessageOption_WithTwoParam);
TH_EXPORT_CPP_API_CreateMessageOption_WithOneParam(OHOS::MessageOptionImpl::CreateMessageOption_WithOneParam);
TH_EXPORT_CPP_API_CreateMessageOption_WithOneIntParam(OHOS::MessageOptionImpl::CreateMessageOption_WithOneIntParam);
TH_EXPORT_CPP_API_DupFileDescriptor(OHOS::MessageSequenceImpl::DupFileDescriptor);
TH_EXPORT_CPP_API_CreateMessageOption(OHOS::MessageOptionImpl::CreateMessageOption);
TH_EXPORT_CPP_API_GetTfSync(OHOS::MessageOptionImpl::GetTfSync);
TH_EXPORT_CPP_API_GetTfAsync(OHOS::MessageOptionImpl::GetTfAsync);
TH_EXPORT_CPP_API_GetTfAcceptFds(OHOS::MessageOptionImpl::GetTfAcceptFds);
TH_EXPORT_CPP_API_GetTfWaitTime(OHOS::MessageOptionImpl::GetTfWaitTime);
TH_EXPORT_CPP_API_CreateAshmem_WithTwoParam(OHOS::AshmemImpl::CreateAshmem_WithTwoParam);
TH_EXPORT_CPP_API_CreateAshmem_WithOneParam(OHOS::AshmemImpl::CreateAshmem_WithOneParam);
TH_EXPORT_CPP_API_GetProtExec(OHOS::AshmemImpl::GetProtExec);
TH_EXPORT_CPP_API_GetProtNone(OHOS::AshmemImpl::GetProtNone);
TH_EXPORT_CPP_API_GetProtRead(OHOS::AshmemImpl::GetProtRead);
TH_EXPORT_CPP_API_GetProtWrite(OHOS::AshmemImpl::GetProtWrite);
TH_EXPORT_CPP_API_GetCallingPid(OHOS::IPCSkeletonImpl::GetCallingPid);
TH_EXPORT_CPP_API_GetCallingUid(OHOS::IPCSkeletonImpl::GetCallingUid);
TH_EXPORT_CPP_API_GetCallingTokenId(OHOS::IPCSkeletonImpl::GetCallingTokenId);
TH_EXPORT_CPP_API_GetContextObject(OHOS::IPCSkeletonImpl::GetContextObject);
TH_EXPORT_CPP_API_ResetCallingIdentity(OHOS::IPCSkeletonImpl::ResetCallingIdentity);
TH_EXPORT_CPP_API_RestoreCallingIdentity(OHOS::IPCSkeletonImpl::RestoreCallingIdentity);
TH_EXPORT_CPP_API_FlushCmdBuffer(OHOS::IPCSkeletonImpl::FlushCmdBuffer);
TH_EXPORT_CPP_API_GetCallingDeviceID(OHOS::IPCSkeletonImpl::GetCallingDeviceID);
TH_EXPORT_CPP_API_GetLocalDeviceID(OHOS::IPCSkeletonImpl::GetLocalDeviceID);
TH_EXPORT_CPP_API_IsLocalCalling(OHOS::IPCSkeletonImpl::IsLocalCalling);
TH_EXPORT_CPP_API_unwrapRemoteObject(OHOS::unwrapRemoteObject);
TH_EXPORT_CPP_API_wrapRemoteObject(OHOS::wrapRemoteObject);
// NOLINTEND

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
         DECLARE_NAPI_FUNCTION("reclaim", NAPI_RemoteProxy_Reclaim),
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

 
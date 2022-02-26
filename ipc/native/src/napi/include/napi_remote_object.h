/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NAPI_IPC_OHOS_REMOTE_OBJECT_H
#define NAPI_IPC_OHOS_REMOTE_OBJECT_H

#include "iremote_object.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "refbase.h"

constexpr size_t  TRACESIZE = 64;
namespace OHOS {
EXTERN_C_START
    napi_value NAPIIPCSkeletonExport(napi_env env, napi_value exports);
    napi_value NAPIRemoteProxyExport(napi_env env, napi_value exports);
    napi_value NAPIRemoteObjectExport(napi_env env, napi_value exports);
    napi_value NAPIMessageOptionExport(napi_env env, napi_value exports);
EXTERN_C_END

    // IPCSkeleton napi methods
    napi_value NAPI_IPCSkeleton_getContextObject(napi_env env, napi_callback_info info);

    napi_value NAPI_IPCSkeleton_getCallingPid(napi_env env, napi_callback_info info);

    napi_value NAPI_IPCSkeleton_getCallingUid(napi_env env, napi_callback_info info);

    napi_value NAPI_IPCSkeleton_getCallingDeviceID(napi_env env, napi_callback_info info);

    napi_value NAPI_IPCSkeleton_getLocalDeviceID(napi_env env, napi_callback_info info);

    napi_value NAPI_IPCSkeleton_isLocalCalling(napi_env env, napi_callback_info info);

    napi_value NAPI_IPCSkeleton_flushCommands(napi_env env, napi_callback_info info);

    napi_value NAPI_IPCSkeleton_resetCallingIdentity(napi_env env, napi_callback_info info);

    napi_value NAPI_IPCSkeleton_setCallingIdentity(napi_env env, napi_callback_info info);

    // RemoteObject napi methods
    napi_value NAPI_RemoteObject_sendRequest(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteObject_getCallingPid(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteObject_getCallingUid(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteObject_getInterfaceDescriptor(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteObject_attachLocalInterface(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteObject_queryLocalInterface(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteObject_addDeathRecipient(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteObject_removeDeathRecipient(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteObject_isObjectDead(napi_env env, napi_callback_info info);

    // RemoteProxy napi methods
    napi_value NAPI_RemoteProxy_sendRequest(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteProxy_queryLocalInterface(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteProxy_addDeathRecipient(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteProxy_removeDeathRecipient(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteProxy_getInterfaceDescriptor(napi_env env, napi_callback_info info);

    napi_value NAPI_RemoteProxy_isObjectDead(napi_env env, napi_callback_info info);

    sptr<IRemoteObject> NAPI_ohos_rpc_getNativeRemoteObject(napi_env env, napi_value object);

    napi_value NAPI_ohos_rpc_CreateJsRemoteObject(napi_env env, const sptr<IRemoteObject> target);

    struct SendRequestParam {
        sptr<IRemoteObject> target;
        uint32_t code;
        std::shared_ptr<MessageParcel> data;
        std::shared_ptr<MessageParcel> reply;
        MessageOption &option;
        napi_async_work asyncWork;
        napi_deferred deferred;
        int errCode;
        napi_ref jsCodeRef;
        napi_ref jsDataRef;
        napi_ref jsReplyRef;
        napi_ref callback;
        napi_env env;
    };
} // namespace OHOS
#endif // NAPI_IPC_OHOS_REMOTE_OBJECT_H

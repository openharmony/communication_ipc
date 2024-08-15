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
#ifndef NAPI_IPC_OHOS_REMOTE_OBJECT_H
#define NAPI_IPC_OHOS_REMOTE_OBJECT_H

#include "iremote_object.h"
#include "napi/native_api.h"
#include "refbase.h"

namespace OHOS {
    // Description of caller information parameters.
    struct CallingInfo {
        pid_t callingPid;
        pid_t callingUid;
        uint32_t callingTokenId;
        std::string callingDeviceID;
        std::string localDeviceID;
        bool isLocalCalling;
        int activeStatus;
    };

    // NAPI caller information parameter description.
    struct NAPI_CallingInfo {
        napi_value callingPid;
        napi_value callingUid;
        napi_value callingTokenId;
        napi_value callingDeviceID;
        napi_value localDeviceID;
        napi_value isLocalCalling;
        napi_value activeStatus;
    };

EXTERN_C_START

    /**
     * @brief Export NAPIRemote object.
     * @param env Indicates the environment in which NAPI is called.
     * @param exports Indicates the NAPI exporter.
     * @return Returns the exporter of NAPI.
     * @since 9
     */
    napi_value NAPIRemoteObjectExport(napi_env env, napi_value exports);
EXTERN_C_END

/**
 * @brief Create a JavaScript proxy object.
 * @param env Indicates the environment in which NAPI is called.
 * @param target Indicates the IRemoteObject pointer object.
 * @return Returns the created proxy object.
 * @since 9
 */
napi_value NAPI_ohos_rpc_CreateJsRemoteObject(napi_env env, const sptr<IRemoteObject> target);

/**
 * @brief Clear native proxy object that associated with js object.
 * @param env Indicates the environment in which NAPI is called.
 * @param jsRemoteProxy Indicates the js object(the associated native object will be cleared).
 * @return Returns <b>true</b> if the operation succeeds; return <b>false</b> Otherwise.
 * @since 12
 */
bool NAPI_ohos_rpc_ClearNativeRemoteProxy(napi_env env, napi_value jsRemoteProxy);

/**
 * @brief Get a native remote object.
 * @param env Indicates the environment in which NAPI is called.
 * @param object Indicates the object obtained.
 * @return Returns the IRemoteObject point object.
 * @since 9
 */
sptr<IRemoteObject> NAPI_ohos_rpc_getNativeRemoteObject(napi_env env, napi_value object);

/**
 * @brief Gets remote proxy object caller information.
 * @param newCallingInfoParam Indicates the caller information.
 * @return void
 * @since 9
 */
void NAPI_RemoteObject_getCallingInfo(CallingInfo &newCallingInfoParam);

/**
 * @brief Saves caller information for the old remote proxy object.
 * @param env Indicates the environment in which NAPI is called.
 * @param oldCallingInfo Indicates the old caller information.
 * @return void
 * @since 9
 */
void NAPI_RemoteObject_saveOldCallingInfo(napi_env env, NAPI_CallingInfo &oldCallingInfo);

/**
 * @brief Sats caller information for the new remote proxy object.
 * @param env Indicates the environment in which NAPI is called.
 * @param newCallingInfoParam Indicates the new caller information.
 * @return void
 * @since 9
 */
void NAPI_RemoteObject_setNewCallingInfo(napi_env env, const CallingInfo &newCallingInfoParam);

/**
 * @brief Resets caller information for the old remote proxy object.
 * @param env Indicates the environment in which NAPI is called.
 * @param oldCallingInfo Indicates the old caller information.
 * @return void
 * @since 9
 */
void NAPI_RemoteObject_resetOldCallingInfo(napi_env env, NAPI_CallingInfo &oldCallingInfo);
}
#endif
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
    struct CallingInfo {
        pid_t callingPid;
        pid_t callingUid;
        uint32_t callingTokenId;
        std::string callingDeviceID;
        std::string localDeviceID;
        bool isLocalCalling;
        int activeStatus;
    };

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
    napi_value NAPIRemoteObjectExport(napi_env env, napi_value exports);
EXTERN_C_END

napi_value NAPI_ohos_rpc_CreateJsRemoteObject(napi_env env, const sptr<IRemoteObject> target);

sptr<IRemoteObject> NAPI_ohos_rpc_getNativeRemoteObject(napi_env env, napi_value object);

void NAPI_RemoteObject_getCallingInfo(CallingInfo &newCallingInfoParam);

void NAPI_RemoteObject_saveOldCallingInfo(napi_env env, NAPI_CallingInfo &oldCallingInfo);

void NAPI_RemoteObject_setNewCallingInfo(napi_env env, const CallingInfo &newCallingInfoParam);

void NAPI_RemoteObject_resetOldCallingInfo(napi_env env, NAPI_CallingInfo &oldCallingInfo);
}
#endif
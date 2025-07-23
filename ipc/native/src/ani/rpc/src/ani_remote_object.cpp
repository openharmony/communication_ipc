/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#include "ani_remote_object.h"
#include "ani_rpc_error.h"
#include "ani_utils.h"
#include "ipc_debug.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "message_parcel.h"
#include "string_ex.h"
#include "rpc_ani_class.h"
#include <ani.h>
#include <array>
#include <cstring>
 
using namespace OHOS;
 
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = {LOG_CORE, LOG_ID_IPC_NAPI, "ani_rpc_error"};
 
sptr<IRemoteObject> AniGetNativeRemoteObject(ani_env *env, ani_object obj)
{
    ZLOGI(LOG_LABEL, "[ANI] enter AniGetNativeRemoteObject func");
    auto holder = AniObjectUtils::Unwrap<IPCObjectRemoteHolder>(env, obj);
    if (holder == nullptr) {
        ZLOGI(LOG_LABEL, "[ANI] IPCObjectRemoteHolder is nullptr");
        return nullptr;
    }
    return holder->Get(env);
}
 
static ani_object CreateJsProxyRemoteObject(ani_env *env, const sptr<IRemoteObject> target)
{
    auto holder = new OhSharedPtrHolder<IRemoteObject>(target);
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "[ANI] OhSharedPtrHolder constructor failed");
        return nullptr;
    }
    ani_object jsRemoteProxy = AniObjectUtils::Create(env, "L@ohos/rpc/rpc;", "LRemoteProxy;");
    if (jsRemoteProxy == nullptr) {
        ZLOGE(LOG_LABEL, "[ANI] Create jsRemoteProxy failed");
        delete holder;
        return nullptr;
    }
    if (ANI_OK != AniObjectUtils::Wrap<OhSharedPtrHolder<IRemoteObject>>(env, jsRemoteProxy, holder)) {
        ZLOGE(LOG_LABEL, "[ANI] Wrap jsRemoteProxy failed");
        delete holder;
        return nullptr;
    }
    return jsRemoteProxy;
}
 
ani_object ANI_ohos_rpc_CreateJsRemoteObject(ani_env *env, sptr<IRemoteObject> remoteObject)
{
    if (remoteObject == nullptr) {
        ZLOGE(LOG_LABEL, "[ANI] RemoteObject is nullptr");
        return nullptr;
    }
 
    return CreateJsProxyRemoteObject(env, remoteObject);
}
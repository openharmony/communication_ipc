/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "remote_object_taihe_ani.h"

#include <ani_signature_builder.h>
#include "ipc_debug.h"
#include "iremote_object.h"
#include "ipc_object_stub.h"
#include "hilog/log.h"
#include "log_tags.h"
// This file is for legacy ANI backward compatibility

using namespace OHOS;
using namespace arkts;
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_OTHER, "rpc_taihe" };

ani_object ANI_ohos_rpc_CreateJsRemoteObject(ani_env* env, OHOS::sptr<OHOS::IRemoteObject> remoteObject)
{
    std::unique_ptr<RemoteObjectTaiheAni> taiheAniobj = std::make_unique<RemoteObjectTaiheAni>();
    taiheAniobj->nativeObject_ = remoteObject;

    ani_signature::Namespace ns = ani_signature::Builder::BuildNamespace("@ohos.rpc.rpc");
    ani_namespace imageNamespace;
    if (env->FindNamespace(ns.Descriptor().c_str(), &imageNamespace) != ANI_OK) {
        ZLOGE(LOG_LABEL, "FindNamespace error");
        return nullptr;
    }
    ani_function createFunc;
    if (env->Namespace_FindFunction(imageNamespace, "wrapRemoteObject", nullptr, &createFunc) != ANI_OK) {
        ZLOGE(LOG_LABEL, "FindFunction error");
        return nullptr;
    }
    ani_ref remoteObj;
    if (env->Function_Call_Ref(createFunc, &remoteObj, reinterpret_cast<ani_long>(taiheAniobj.get())) == ANI_OK) {
        taiheAniobj.release();
    } else {
        ZLOGE(LOG_LABEL, "Call_Ref error");
        return nullptr;
    }
    return reinterpret_cast<ani_object>(remoteObj);
}

OHOS::sptr<OHOS::IRemoteObject> AniGetNativeRemoteObject(ani_env* env, ani_object obj)
{
    ani_signature::Namespace ns = ani_signature::Builder::BuildNamespace("@ohos.rpc.rpc");
    ani_namespace imageNamespace;
    if (env->FindNamespace(ns.Descriptor().c_str(), &imageNamespace) != ANI_OK) {
        ZLOGE(LOG_LABEL, "FindNamespace error");
        return nullptr;
    }
    ani_function createFunc;
    if (env->Namespace_FindFunction(imageNamespace, "unwrapRemoteObject", nullptr, &createFunc) != ANI_OK) {
        ZLOGE(LOG_LABEL, "FindFunction error");
        return nullptr;
    }
    ani_long implPtr;
    if (!(env->Function_Call_Long(createFunc, &implPtr, obj) == ANI_OK)) {
        ZLOGE(LOG_LABEL, "Call_Long error");
        return nullptr;
    }
    return reinterpret_cast<OHOS::IPCObjectStub*>(implPtr);
}
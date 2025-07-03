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

using namespace OHOS;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = {LOG_CORE, LOG_ID_IPC_NAPI, "rpc_ani"};

static void InitMessageOption([[maybe_unused]] ani_env *env,
                              [[maybe_unused]] ani_object obj,
                              ani_double syncFlags,
                              ani_double waitTimeParam)
{
    ZLOGI(LOG_LABEL, "[ANI] enter InitMessageOption func syncFlags: %{public}f, waitTimeParam: %{public}f", syncFlags,
          waitTimeParam);
    int flags = MessageOption::TF_SYNC;
    int waitTime = MessageOption::TF_WAIT_TIME;

    int32_t syncFlagsValue = static_cast<int32_t>(syncFlags);
    int32_t waitTimeValue = static_cast<int32_t>(waitTimeParam);
    if (syncFlagsValue != 0 && waitTimeValue != 0) {
        flags = MessageOption::TF_ASYNC;
        waitTime = waitTimeValue;
    }

    auto messageOptionHolder = new StdSharedPtrHolder(std::make_shared<MessageOption>(flags, waitTime));
    AniObjectUtils::Wrap<StdSharedPtrHolder<MessageOption>>(env, obj, messageOptionHolder);
    ZLOGI(LOG_LABEL, "[ANI] InitMessageOption end");
}

static ani_string MessageSequenceReadString([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ZLOGI(LOG_LABEL, "[ANI] enter MessageSequenceReadString func");
    auto parcel = AniObjectUtils::Unwrap<MessageParcel>(env, object);
    if (parcel == nullptr) {
        AniError::ThrowError(env, READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        return ani_string {};
    }
    auto str = parcel->ReadString();
    return AniStringUtils::ToAni(env, str);
}

static bool MessageSequenceWriteString([[maybe_unused]] ani_env *env,
                                       [[maybe_unused]] ani_object object,
                                       ani_string str)
{
    ZLOGI(LOG_LABEL, "[ANI] enter MessageSequenceWriteString func");
    auto parcel = AniObjectUtils::Unwrap<MessageParcel>(env, object);
    if (parcel == nullptr) {
        AniError::ThrowError(env, WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        return false;
    }
    auto stringContent = AniStringUtils::ToStd(env, str);
    return parcel->WriteString(stringContent);
}

static ani_string MessageSequencereadInterfaceToken([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ZLOGI(LOG_LABEL, "[ANI] enter MessageSequencereadInterfaceToken func");
    auto parcel = AniObjectUtils::Unwrap<MessageParcel>(env, object);
    if (parcel == nullptr) {
        AniError::ThrowError(env, READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        return ani_string {};
    }
    auto str = parcel->ReadInterfaceToken();
    std::string outString = Str16ToStr8(str.c_str());
    return AniStringUtils::ToAni(env, outString);
}

static void RemoteObjectInit([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string descriptor)
{
    ZLOGI(LOG_LABEL, "[ANI] enter RemoteObjectInit func");
    auto descriptorStr = AniStringUtils::ToStd(env, static_cast<ani_string>(descriptor));
    auto objectRemoteHolder = new IPCObjectRemoteHolder(env, object, OHOS::Str8ToStr16(descriptorStr));
    AniObjectUtils::Wrap<IPCObjectRemoteHolder>(env, object, objectRemoteHolder);
}

static ani_string GetRemoteObjectDescriptor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ZLOGI(LOG_LABEL, "[ANI] enter GetRemoteObjectDescriptor func");
    ani_string result_string {};
    auto objectRemoteHolder = AniObjectUtils::Unwrap<IPCObjectRemoteHolder>(env, object);
    if (objectRemoteHolder == nullptr) {
        ZLOGE(LOG_LABEL, "[ANI] objectRemoteHolder is nullptr");
        AniError::ThrowError(env, PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
        return result_string;
    }
    auto descriptorStr = objectRemoteHolder->GetDescriptor();
    ZLOGI(LOG_LABEL, "[ANI] get descriptor: %{public}s", descriptorStr.c_str());
    env->String_NewUTF8(descriptorStr.c_str(), descriptorStr.size(), &result_string);
    return result_string;
}

static ani_string GetRemoteProxyDescriptor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ZLOGI(LOG_LABEL, "[ANI] enter GetRemoteProxyDescriptor func");
    ani_string result_string {};
    auto objectProxyHolder = AniObjectUtils::Unwrap<IPCObjectProxyHolder>(env, object);
    if (objectProxyHolder == nullptr) {
        ZLOGE(LOG_LABEL, "[ANI] objectProxyHolder is nullptr");
        AniError::ThrowError(env, PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
        return result_string;
    }
    auto descriptorStr = objectProxyHolder->GetDescriptor();
    ZLOGI(LOG_LABEL, "[ANI] get descriptor: %{public}s", descriptorStr.c_str());
    env->String_NewUTF8(descriptorStr.c_str(), descriptorStr.size(), &result_string);
    return result_string;
}

static ani_status BindMessageSequenceClassMethods(ani_env *env, ani_namespace &ns)
{
    static const char *msgSeqClsName = "LMessageSequence;";
    ani_class msgSequenceClass;
    if (ANI_OK != env->Namespace_FindClass(ns, msgSeqClsName, &msgSequenceClass)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", msgSeqClsName);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"readString", nullptr, reinterpret_cast<void *>(MessageSequenceReadString)},
        ani_native_function {"writeString", nullptr, reinterpret_cast<void *>(MessageSequenceWriteString)},
        ani_native_function {"readInterfaceToken", nullptr,
                             reinterpret_cast<void *>(MessageSequencereadInterfaceToken)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(msgSequenceClass, methods.data(), methods.size())) {
        ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", msgSeqClsName);
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindMessageOptionClassMethods(ani_env *env, ani_namespace &ns)
{
    static const char *msgOptClsName = "LMessageOption;";
    ani_class msgOptionClass;
    if (ANI_OK != env->Namespace_FindClass(ns, msgOptClsName, &msgOptionClass)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", msgOptClsName);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"init", nullptr, reinterpret_cast<void *>(InitMessageOption)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(msgOptionClass, methods.data(), methods.size())) {
        ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", msgOptClsName);
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindRemoteObjectClassMethods(ani_env *env, ani_namespace &ns)
{
    static const char *remoteObjClsName = "LRemoteObject;";
    ani_class remoteObjClass;
    if (ANI_OK != env->Namespace_FindClass(ns, remoteObjClsName, &remoteObjClass)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", remoteObjClsName);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"getDescriptor", nullptr, reinterpret_cast<void *>(GetRemoteObjectDescriptor)},
        ani_native_function {"init", "Lstd/core/String;:V", reinterpret_cast<void *>(RemoteObjectInit)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(remoteObjClass, methods.data(), methods.size())) {
        ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", remoteObjClsName);
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindRemoteProxyClassMethods(ani_env *env, ani_namespace &ns)
{
    static const char *remoteProxyClsName = "LRemoteProxy;";
    ani_class remoteProxyClass;
    if (ANI_OK != env->Namespace_FindClass(ns, remoteProxyClsName, &remoteProxyClass)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", remoteProxyClsName);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"getDescriptor", nullptr, reinterpret_cast<void *>(GetRemoteProxyDescriptor)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(remoteProxyClass, methods.data(), methods.size())) {
        ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", remoteProxyClsName);
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindCleanerclassMethods(ani_env *env, ani_namespace &ns)
{
    auto cleanerCls = AniTypeFinder(env).FindClass(ns, "LCleaner;");
    return NativePtrCleaner(env).Bind(cleanerCls.value());
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ZLOGE(LOG_LABEL, "[ANI] Unsupported ANI_VERSION_1");
        return ANI_ERROR;
    }

    static const char *nsName = "L@ohos/rpc/rpc;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(nsName, &ns)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", nsName);
        return ANI_NOT_FOUND;
    }

    if (ANI_OK != BindMessageSequenceClassMethods(env, ns)) {
        ZLOGE(LOG_LABEL, "[ANI] BindMessageSequenceClassMethods failed");
        return ANI_ERROR;
    }

    if (ANI_OK != BindMessageOptionClassMethods(env, ns)) {
        ZLOGE(LOG_LABEL, "[ANI] BindMessageOptionClassMethods failed");
        return ANI_ERROR;
    }

    if (ANI_OK != BindRemoteObjectClassMethods(env, ns)) {
        ZLOGE(LOG_LABEL, "[ANI] BindRemoteObjectClassMethods failed");
        return ANI_ERROR;
    }

    if (ANI_OK != BindRemoteProxyClassMethods(env, ns)) {
        ZLOGE(LOG_LABEL, "[ANI] BindRemoteProxyClassMethods failed");
        return ANI_ERROR;
    }

    if (ANI_OK != BindCleanerclassMethods(env, ns)) {
        ZLOGE(LOG_LABEL, "[ANI] BindCleanerclassMethods failed");
        return ANI_ERROR;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}

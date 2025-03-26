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

#include <ani.h>
#include <array>
#include <cstring>
#include "ani_remote_object.h"
#include "ani_utils.h"
#include "iremote_object.h"
#include "ipc_object_stub.h"
#include "ipc_object_proxy.h"
#include "message_parcel.h"
#include "string_ex.h"
#include "ipc_debug.h"
#include "log_tags.h"

using namespace OHOS;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "rpc_ani" };

static ani_object CreateMessageSequence([[maybe_unused]] ani_env *env, MessageParcel &msgParcel)
{
    ZLOGI(LOG_LABEL, "[ANI] enter CreateMessageSequence func");
    static const char *nsName = "L@ohos/rpc/rpc;";
    ani_namespace ns;
    ani_object nullobj{};
    if (ANI_OK != env->FindNamespace(nsName, &ns)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found MessageSequence Namespace: '%{public}s'", nsName);
        return nullobj;
    }

    static const char *className = "LMessageSequence;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found MessageSequence Class: '%{public}s'", className);
        return nullobj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found MessageSequence ctor");
        return nullobj;
    }

    ani_object sequenceObj;
    if (ANI_OK != env->Object_New(cls, ctor, &sequenceObj)) {
        ZLOGE(LOG_LABEL, "[ANI] New MessageSequence Fail");
        return nullobj;
    }

    AniObjectUtils::Wrap<MessageParcel>(env, sequenceObj, &msgParcel);
    return sequenceObj;
}

static ani_object DoubleToObject(ani_env *env, double value)
{
    ani_object aniObject = nullptr;
    ani_double doubleValue = static_cast<ani_double>(value);
    static const char *className = "Lstd/core/Double;";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        ZLOGE(LOG_LABEL, "Not found '%{public}s'", className);
        return aniObject;
    }
    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "D:V", &personInfoCtor)) {
        ZLOGE(LOG_LABEL, "Class_GetMethod Failed '%{public}s' <ctor>", className);
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, doubleValue)) {
        ZLOGE(LOG_LABEL, "Object_New Failed '%{public}s' <ctor>", className);
        return aniObject;
    }
    return aniObject;
}

static ani_object CreateMessageOption([[maybe_unused]] ani_env *env, MessageOption &option)
{
    ZLOGI(LOG_LABEL, "[ANI] enter CreateMessageOption func, flags: %{public}u", option.GetFlags());

    static const char *nsName = "L@ohos/rpc/rpc;";
    ani_namespace ns;
    ani_object nullobj{};
    if (ANI_OK != env->FindNamespace(nsName, &ns)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found MessageSequence Namespace: '%{public}s'", nsName);
        return nullobj;
    }

    static const char *className = "LMessageOption;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found MessageOption Class: '%{public}s'", className);
        return nullobj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found MessageOption ctor");
        return nullobj;
    }

    ani_object flagsObj = DoubleToObject(env, option.GetFlags());
    ani_object waitTimeObj = DoubleToObject(env, option.GetWaitTime());

    ZLOGI(LOG_LABEL, "[ANI] CreateMessageOption Object_New");
    ani_object optionObj;
    if (ANI_OK != env->Object_New(cls, ctor, &optionObj, flagsObj, waitTimeObj)) {
        ZLOGE(LOG_LABEL, "[ANI] [ANI] New MessageOption Fail");
        return nullobj;
    }

    return optionObj;
}

static void InitMessageOption([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj, ani_double syncFlags,
                              ani_double waitTimeParam)
{
    ZLOGI(LOG_LABEL, "[ANI] enter InitMessageOption func syncFlags: %{public}f, waitTimeParam: %{public}f",
        syncFlags, waitTimeParam);
    int flags = MessageOption::TF_SYNC;
    int waitTime = MessageOption::TF_WAIT_TIME;

    int32_t syncFlagsValue = static_cast<int32_t>(syncFlags);
    int32_t waitTimeValue = static_cast<int32_t>(waitTimeParam);
    if (syncFlagsValue != 0 && waitTimeValue != 0) {
        flags = MessageOption::TF_ASYNC;
        waitTime = waitTimeValue;
    }

    auto messageOption = new MessageOption(flags, waitTime);
    AniObjectUtils::Wrap<MessageOption>(env, obj, messageOption);
    ZLOGI(LOG_LABEL, "[ANI] InitMessageOption end");
}

class IPCAniStub : public IPCObjectStub {
public:
    IPCAniStub(ani_env *env, ani_ref saveRemote, const std::u16string &descriptor) : IPCObjectStub(descriptor),
        env_(env), saveRemote_(saveRemote)
    {
        ZLOGI(LOG_LABEL, "[ANI] enter IPCAniStub ctor");
    }

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        ZLOGI(LOG_LABEL, "[ANI] enter IPCAniStub OnRemoteRequest");
        ani_env *env = env_;
        static const char *nsName = "L@ohos/rpc/rpc;";
        ani_namespace ns;
        if (ANI_OK != env->FindNamespace(nsName, &ns)) {
            ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", nsName);
            return ANI_NOT_FOUND;
        }

        static const char *remoteObjClsName = "LRemoteObject;";
        ani_class cls;
        if (ANI_OK != env->Namespace_FindClass(ns, remoteObjClsName, &cls)) {
            ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", remoteObjClsName);
            return ANI_NOT_FOUND;
        }

        ani_object aniData = CreateMessageSequence(env, data);
        ani_object aniReply = CreateMessageSequence(env, reply);
        ani_object aniOption = CreateMessageOption(env, option);

        auto obj = reinterpret_cast<ani_object>(saveRemote_);
        ZLOGE(LOG_LABEL, "[ANI] before Object_CallMethodByName_Void onRemoteMessageRequestSync");
        ani_boolean result;
        env_->Object_CallMethodByName_Boolean(obj, "onRemoteMessageRequestSync", nullptr, &result,
            (ani_double)code, aniData, aniReply, aniOption);
        ZLOGE(LOG_LABEL, "[ANI] after Object_CallMethodByName_Void onRemoteMessageRequestSync");

        return result;
    }

    ~IPCAniStub()
    {
        ZLOGI(LOG_LABEL, "[ANI] enter IPCAniStub dtor");
    }

private:
    ani_env *env_ = nullptr;
    ani_ref saveRemote_;
};

class IPCObjectRemoteHolder {
public:
    IPCObjectRemoteHolder(ani_env *env, const std::u16string &descriptor) : env_(env), descriptor_(descriptor)
    {
        ZLOGI(LOG_LABEL, "[ANI] enter IPCObjectRemoteHolder ctor");
    }

    std::string GetDescriptor()
    {
        std::string ret = Str16ToStr8(descriptor_);
        ZLOGI(LOG_LABEL, "[ANI] enter IPCObjectRemoteHolder GetDescriptor, descriptor:%{public}s", ret.c_str());
        return ret;
    }

    sptr<IRemoteObject> Get()
    {
        if (object_ == nullptr) {
            object_ = sptr<IPCAniStub>::MakeSptr(env_, saveRemote_, descriptor_);
        }
        return object_;
    }

    void Set(ani_ref saveRemote)
    {
        saveRemote_ = saveRemote;
    }

    ~IPCObjectRemoteHolder()
    {
        ZLOGI(LOG_LABEL, "[ANI] enter IPCObjectRemoteHolder dtor");
    }

private:
    sptr<IRemoteObject> object_;
    ani_env *env_ = nullptr;
    ani_ref saveRemote_;
    std::u16string descriptor_;
};

class IPCObjectProxyHolder {
public:
    std::string GetDescriptor()
    {
        ZLOGI(LOG_LABEL, "[ANI] enter IPCObjectRemoteHolder GetDescriptor");
        if (!object_) {
            return "";
        }
        return OHOS::Str16ToStr8(object_->GetInterfaceDescriptor());
    }

private:
    sptr<IPCObjectProxy> object_;
};

sptr<IRemoteObject> AniGetNativeRemoteObject(ani_env *env, ani_object obj)
{
    ZLOGI(LOG_LABEL, "[ANI] enter AniGetNativeRemoteObject func");
    auto holder = AniObjectUtils::Unwrap<IPCObjectRemoteHolder>(env, obj);
    if (holder == nullptr) {
        return nullptr;
    }
    return holder->Get();
}

static ani_string MessageSequenceReadString([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ZLOGI(LOG_LABEL, "[ANI] enter MessageSequenceReadString func");
    auto parcel = AniObjectUtils::Unwrap<MessageParcel>(env, object);
    if (parcel == nullptr) {
        return ani_string{};
    }
    auto str = parcel->ReadString();
    return AniStringUtils::ToAni(env, str);
}

static bool MessageSequenceWriteString([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_string str)
{
    ZLOGI(LOG_LABEL, "[ANI] enter MessageSequenceWriteString func");
    auto parcel = AniObjectUtils::Unwrap<MessageParcel>(env, object);
    if (parcel == nullptr) {
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
        return ani_string{};
    }
    auto str = parcel->ReadInterfaceToken();
    std::string outString = Str16ToStr8(str.c_str());
    return AniStringUtils::ToAni(env, outString);
}

static void RemoteObjectConstructor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_string descriptor)
{
    ZLOGI(LOG_LABEL, "[ANI] enter RemoteObjectConstructor func");
    auto descriptorStr = AniStringUtils::ToStd(env, static_cast<ani_string>(descriptor));
    ani_ref saveRemote = nullptr;
    env->GlobalReference_Create(reinterpret_cast<ani_ref>(object), &saveRemote);
    auto objectRemoteHolder = new IPCObjectRemoteHolder(env, OHOS::Str8ToStr16(descriptorStr));
    objectRemoteHolder->Set(saveRemote);
    AniObjectUtils::Wrap<IPCObjectRemoteHolder>(env, object, objectRemoteHolder);
}

static ani_string GetRemoteObjectDescriptor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ZLOGI(LOG_LABEL, "[ANI] enter GetRemoteObjectDescriptor func");
    ani_string result_string{};
    auto objectRemoteHolder = AniObjectUtils::Unwrap<IPCObjectRemoteHolder>(env, object);
    if (objectRemoteHolder == nullptr) {
        env->String_NewUTF8("", 0, &result_string);
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
    ani_string result_string{};
    auto objectProxyHolder = AniObjectUtils::Unwrap<IPCObjectProxyHolder>(env, object);
    if (objectProxyHolder == nullptr) {
        env->String_NewUTF8("", 0, &result_string);
        return result_string;
    }
    auto descriptorStr = objectProxyHolder->GetDescriptor();
    ZLOGI(LOG_LABEL, "[ANI] get descriptor: %{public}s", descriptorStr.c_str());
    env->String_NewUTF8(descriptorStr.c_str(), descriptorStr.size(), &result_string);
    return result_string;
}

static ani_status BindMessageSequenceClassMethods(ani_env* env, ani_namespace& ns)
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

static ani_status BindMessageOptionClassMethods(ani_env* env, ani_namespace& ns)
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

static ani_status BindRemoteObjectClassMethods(ani_env* env, ani_namespace& ns)
{
    static const char *remoteObjClsName = "LRemoteObject;";
    ani_class remoteObjClass;
    if (ANI_OK != env->Namespace_FindClass(ns, remoteObjClsName, &remoteObjClass)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", remoteObjClsName);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"getDescriptor", nullptr, reinterpret_cast<void *>(GetRemoteObjectDescriptor)},
        ani_native_function {"<ctor>", "Lstd/core/String;:V", reinterpret_cast<void *>(RemoteObjectConstructor)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(remoteObjClass, methods.data(), methods.size())) {
        ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", remoteObjClsName);
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindRemoteProxyClassMethods(ani_env* env, ani_namespace& ns)
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

    *result = ANI_VERSION_1;
    return ANI_OK;
}

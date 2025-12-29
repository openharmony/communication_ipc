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
 #include <ani.h>
 #include <array>
 #include <cstring>
 
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
 
     auto messageOptionHolder = new (std::nothrow) StdSharedPtrHolder(std::make_shared<MessageOption>(flags, waitTime));
     if (messageOptionHolder == nullptr) {
         ZLOGE(LOG_LABEL, "[ANI] new StdSharedPtrHolder failed");
         return;
     }
     if (ANI_OK != AniObjectUtils::Wrap<StdSharedPtrHolder<MessageOption>>(env, obj, messageOptionHolder)) {
         ZLOGE(LOG_LABEL, "[ANI] Wrap StdSharedPtrHolder failed");
         delete messageOptionHolder;
         return;
     }
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
     auto objectRemoteHolder = new (std::nothrow) IPCObjectRemoteHolder(env, object, OHOS::Str8ToStr16(descriptorStr));
     if (objectRemoteHolder == nullptr) {
         ZLOGE(LOG_LABEL, "[ANI] new IPCObjectRemoteHolder failed");
         return;
     }
     if (ANI_OK != AniObjectUtils::Wrap<IPCObjectRemoteHolder>(env, object, objectRemoteHolder)) {
         ZLOGE(LOG_LABEL, "[ANI] Wrap IPCObjectRemoteHolder failed");
         delete objectRemoteHolder;
         return;
     }
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
 
 static ani_status BindMessageSequenceClassMethods(ani_env *env, const char *nsName)
 {
     const std::string msgSeqClsName = std::string(nsName).append(".MessageSequence");
     ani_class msgSequenceClass;
     if (ANI_OK != env->FindClass(msgSeqClsName.c_str(), &msgSequenceClass)) {
         ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", msgSeqClsName.c_str());
         return ANI_NOT_FOUND;
     }
 
     std::array methods = {
         ani_native_function {"readString", nullptr, reinterpret_cast<void *>(MessageSequenceReadString)},
         ani_native_function {"writeString", nullptr, reinterpret_cast<void *>(MessageSequenceWriteString)},
         ani_native_function {"readInterfaceToken", nullptr,
                              reinterpret_cast<void *>(MessageSequencereadInterfaceToken)},
     };
 
     if (ANI_OK != env->Class_BindNativeMethods(msgSequenceClass, methods.data(), methods.size())) {
         ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", msgSeqClsName.c_str());
         return ANI_ERROR;
     };
 
     return ANI_OK;
 }
 
 static ani_status BindMessageOptionClassMethods(ani_env *env, const char *nsName)
 {
     const std::string msgOptClsName = std::string(nsName).append(".MessageOption");
     ani_class msgOptionClass;
     if (ANI_OK != env->FindClass(msgOptClsName.c_str(), &msgOptionClass)) {
         ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", msgOptClsName.c_str());
         return ANI_NOT_FOUND;
     }
 
     std::array methods = {
         ani_native_function {"init", nullptr, reinterpret_cast<void *>(InitMessageOption)},
     };
 
     if (ANI_OK != env->Class_BindNativeMethods(msgOptionClass, methods.data(), methods.size())) {
         ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", msgOptClsName.c_str());
         return ANI_ERROR;
     };
 
     return ANI_OK;
 }
 
 static ani_status BindRemoteObjectClassMethods(ani_env *env, const char *nsName)
 {
     const std::string remoteObjClsName = std::string(nsName).append(".RemoteObject");
     ani_class remoteObjClass;
     if (ANI_OK != env->FindClass(remoteObjClsName.c_str(), &remoteObjClass)) {
         ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", remoteObjClsName.c_str());
         return ANI_NOT_FOUND;
     }
 
     std::array methods = {
         ani_native_function {"getDescriptor", nullptr, reinterpret_cast<void *>(GetRemoteObjectDescriptor)},
         ani_native_function {"init", "C{std.core.String}:", reinterpret_cast<void *>(RemoteObjectInit)},
     };
 
     if (ANI_OK != env->Class_BindNativeMethods(remoteObjClass, methods.data(), methods.size())) {
         ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", remoteObjClsName.c_str());
         return ANI_ERROR;
     };
 
     return ANI_OK;
 }
 
 static ani_status BindRemoteProxyClassMethods(ani_env *env, const char *nsName)
 {
     const std::string remoteProxyClsName = std::string(nsName).append(".RemoteProxy");
     ani_class remoteProxyClass;
     if (ANI_OK != env->FindClass(remoteProxyClsName.c_str(), &remoteProxyClass)) {
         ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", remoteProxyClsName.c_str());
         return ANI_NOT_FOUND;
     }
 
     std::array methods = {
         ani_native_function {"getDescriptor", nullptr, reinterpret_cast<void *>(GetRemoteProxyDescriptor)},
     };
 
     if (ANI_OK != env->Class_BindNativeMethods(remoteProxyClass, methods.data(), methods.size())) {
         ZLOGE(LOG_LABEL, "[ANI] Cannot bind native methods to '%{public}s'", remoteProxyClsName.c_str());
         return ANI_ERROR;
     };
 
     return ANI_OK;
 }
 
 static ani_status BindCleanerclassMethods(ani_env *env, const char *nsName)
 {
     auto cleanerCls = AniTypeFinder(env).FindClass(nsName, "Cleaner");
     return NativePtrCleaner(env).Bind(cleanerCls.value());
 }
 
 ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
 {
     ani_env *env;
     if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
         ZLOGE(LOG_LABEL, "[ANI] Unsupported ANI_VERSION_1");
         return ANI_ERROR;
     }
 
     static const char *nsName = "@ohos.rpc.rpc";
 
     if (ANI_OK != BindMessageSequenceClassMethods(env, nsName)) {
         ZLOGE(LOG_LABEL, "[ANI] BindMessageSequenceClassMethods failed");
         return ANI_ERROR;
     }
 
     if (ANI_OK != BindMessageOptionClassMethods(env, nsName)) {
         ZLOGE(LOG_LABEL, "[ANI] BindMessageOptionClassMethods failed");
         return ANI_ERROR;
     }
 
     if (ANI_OK != BindRemoteObjectClassMethods(env, nsName)) {
         ZLOGE(LOG_LABEL, "[ANI] BindRemoteObjectClassMethods failed");
         return ANI_ERROR;
     }
 
     if (ANI_OK != BindRemoteProxyClassMethods(env, nsName)) {
         ZLOGE(LOG_LABEL, "[ANI] BindRemoteProxyClassMethods failed");
         return ANI_ERROR;
     }
 
     if (ANI_OK != BindCleanerclassMethods(env, nsName)) {
         ZLOGE(LOG_LABEL, "[ANI] BindCleanerclassMethods failed");
         return ANI_ERROR;
     }
 
     *result = ANI_VERSION_1;
     return ANI_OK;
 }

 static ani_object CreateMessageSequence(ani_env *env, MessageParcel &msgParcel)
{
    ZLOGI(LOG_LABEL, "[ANI] enter CreateMessageSequence func");
    static const char *className = "@ohos.rpc.rpc.MessageSequence";
    ani_class cls;
    ani_object nullobj {};
    if (ANI_OK != env->FindClass(className, &cls)) {
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
    static const char *className = "std.core.Double";
    ani_class aniClass;
    if (env == nullptr) {
        return aniObject;
    }
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        ZLOGE(LOG_LABEL, "Not found '%{public}s'", className);
        return aniObject;
    }
    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "d:", &personInfoCtor)) {
        ZLOGE(LOG_LABEL, "Class_GetMethod Failed '%{public}s' <ctor>", className);
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, doubleValue)) {
        ZLOGE(LOG_LABEL, "Object_New Failed '%{public}s' <ctor>", className);
        return aniObject;
    }
    return aniObject;
}

static ani_object CreateMessageOption(ani_env *env, MessageOption &option)
{
    ZLOGI(LOG_LABEL, "[ANI] enter CreateMessageOption func, flags: %{public}u", option.GetFlags());

    static const char *className = "@ohos.rpc.rpc.MessageOption";
    ani_class cls;
    ani_object nullobj {};
    if (ANI_OK != env->FindClass(className, &cls)) {
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

IPCAniStub::IPCAniStub(ani_env *env, ani_object remoteObject, const std::u16string &descriptor)
    : IPCObjectStub(descriptor), env_(env)
{
    ZLOGI(LOG_LABEL, "[ANI] enter IPCAniStub ctor");
    if (env_ == nullptr) {
        return;
    }
    if (ANI_OK != env_->GlobalReference_Create(reinterpret_cast<ani_ref>(remoteObject), &saveRemote_)) {
        ZLOGE(LOG_LABEL, "[ANI] GlobalReference_Create failed");
    }
}
IPCAniStub::~IPCAniStub()
{
    ZLOGI(LOG_LABEL, "[ANI] enter IPCAniStub dtor");
    if (env_ == nullptr) {
        return;
    }
    if (ANI_OK != env_->GlobalReference_Delete(saveRemote_)) {
        ZLOGE(LOG_LABEL, "[ANI] GlobalReference_Delete failed");
    }
}

int IPCAniStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ZLOGI(LOG_LABEL, "[ANI] enter IPCAniStub OnRemoteRequest");
    ani_env *env = env_;
    static const char *remoteObjClsName = "@ohos.rpc.rpc.RemoteObject";
    if (env == nullptr) {
        return ANI_ERROR;
    }

    ani_class cls;
    if (ANI_OK != env->FindClass(remoteObjClsName, &cls)) {
        ZLOGE(LOG_LABEL, "[ANI] Not found '%{public}s'", remoteObjClsName);
        return ANI_NOT_FOUND;
    }

    ani_object aniData = CreateMessageSequence(env, data);
    ani_object aniReply = CreateMessageSequence(env, reply);
    ani_object aniOption = CreateMessageOption(env, option);

    auto obj = reinterpret_cast<ani_object>(saveRemote_);
    ZLOGI(LOG_LABEL, "[ANI] before Object_CallMethodByName_Void onRemoteMessageRequestSync");
    ani_boolean result;
    if (ANI_OK !=
        env_->Object_CallMethodByName_Boolean(
            obj, "onRemoteMessageRequestSync", nullptr, &result, (ani_double)code, aniData, aniReply, aniOption)) {
        AniError::ThrowError(env_, CALL_JS_METHOD_ERROR);
        return ANI_ERROR;
    }
    ZLOGI(LOG_LABEL, "[ANI] after Object_CallMethodByName_Void onRemoteMessageRequestSync");

    return result;
}
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

DeathRecipientImpl::DeathRecipientImpl(::ohos::rpc::rpc::DeathRecipient jsObjRef) : jsObjRef_(jsObjRef)
{
}

void DeathRecipientImpl::OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object)
{
    jsObjRef_.onRemoteDied();
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call onRemoteDied failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
    }
}

// ANIRemoteObject
ANIRemoteObject::ANIRemoteObject(const std::u16string &descriptor, ::ohos::rpc::rpc::weak::RemoteObject jsObj,
    bool hasCallingInfo) : OHOS::IPCObjectStub(descriptor), jsObjRef_(jsObj), hasCallingInfoAni_(hasCallingInfo)
{
}

ANIRemoteObject::~ANIRemoteObject()
{
}

::ohos::rpc::rpc::CallingInfo ANIRemoteObject::GetCallingInfo()
{
    bool isLocalCalling = IPCSkeleton::IsLocalCalling();
    if (isLocalCalling) {
        return {
            IPCSkeleton::GetCallingPid(),
            IPCSkeleton::GetCallingUid(),
            IPCSkeleton::GetCallingTokenID(),
            "",
            "",
            IPCSkeleton::IsLocalCalling()
        };
    }
    return {
        IPCSkeleton::GetCallingPid(),
        IPCSkeleton::GetCallingUid(),
        IPCSkeleton::GetCallingTokenID(),
        IPCSkeleton::GetCallingDeviceID(),
        IPCSkeleton::GetLocalDeviceID(),
        IPCSkeleton::IsLocalCalling()
    };
}

int ANIRemoteObject::OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
    OHOS::MessageOption &option)
{
    auto jsData = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(&data);
    jsData->AddJsObjWeakRef(jsData);
    auto jsReply = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(&reply);
    jsReply->AddJsObjWeakRef(jsReply);
    auto jsOption = taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(option.GetFlags(),
        option.GetWaitTime());
    int ret = OHOS::ERR_UNKNOWN_TRANSACTION;
    if (hasCallingInfoAni_) {
        ret = jsObjRef_.value()->OnRemoteMessageRequestWithCallingInfo(code, jsData, jsReply, jsOption,
            GetCallingInfo());
    } else {
        ret = jsObjRef_.value()->OnRemoteMessageRequest(code, jsData, jsReply, jsOption);
    }
    return ret ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
}

int ANIRemoteObject::GetObjectType() const
{
    return OBJECT_TYPE_JAVASCRIPT;
}

::ohos::rpc::rpc::RemoteObject ANIRemoteObject::GetJsObject()
{
    return jsObjRef_.value();
}

// IRemoteBrokerImpl
::ohos::rpc::rpc::IRemoteObjectUnion IRemoteBrokerImpl::AsObject()
{
    TH_THROW(std::runtime_error, "asObject should be implemented in ets");
}

// RemoteProxyImpl
RemoteProxyImpl::RemoteProxyImpl(uintptr_t nativePtr, bool isCreateJsRemoteObj)
{
    if (reinterpret_cast<void*>(nativePtr) == nullptr) {
        ZLOGE(LOG_LABEL, "nativePtr is null");
        TH_THROW(std::runtime_error, "RemoteProxyImpl nativePtr is nullptr");
        return;
    }
    if (isCreateJsRemoteObj) {
        auto proxy = reinterpret_cast<RemoteObjectTaiheAni *>(nativePtr);
        if (proxy == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast nativePtr failed");
            TH_THROW(std::runtime_error, "RemoteProxyImpl reinterpret_cast nativePtr failed");
            return;
        }
        auto ipcObjectProxy = reinterpret_cast<OHOS::IPCObjectProxy *>((proxy->nativeObject_).GetRefPtr());
        if (ipcObjectProxy == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast nativeObject failed");
            TH_THROW(std::runtime_error, "RemoteProxyImpl reinterpret_cast nativeObject failed");
            return;
        }
        cachedObject_ = ipcObjectProxy;
        return;
    }
    auto proxy = reinterpret_cast<OHOS::IPCObjectProxy *>(nativePtr);
    if (proxy == nullptr) {
        ZLOGE(LOG_LABEL, "reinterpret_cast nativePtr failed");
        TH_THROW(std::runtime_error, "RemoteProxyImpl reinterpret_cast nativePtr failed");
        return;
    }
    cachedObject_ = proxy;
}

::ohos::rpc::rpc::IRemoteBroker RemoteProxyImpl::GetLocalInterface(::taihe::string_view descriptor)
{
    ZLOGE(LOG_LABEL, "only RemoteObject permitted");
    auto jsBroker = taihe::make_holder<IRemoteBrokerImpl, ::ohos::rpc::rpc::IRemoteBroker>();
    RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_ONLY_REMOTE_OBJECT_PERMITTED_ERROR, jsBroker);
}

::ohos::rpc::rpc::RequestResult RemoteProxyImpl::SendMessageRequestSync(
    int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data,
    ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options)
{
    auto nativeData = reinterpret_cast<OHOS::MessageParcel *>(data->GetNativePtr());
    auto nativeReply = reinterpret_cast<OHOS::MessageParcel *>(reply->GetNativePtr());
    auto nativeOptions = reinterpret_cast<OHOS::MessageOption *>(options->GetNativePtr());
    int32_t ret = cachedObject_->SendRequest(code, *nativeData, *nativeReply, *nativeOptions);
    return { ret, code, data, reply };
}

void RemoteProxyImpl::RegisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags)
{
    std::lock_guard<std::mutex> lock(deathMutex_);
    OHOS::sptr<DeathRecipientImpl> nativeDeathRecipient = new (std::nothrow) DeathRecipientImpl(recipient);
    if (!cachedObject_->AddDeathRecipient(nativeDeathRecipient)) {
        ZLOGE(LOG_LABEL, "AddDeathRecipient failed");
        return;
    }

    deathRecipientMap_.emplace(const_cast<::ohos::rpc::rpc::DeathRecipient *>(&recipient), nativeDeathRecipient);
}

void RemoteProxyImpl::UnregisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags)
{
    std::lock_guard<std::mutex> lock(deathMutex_);
    auto it = deathRecipientMap_.find(const_cast<::ohos::rpc::rpc::DeathRecipient *>(&recipient));
    if (it != deathRecipientMap_.end()) {
        if (!cachedObject_->RemoveDeathRecipient(it->second)) {
            ZLOGE(LOG_LABEL, "RemoveDeathRecipient failed");
        }
        deathRecipientMap_.erase(const_cast<::ohos::rpc::rpc::DeathRecipient *>(&recipient));
    } else {
        ZLOGE(LOG_LABEL, "DeathRecipient not found");
    }
    return;
}

::taihe::string RemoteProxyImpl::GetDescriptor()
{
    return OHOS::Str16ToStr8(cachedObject_->GetInterfaceDescriptor());
}

bool RemoteProxyImpl::IsObjectDead()
{
    return cachedObject_->IsObjectDead();
}

int64_t RemoteProxyImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(cachedObject_.GetRefPtr());
}

void RemoteProxyImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::RemoteProxy obj)
{
    jsObjRef_ = std::optional<::ohos::rpc::rpc::weak::RemoteProxy>(std::in_place, obj);
}

::ohos::rpc::rpc::RemoteProxy RemoteProxyImpl::CreateRemoteProxyFromNative(uintptr_t nativePtr)
{
    ::ohos::rpc::rpc::RemoteProxy obj = taihe::make_holder<RemoteProxyImpl, ::ohos::rpc::rpc::RemoteProxy>(nativePtr);
    obj->AddJsObjWeakRef(obj);
    return obj;
}

int32_t RemoteProxyImpl::GetPingTransaction()
{
    return static_cast<int32_t>(PING_TRANSACTION);
}

int32_t RemoteProxyImpl::GetDumpTransaction()
{
    return static_cast<int32_t>(DUMP_TRANSACTION);
}

int32_t RemoteProxyImpl::GetInterfaceTransaction()
{
    return static_cast<int32_t>(INTERFACE_TRANSACTION);
}

int32_t RemoteProxyImpl::GetMinTransactionId()
{
    return static_cast<int32_t>(MIN_TRANSACTION_ID);
}

int32_t RemoteProxyImpl::GetMaxTransactionId()
{
    return static_cast<int32_t>(MAX_TRANSACTION_ID);
}

// ParcelableImpl
bool ParcelableImpl::Marshalling(::ohos::rpc::rpc::weak::MessageSequence dataOut)
{
    TH_THROW(std::runtime_error, "mashalling not implemented");
}

bool ParcelableImpl::Unmarshalling(::ohos::rpc::rpc::weak::MessageSequence dataIn)
{
    TH_THROW(std::runtime_error, "unmarshalling not implemented");
}

// AshmemImpl
// only be used for returning invalid Ashmem.
AshmemImpl::AshmemImpl()
{
}

AshmemImpl::AshmemImpl(const char *name, int32_t size)
{
    ashmem_ = OHOS::Ashmem::CreateAshmem(name, size);
}

AshmemImpl::AshmemImpl(OHOS::sptr<OHOS::Ashmem> ashmem)
{
    int32_t fd = ashmem->GetAshmemFd();
    int32_t size = ashmem->GetAshmemSize();
    if (fd < 0 || size == 0) {
        ZLOGE(LOG_LABEL, "fd < 0 or size == 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        ZLOGE(LOG_LABEL, "fail to dup fd:%{public}d", dupFd);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_OS_DUP_ERROR);
    }
    OHOS::sptr<OHOS::Ashmem> newAshmem(new (std::nothrow) OHOS::Ashmem(dupFd, size));
    if (newAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "fail to create new Ashmem");
        close(dupFd);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_PARCEL_MEMORY_ALLOC_ERROR);
    }
    ashmem_ = newAshmem;
}

int64_t AshmemImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(ashmem_.GetRefPtr());
}

void AshmemImpl::MapReadWriteAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    ashmem_->MapReadAndWriteAshmem();
}

int32_t AshmemImpl::GetAshmemSize()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR, 0);
    return ashmem_->GetAshmemSize();
}

void AshmemImpl::SetProtectionType(int32_t protectionType)
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_IOCTL_ERROR);
    ashmem_->SetProtection(protectionType);
}

void AshmemImpl::MapReadonlyAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    ashmem_->MapReadOnlyAshmem();
}

void AshmemImpl::MapTypedAshmem(int32_t mapType)
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    if (mapType > MAP_PROT_MAX) {
        ZLOGE(LOG_LABEL, "napiAshmem mapType error");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    ashmem_->MapAshmem(mapType);
}

void AshmemImpl::CloseAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    ashmem_->CloseAshmem();
}

void AshmemImpl::UnmapAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    ashmem_->UnmapAshmem();
}

::taihe::array<uint8_t> AshmemImpl::ReadDataFromAshmem(int32_t size, int32_t offset)
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(ashmem_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_FROM_ASHMEM_ERROR, ::taihe::array<uint8_t>(nullptr, 0));
    int32_t ashmemSize = GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() ||
        offset < 0 || offset > std::numeric_limits<int32_t>::max() ||
        (size + offset) > ashmemSize || ashmemSize < 0) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}d offset:%{public}d", size, offset);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_FROM_ASHMEM_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    const void *rawData = ashmem_->ReadFromAshmem(size, offset);
    if (rawData == nullptr) {
        ZLOGE(LOG_LABEL, "rawData is null");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_FROM_ASHMEM_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    const uint8_t* bytePtr = static_cast<const uint8_t*>(rawData);
    std::vector<uint8_t> res(size);
    std::copy(bytePtr, bytePtr + size, res.begin());
    return ::taihe::array<uint8_t>(res);
}

void AshmemImpl::WriteDataToAshmem(::taihe::array_view<uint8_t> buf, int32_t size, int32_t offset)
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    int32_t ashmemSize = GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() ||
        offset < 0 || offset > std::numeric_limits<int32_t>::max() ||
        (size + offset) > ashmemSize || ashmemSize < 0) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}d offset:%{public}d", size, offset);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_TO_ASHMEM_ERROR);
        return;
    }
    if (!ashmem_->WriteToAshmem(static_cast<const void*>(buf.data()), size, offset)) {
        ZLOGE(LOG_LABEL, "write data failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_TO_ASHMEM_ERROR);
    }
}

OHOS::sptr<OHOS::Ashmem> AshmemImpl::GetAshmem()
{
    return ashmem_;
}

::ohos::rpc::rpc::Ashmem AshmemImpl::CreateAshmem_WithTwoParam(::taihe::string_view name, int32_t size)
{
    return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(name.data(), size);
}

::ohos::rpc::rpc::Ashmem AshmemImpl::CreateAshmem_WithOneParam(::ohos::rpc::rpc::weak::Ashmem ashmem)
{
    OHOS::sptr<OHOS::Ashmem> nativeAshmem = reinterpret_cast<OHOS::Ashmem *>(ashmem->GetNativePtr());
    return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(nativeAshmem);
}

int32_t AshmemImpl::GetProtExec()
{
    return static_cast<int32_t>(PROT_EXEC);
}

int32_t AshmemImpl::GetProtNone()
{
    return static_cast<int32_t>(PROT_NONE);
}

int32_t AshmemImpl::GetProtRead()
{
    return static_cast<int32_t>(PROT_READ);
}

int32_t AshmemImpl::GetProtWrite()
{
    return static_cast<int32_t>(PROT_WRITE);
}

// RemoteObjectImpl
// ETS to ANI
RemoteObjectImpl::RemoteObjectImpl(::taihe::string_view descriptor) : desc_(descriptor)
{
}

// ANI to ETS
RemoteObjectImpl::RemoteObjectImpl(uintptr_t nativePtr) : desc_("")
{
    if (reinterpret_cast<void*>(nativePtr) == nullptr) {
        ZLOGE(LOG_LABEL, "nativePtr is null");
        TH_THROW(std::runtime_error, "nativePtr is null");
        return;
    }
    
    auto stub = reinterpret_cast<OHOS::IPCObjectStub *>(nativePtr);
    if (stub == nullptr) {
        ZLOGE(LOG_LABEL, "reinterpret_cast nativePtr failed");
        TH_THROW(std::runtime_error, "reinterpret_cast nativePtr failed");
        return;
    }
    desc_ = OHOS::Str16ToStr8(stub->GetObjectDescriptor());
    sptrCachedObject_ = stub;
}

int32_t RemoteObjectImpl::GetCallingPid()
{
    return OHOS::IPCSkeleton::GetCallingPid();
}

int32_t RemoteObjectImpl::GetCallingUid()
{
    return OHOS::IPCSkeleton::GetCallingUid();
}

void RemoteObjectImpl::ModifyLocalInterface(::ohos::rpc::rpc::weak::IRemoteBroker localInterface,
    ::taihe::string_view descriptor)
{
    if (std::string(descriptor).size() >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "string length exceeds %{public}zu bytes", MAX_BYTES_LENGTH);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    jsLocalInterface_ = localInterface;
    desc_ = descriptor;
}

::ohos::rpc::rpc::IRemoteBroker RemoteObjectImpl::GetLocalInterface(::taihe::string_view descriptor)
{
    auto jsBroker = taihe::make_holder<IRemoteBrokerImpl, ::ohos::rpc::rpc::IRemoteBroker>();
    if (std::string(descriptor).size() >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "string length exceeds %{public}zu bytes", MAX_BYTES_LENGTH);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR, jsBroker);
    }
    if (descriptor != desc_) {
        ZLOGE(LOG_LABEL, "descriptor: %{public}s mispatch, expected: %{public}s", descriptor.data(), desc_.data());
        return jsBroker;
    }
    if (!jsLocalInterface_.has_value()) {
        ZLOGE(LOG_LABEL, "jsLocalInterface_ is empty!");
        return jsBroker;
    }
    return jsLocalInterface_.value();
}

::ohos::rpc::rpc::RequestResult RemoteObjectImpl::SendMessageRequestSync(
    int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data,
    ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options)
{
    int ret = OHOS::ERR_UNKNOWN_TRANSACTION;
    if (hasCallingInfo_) {
        auto *aniObj = reinterpret_cast<OHOS::ANIRemoteObject *>(GetNativePtr());
        ret = jsObjRef_.value()->OnRemoteMessageRequestWithCallingInfo(code, data, reply, options,
            aniObj->GetCallingInfo());
    } else {
        ret = jsObjRef_.value()->OnRemoteMessageRequest(code, data, reply, options);
    }
    int32_t retVal = ret ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
    return { retVal, code, data, reply };
}

bool RemoteObjectImpl::OnRemoteMessageRequestWithCallingInfo(int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data, ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options, ::ohos::rpc::rpc::CallingInfo const& callingInfo)
{
    TH_THROW(std::runtime_error, "OnRemoteMessageRequestWithCallingInfo should be implemented in ets");
}

bool RemoteObjectImpl::OnRemoteMessageRequest(int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data, ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options)
{
    TH_THROW(std::runtime_error, "OnRemoteMessageRequest should be implemented in ets");
}

void RemoteObjectImpl::RegisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags)
{
    ZLOGI(LOG_LABEL, "only RemoteProxy needed");
    RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_ONLY_PROXY_OBJECT_PERMITTED_ERROR);
}

void RemoteObjectImpl::UnregisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags)
{
    ZLOGI(LOG_LABEL, "only RemoteProxy needed");
    RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_ONLY_PROXY_OBJECT_PERMITTED_ERROR);
}

::taihe::string RemoteObjectImpl::GetDescriptor()
{
    return desc_;
}

bool RemoteObjectImpl::IsObjectDead()
{
    return false;
}

OHOS::sptr<OHOS::IPCObjectStub> RemoteObjectImpl::GetNativeObject()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    // grab an strong reference to the object,
    // so it will not be freed util this reference released.
    if (sptrCachedObject_ != nullptr) {
        return sptrCachedObject_;
    }
    OHOS::sptr<OHOS::IPCObjectStub> tmp = wptrCachedObject_.promote();
    if (tmp == nullptr) {
        std::u16string descStr16(desc_.begin(), desc_.end());
        tmp = new (std::nothrow) ANIRemoteObject(descStr16, jsObjRef_.value());
        if (tmp == nullptr) {
            ZLOGE(LOG_LABEL, "new ANIRemoteObject failed");
            return nullptr;
        }
        wptrCachedObject_ = tmp;
    }
    return tmp;
}

int64_t RemoteObjectImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(sptrCachedObject_ != nullptr ?
        sptrCachedObject_.GetRefPtr() : wptrCachedObject_.GetRefPtr());
}

void RemoteObjectImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::RemoteObject obj, bool isNative, bool hasCallingInfo)
{
    hasCallingInfo_ = hasCallingInfo;
    jsObjRef_ = std::optional<::ohos::rpc::rpc::RemoteObject>(std::in_place, obj);
    std::u16string descStr16(desc_.begin(), desc_.end());
    ANIRemoteObject *newObject = new (std::nothrow) ANIRemoteObject(descStr16, jsObjRef_.value(), hasCallingInfo);
    if (newObject == nullptr) {
        ZLOGE(LOG_LABEL, "new ANIRemoteObject failed");
        return;
    }
    if (!isNative) {
        wptrCachedObject_ = newObject;
    } else {
        sptrCachedObject_ = newObject;
    }
}

::ohos::rpc::rpc::RemoteObject RemoteObjectImpl::CreateRemoteObject(::ohos::rpc::rpc::weak::RemoteObject jsSelf,
    ::taihe::string_view descriptor, ::taihe::callback_view<bool()> hasCallingInfoCB)
{
    ::ohos::rpc::rpc::RemoteObject obj = taihe::make_holder<RemoteObjectImpl,
        ::ohos::rpc::rpc::RemoteObject>(descriptor);
    obj->AddJsObjWeakRef(jsSelf, true, hasCallingInfoCB());
    return obj;
}

::ohos::rpc::rpc::RemoteObject RemoteObjectImpl::CreateRemoteObjectFromNative(uintptr_t nativePtr)
{
    ::ohos::rpc::rpc::RemoteObject obj = taihe::make_holder<RemoteObjectImpl,
        ::ohos::rpc::rpc::RemoteObject>(nativePtr);
    obj->AddJsObjWeakRef(obj, false, false);
    return obj;
}

// MessageSequenceImpl
MessageSequenceImpl::MessageSequenceImpl()
{
    nativeParcel_ = new (std::nothrow) OHOS::MessageParcel();
    if (nativeParcel_ == nullptr) {
        ZLOGE(LOG_LABEL, "create MessageParcel failed");
        taihe::set_error("create MessageParcel failed");
    }
    isOwner_ = true;
}

MessageSequenceImpl::MessageSequenceImpl(OHOS::MessageParcel* messageparcel)
{
    nativeParcel_ = messageparcel;
    isOwner_ = false;
}

MessageSequenceImpl::~MessageSequenceImpl()
{
    Reclaim();
}

void MessageSequenceImpl::Reclaim()
{
    if (isOwner_ && nativeParcel_ != nullptr) {
        delete nativeParcel_;
    }
    nativeParcel_ = nullptr;
}

int64_t MessageSequenceImpl::GetMessageSequenceImpl()
{
    return reinterpret_cast<int64_t>(this);
}

::ohos::rpc::rpc::MessageSequence MessageSequenceImpl::RpcTransferStaicImpl(uintptr_t input)
{
    ZLOGE(LOG_LABEL, "RpcTransferStaicImpl start");
    void* nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(taihe::get_env(), reinterpret_cast<ani_object>(input), &nativePtr) ||
        !nativePtr) {
        ZLOGE(LOG_LABEL, "arkts_esvalue_unwrap failed");
        return taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>();
    }

    auto* napiMessageSequence = reinterpret_cast<NAPI_MessageSequence*>(nativePtr);
    if (!napiMessageSequence) {
        ZLOGE(LOG_LABEL, "napiMessageSequence is nullptr");
        return taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>();
    }

    OHOS::MessageParcel* parcel = napiMessageSequence->GetMessageParcel().get();
    if (!parcel) {
        ZLOGE(LOG_LABEL, "parcel is nullptr");
        return taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>();
    }

    auto jsref = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(parcel);
    jsref->AddJsObjWeakRef(jsref);
    return jsref;
}

uintptr_t MessageSequenceImpl::RpcTransferDynamicImpl(::ohos::rpc::rpc::MessageSequence obj)
{
    ZLOGE(LOG_LABEL, "RpcTransferDynamicImpl start");
    int64_t impRawPtr = obj->GetMessageSequenceImpl();
    auto* impl = reinterpret_cast<MessageSequenceImpl*>(impRawPtr);
    if (!impl || !impl->GetNativeParcel()) {
        ZLOGE(LOG_LABEL, "impl or parcel is nullptr");
        return 0;
    }

    napi_env jsenv;
    if (!arkts_napi_scope_open(taihe::get_env(), &jsenv)) {
        ZLOGE(LOG_LABEL, "arkts_napi_scope_open failed");
        return 0;
    }

    napi_value global = nullptr;
    napi_status status = napi_get_global(jsenv, &global);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_get_global failed");
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        return 0;
    }

    napi_value jsMessageSequence = nullptr;
    CreateJsMessageSequence(jsenv, status, global, &jsMessageSequence);
    if (jsMessageSequence == nullptr) {
        ZLOGE(LOG_LABEL, "CreateJsMessageSequence failed");
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        return 0;
    }

    auto messageSequence = new (std::nothrow) NAPI_MessageSequence(jsenv, jsMessageSequence, impl->GetNativeParcel());
    status = napi_wrap(
        jsenv,
        jsMessageSequence,
        messageSequence,
        [](napi_env env, void *data, void *hint) {
            NAPI_MessageSequence *messageSequence = reinterpret_cast<NAPI_MessageSequence *>(data);
            delete messageSequence;
        },
        nullptr,
        nullptr);

    uintptr_t result = 0;
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_wrap failed");
        delete messageSequence;
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        return 0;
    } else {
        arkts_napi_scope_close_n(jsenv, 1, &jsMessageSequence, reinterpret_cast<ani_ref*>(&result));
    }
    return result;
}

void MessageSequenceImpl::CreateJsMessageSequence(napi_env jsenv, napi_status status, napi_value global,
    napi_value* jsMessageSequence)

{
    napi_value constructor = nullptr;
    status = napi_get_named_property(jsenv, global, "IPCSequenceConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get constructor failed");
        return;
    }

    status = napi_new_instance(jsenv, constructor, 0, nullptr, jsMessageSequence);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_new_instance failed");
        return;
    }
}

void MessageSequenceImpl::WriteRemoteObject(::ohos::rpc::rpc::IRemoteObjectUnion const& object)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
        auto &remoteStub = object.get_remoteObject_ref();
        OHOS::sptr<OHOS::IRemoteObject> nativeStub =
            reinterpret_cast<OHOS::IRemoteObject *>(remoteStub->GetNativePtr());
        if (nativeStub == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast to IRemoteObject failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        bool result = nativeParcel_->WriteRemoteObject(nativeStub);
        if (!result) {
            ZLOGE(LOG_LABEL, "write RemoteObject failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        return;
    } else if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
        auto &remoteProxy = object.get_remoteProxy_ref();
        auto nativeProxy = reinterpret_cast<OHOS::IPCObjectProxy *>(remoteProxy->GetNativePtr());
        bool result = nativeParcel_->WriteRemoteObject(nativeProxy);
        if (!result) {
            ZLOGE(LOG_LABEL, "write RemoteProxy failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        return;
    } else {
        ZLOGE(LOG_LABEL, "unknown tag: %{public}d", object.get_tag());
        TH_THROW(std::runtime_error, "unknown tag");
    }
}

::ohos::rpc::rpc::IRemoteObjectUnion MessageSequenceImpl::ReadRemoteObject()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::ohos::rpc::rpc::IRemoteObjectUnion::make_errRet());
    OHOS::sptr<OHOS::IRemoteObject> obj = nativeParcel_->ReadRemoteObject();
    if (obj == nullptr) {
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::ohos::rpc::rpc::IRemoteObjectUnion::make_errRet());
    }
    if (obj->IsProxyObject()) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(obj.GetRefPtr());
        auto jsProxy = RemoteProxyImpl::CreateRemoteProxyFromNative(addr);
        return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteProxy(jsProxy);
    } else {
        auto stub = reinterpret_cast<OHOS::IPCObjectStub *>(obj.GetRefPtr());
        if (stub->GetObjectType() == OHOS::IPCObjectStub::OBJECT_TYPE_JAVASCRIPT) {
            auto aniStub = reinterpret_cast<ANIRemoteObject *>(obj.GetRefPtr());
            return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteObject(aniStub->GetJsObject());
        } else {
            uintptr_t addr = reinterpret_cast<uintptr_t>(stub);
            auto jsStub = RemoteObjectImpl::CreateRemoteObjectFromNative(addr);
            return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteObject(jsStub);
        }
    }
}

void MessageSequenceImpl::WriteInterfaceToken(::taihe::string_view token)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (token.size() >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "token is too large");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    std::u16string tokenStr(token.begin(), token.end());
    bool result = nativeParcel_->WriteInterfaceToken(tokenStr);
    if (!result) {
        ZLOGE(LOG_LABEL, "write interface token failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

int64_t unwrapRemoteObject(::ohos::rpc::rpc::IRemoteObjectUnion const& obj)
{
    if (obj.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
        auto &remoteStub = obj.get_remoteObject_ref();
        int64_t objectptr = remoteStub->GetNativePtr();
        return objectptr;
    }
    if (obj.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
        auto &remoteProxy = obj.get_remoteProxy_ref();
        int64_t proxyptr = remoteProxy->GetNativePtr();
        return proxyptr;
    }
    return 0;
}

::ohos::rpc::rpc::IRemoteObjectUnion wrapRemoteObject(int64_t nativePtr)
{
    if (reinterpret_cast<void*>(nativePtr) == nullptr) {
        ZLOGE(LOG_LABEL, "nativePtr is nullptr");
        TH_THROW(std::runtime_error, "nativePtr is null");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::ohos::rpc::rpc::IRemoteObjectUnion::make_errRet());
    }
    ::ohos::rpc::rpc::RemoteProxy obj = taihe::make_holder<RemoteProxyImpl,
        ::ohos::rpc::rpc::RemoteProxy>(nativePtr, true);
    return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteProxy(obj);
}

::taihe::string MessageSequenceImpl::ReadInterfaceToken()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "");
    std::u16string result = nativeParcel_->ReadInterfaceToken();
    return OHOS::Str16ToStr8(result);
}

int32_t MessageSequenceImpl::GetCapacity()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetDataCapacity());
    return result;
}

void MessageSequenceImpl::SetCapacity(int32_t size)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->SetDataCapacity(size);
    if (!result) {
        ZLOGE(LOG_LABEL, "set data capacity failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteNoException()
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt32(0);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::ReadException()
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t code = nativeParcel_->ReadInt32();
    if (code == 0) {
        ZLOGE(LOG_LABEL, "ReadException failed, no exception");
        return;
    }
    std::u16string result = nativeParcel_->ReadString16();
    taihe::set_business_error(code, OHOS::Str16ToStr8(result));
}

void MessageSequenceImpl::WriteInt(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt32(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteLong(int64_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt64(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int64 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteBoolean(bool val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt8(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int8 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteChar(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteUint8(static_cast<uint8_t>(val));
    if (!result) {
        ZLOGE(LOG_LABEL, "write uint8 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteString(::taihe::string_view val)
{
    if (val.size() >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "write string failed, string size:%{public}zu is too large", val.size());
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 * val.size(), nativeParcel_, (nativeParcel_->GetMaxCapacity()));
    std::u16string str(val.begin(), val.end());
    bool result = nativeParcel_->WriteString16(str);
    if (!result) {
        ZLOGE(LOG_LABEL, "write string16 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteParcelable(::ohos::rpc::rpc::weak::Parcelable val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteInt32(1);
    val->Marshalling(*jsObjRef_);
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call marshalling failed");
        nativeParcel_->RewindWrite(pos);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
    }
}

void MessageSequenceImpl::WriteByteArray(::taihe::array_view<int8_t> byteArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = byteArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + (BYTE_SIZE_8 * arrayLength), nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt8(byteArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int8 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteShortArray(::taihe::array_view<int32_t> shortArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = shortArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(int16_t) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt16(static_cast<int16_t>(shortArray[i]));
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int16 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteIntArray(::taihe::array_view<int32_t> intArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = intArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 * (arrayLength + 1), nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt32(intArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int32 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteLongArray(::taihe::array_view<int64_t> longArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = longArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(int64_t) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt64(longArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int64 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteFloatArray(::taihe::array_view<double> floatArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = floatArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(double) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteDouble(floatArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write float failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteDoubleArray(::taihe::array_view<double> doubleArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = doubleArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(double) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteDouble(doubleArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write double failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteBooleanArray(::taihe::array_view<bool> booleanArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = booleanArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + (BYTE_SIZE_8 * arrayLength), nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt8(static_cast<int8_t>(booleanArray[i]));
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int8 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteCharArray(::taihe::array_view<int32_t> charArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = charArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(uint8_t) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteUint8(static_cast<uint8_t>(charArray[i]));
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write uint8 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteStringArray(::taihe::array_view<::taihe::string> stringArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = stringArray.size();
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        if (stringArray[i].size() >= MAX_BYTES_LENGTH) {
            ZLOGE(LOG_LABEL, "string length is too long, index:%{public}zu, size:%{public}zu",
                i, stringArray[i].size());
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
        }
        REWIND_IF_WRITE_CHECK_FAIL(BYTE_SIZE_32 + (BYTE_SIZE_16 * stringArray[i].size()), pos, nativeParcel_,
            (nativeParcel_->GetMaxCapacity()));
        std::u16string str(stringArray[i].begin(), stringArray[i].end());
        result = nativeParcel_->WriteString16(str);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write string16 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = parcelableArray.size();
    size_t pos = nativeParcel_->GetWritePosition();
    if (!(nativeParcel_->WriteUint32(arrayLength))) {
        ZLOGE(LOG_LABEL, "write array length failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    for (size_t i = 0; i < arrayLength; i++) {
        nativeParcel_->WriteInt32(1);
        parcelableArray[i]->Marshalling(*jsObjRef_);
        if (taihe::has_error()) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "call marshalling failed, element index:%{public}zu", i);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteRemoteObjectArray(::taihe::array_view<::ohos::rpc::rpc::IRemoteObjectUnion> objectArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = objectArray.size();
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(::ohos::rpc::rpc::IRemoteObjectUnion) * arrayLength,
        nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    if (!(nativeParcel_->WriteUint32(arrayLength))) {
        ZLOGE(LOG_LABEL, "write array length failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    for (size_t i = 0; i < arrayLength; i++) {
        if (objectArray[i].get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
            auto &remoteStub = objectArray[i].get_remoteObject_ref();
            OHOS::sptr<OHOS::IRemoteObject> nativeStub =
                reinterpret_cast<OHOS::IRemoteObject *>(remoteStub->GetNativePtr());
            if (nativeStub == nullptr) {
                ZLOGE(LOG_LABEL, "reinterpret_cast to IRemoteObject failed");
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
            bool result = nativeParcel_->WriteRemoteObject(nativeStub);
            if (!result) {
                ZLOGE(LOG_LABEL, "write RemoteObject failed");
                nativeParcel_->RewindWrite(pos);
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        } else if (objectArray[i].get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
            auto &remoteProxy = objectArray[i].get_remoteProxy_ref();
            auto nativeProxy = reinterpret_cast<OHOS::IPCObjectProxy *>(remoteProxy->GetNativePtr());
            bool result = nativeParcel_->WriteRemoteObject(nativeProxy);
            if (!result) {
                ZLOGE(LOG_LABEL, "write RemoteProxy failed");
                nativeParcel_->RewindWrite(pos);
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        } else {
            ZLOGE(LOG_LABEL, "unknown tag: %{public}d", objectArray[i].get_tag());
            TH_THROW(std::runtime_error, "unknown tag");
        }
    }
}

int32_t MessageSequenceImpl::ReadInt()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return nativeParcel_->ReadInt32();
}

int64_t MessageSequenceImpl::ReadLong()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return nativeParcel_->ReadInt64();
}

bool MessageSequenceImpl::ReadBoolean()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, false);
    return static_cast<bool>(nativeParcel_->ReadInt8());
}

::taihe::string MessageSequenceImpl::ReadString()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "");
    return OHOS::Str16ToStr8(nativeParcel_->ReadString16());
}

void MessageSequenceImpl::ReadParcelable(::ohos::rpc::rpc::weak::Parcelable dataIn)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t flags = nativeParcel_->ReadInt32();
    if (flags != 1) {
        ZLOGE(LOG_LABEL, "read parcelable failed, flags:%{public}d", flags);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    dataIn->Unmarshalling(*jsObjRef_);
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call marshalling failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
    }
}

::taihe::array<int32_t> MessageSequenceImpl::ReadIntArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<int32_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<int32_t>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_32,
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
    ::taihe::array<int32_t> res(arrayLength);
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt32(res[i])) {
            ZLOGE(LOG_LABEL, "read int32 failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<int32_t>(nullptr, 0)));
        }
    }
    return res;
}

::taihe::array<double> MessageSequenceImpl::ReadDoubleArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<double>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<double>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(double),
        nativeParcel_, (::taihe::array<double>(nullptr, 0)));
    ::taihe::array<double> res(arrayLength);
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadDouble(res[i])) {
            ZLOGE(LOG_LABEL, "read double failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<double>(nullptr, 0)));
        }
    }
    return res;
}

::taihe::array<bool> MessageSequenceImpl::ReadBooleanArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<bool>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<bool>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_8,
        nativeParcel_, (::taihe::array<bool>(nullptr, 0)));
    ::taihe::array<bool> res(arrayLength);
    int8_t val;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt8(val)) {
            ZLOGE(LOG_LABEL, "read bool failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<bool>(nullptr, 0)));
        }
        res[i] = (val != 0) ? true : false;
    }
    return res;
}

::taihe::array<::taihe::string> MessageSequenceImpl::ReadStringArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<::taihe::string>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<::taihe::string>(nullptr, 0);
    }
    std::vector<std::string> res;
    std::u16string val;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (nativeParcel_->GetReadableBytes() <= 0) {
            break;
        }
        if (!nativeParcel_->ReadString16(val)) {
            ZLOGE(LOG_LABEL, "read string16 failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<::taihe::string>(nullptr, 0)));
        }
        res.push_back(OHOS::Str16ToStr8(val));
    }
    return ::taihe::array<::taihe::string>(taihe::copy_data_t{}, res.data(), res.size());
}

::taihe::array<int32_t> MessageSequenceImpl::ReadCharArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<int32_t>(nullptr, 0));
    uint32_t arrayLength = nativeParcel_->ReadUint32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<int32_t>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(uint8_t),
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
    std::vector<int32_t> res;
    for (uint32_t i = 0; i < arrayLength; i++) {
        uint8_t val = nativeParcel_->ReadUint8();
        res.push_back(static_cast<int32_t>(val));
    }
    return ::taihe::array<int32_t>(res);
}

::taihe::array<double> MessageSequenceImpl::ReadFloatArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<double>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<double>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(double),
        nativeParcel_, (::taihe::array<double>(nullptr, 0)));
    std::vector<double> res;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        res.push_back(nativeParcel_->ReadDouble());
    }
    return ::taihe::array<double>(res);
}

::taihe::array<int64_t> MessageSequenceImpl::ReadLongArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<int64_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<int64_t>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(long),
        nativeParcel_, (::taihe::array<int64_t>(nullptr, 0)));
    std::vector<int64_t> res;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        res.push_back(nativeParcel_->ReadInt64());
    }
    return ::taihe::array<int64_t>(res);
}

::taihe::array<int32_t> MessageSequenceImpl::ReadShortArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<int32_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<int32_t>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(int32_t),
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
    std::vector<int32_t> res;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        int16_t val = nativeParcel_->ReadInt16();
        res.push_back(static_cast<int32_t>(val));
    }
    return ::taihe::array<int32_t>(res);
}

int32_t MessageSequenceImpl::ReadChar()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    uint8_t value = nativeParcel_->ReadUint8();
    return static_cast<int32_t>(value);
}

double MessageSequenceImpl::ReadFloat()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    double value = nativeParcel_->ReadDouble();
    return value;
}

double MessageSequenceImpl::ReadDouble()
{
    return ReadFloat();
}

int32_t MessageSequenceImpl::ReadShort()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int16_t value = nativeParcel_->ReadInt16();
    return static_cast<int32_t>(value);
}

int32_t MessageSequenceImpl::ReadByte()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int8_t value = nativeParcel_->ReadInt8();
    return static_cast<int32_t>(value);
}

void MessageSequenceImpl::ReadParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t arrayLength = nativeParcel_->ReadInt32();
    int32_t flags;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        flags = nativeParcel_->ReadInt32();
        if (flags != 1) {
            ZLOGE(LOG_LABEL, "read parcelable failed, flags:%{public}d", flags);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        }
        parcelableArray[i]->Unmarshalling(*jsObjRef_);
        if (taihe::has_error()) {
            ZLOGE(LOG_LABEL, "call unmarshalling failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
        }
    }
}


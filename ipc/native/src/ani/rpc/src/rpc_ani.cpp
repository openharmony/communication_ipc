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
#include <future>
#include <iostream>
#include <thread>
#include <securec.h>
#include "ani_remote_object.h"
#include "ani_utils.h"
#include "iremote_object.h"
#include "ipc_object_stub.h"
#include "ipc_object_proxy.h"
#include "message_parcel.h"
#include "string_ex.h"

using namespace OHOS;

constexpr int REQUEST_WAIT_TIME_SECOND = 5;
constexpr int MESSAGE_OPTION_WAIT_TIME_MS = 1000;
constexpr int MESSAGE_OPTION_FLAGS = 1;

static ani_object CreateMessageSequence([[maybe_unused]] ani_env *env, MessageParcel &msgParcel)
{
    std::cout << "[ANI] enter CreateMessageSequence func" << std::endl;
    static const char *nsName = "L@ohos/rpc/rpc;";
    ani_namespace ns;
    ani_object nullobj{};
    if (ANI_OK != env->FindNamespace(nsName, &ns)) {
        std::cerr << "[ANI] Not found MessageSequence Namespace: '" << nsName << "'" << std::endl;
        return nullobj;
    }

    static const char *className = "LMessageSequence;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        std::cerr << "[ANI] Not found MessageSequence Class: '" << className << "'" << std::endl;
        return nullobj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        std::cerr << "[ANI] Not found MessageSequence ctor" << std::endl;
        return nullobj;
    }

    ani_object sequenceObj;
    if (ANI_OK != env->Object_New(cls, ctor, &sequenceObj)) {
        std::cerr << "[ANI] New MessageSequence Fail" << std::endl;
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
        std::cerr << "Not found '" << className << "'" << std::endl;
        return aniObject;
    }
    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "D:V", &personInfoCtor)) {
        std::cerr << "Class_GetMethod Failed '" << className << "' <ctor>" << std::endl;
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, doubleValue)) {
        std::cerr << "Object_New Failed '" << className << "' <ctor>" << std::endl;
        return aniObject;
    }
    return aniObject;
}

static ani_object CreateMessageOption([[maybe_unused]] ani_env *env, MessageOption &option)
{
    std::cout << "[ANI] enter CreateMessageOption func, flags: " << option.GetFlags() << ", waitTime: " <<
                 option.GetWaitTime() << std::endl;

    static const char *nsName = "L@ohos/rpc/rpc;";
    ani_namespace ns;
    ani_object nullobj{};
    if (ANI_OK != env->FindNamespace(nsName, &ns)) {
        std::cerr << "[ANI] Not found MessageOption Namespace: '" << nsName << "'" << std::endl;
        return nullobj;
    }

    static const char *className = "LMessageOption;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        std::cerr << "[ANI] Not found MessageOption Class: '" << className << "'" << std::endl;
        return nullobj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        std::cerr << "[ANI] Not found MessageOption ctor" << std::endl;
        return nullobj;
    }

    ani_object flagsObj = DoubleToObject(env, option.GetFlags());
    ani_object waitTimeObj = DoubleToObject(env, option.GetWaitTime());

    std::cout << "[ANI] CreateMessageOption Object_New" << std::endl;
    ani_object optionObj;
    if (ANI_OK != env->Object_New(cls, ctor, &optionObj, flagsObj, waitTimeObj)) {
        std::cerr << "[ANI] New MessageOption Fail" << std::endl;
        return nullobj;
    }

    return optionObj;
}

static void InitMessageOption([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj, ani_double syncFlags,
                              ani_double waitTimeParam)
{
    std::cout << "[ANI] enter InitMessageOption func syncFlags: " << syncFlags << ", waitTimeParam: " <<
                 waitTimeParam << std::endl;
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
    std::cout << "[ANI] InitMessageOption end" << std::endl;
}

class IPCAniStub : public IPCObjectStub {
public:
    IPCAniStub(ani_env *env, ani_ref saveRemote, const std::u16string &descriptor) : IPCObjectStub(descriptor),
        env_(env), saveRemote_(saveRemote)
    {
        std::cout << "[ANI] enter IPCAniStub ctor " << std::endl;
    }

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        std::cout << "[ANI] enter IPCAniStub OnRemoteRequest " << std::endl;
        ani_env *env = env_;
        static const char *nsName = "L@ohos/rpc/rpc;";
        ani_namespace ns;
        if (ANI_OK != env->FindNamespace(nsName, &ns)) {
            std::cerr << "[ANI] Not found '" << nsName << "'" << std::endl;
            return ANI_NOT_FOUND;
        }

        static const char *remoteObjClsName = "LRemoteObject;";
        ani_class cls;
        if (ANI_OK != env->Namespace_FindClass(ns, remoteObjClsName, &cls)) {
            std::cerr << "[ANI] Not found '" << remoteObjClsName << "'" << std::endl;
            return ANI_NOT_FOUND;
        }

        ani_object aniData = CreateMessageSequence(env, data);
        ani_object aniReply = CreateMessageSequence(env, reply);
        ani_object aniOption = CreateMessageOption(env, option);

        auto obj = reinterpret_cast<ani_object>(saveRemote_);
        std::cerr << "[ANI] before Object_CallMethodByName_Void onRemoteMessageRequestSync" << std::endl;
        env_->Object_CallMethodByName_Void(obj, "onRemoteMessageRequestSync", nullptr,
            (ani_double)code, aniData, aniReply, aniOption);
        std::cerr << "[ANI] after Object_CallMethodByName_Void onRemoteMessageRequestSync" << std::endl;

        const std::chrono::seconds waitSecond(REQUEST_WAIT_TIME_SECOND);
        std::this_thread::sleep_for(waitSecond);

        std::cerr << "[ANI] Leave OnRemoteRequest with " << result_ << std::endl;
        return result_;
    }

    void SetResult(bool result)
    {
        std::cerr << "[ANI] IPCAniStub::SetResult(" << result << ")" << std::endl;
        result_ = result;
    }

    ~IPCAniStub()
    {
        std::cout << "[ANI] enter IPCAniStub dtor " << std::endl;
    }

private:
    bool result_;
    ani_env *env_ = nullptr;
    ani_ref saveRemote_;
};

class IPCObjectRemoteHolder {
public:
    IPCObjectRemoteHolder(ani_env *env, const std::u16string &descriptor) : env_(env), descriptor_(descriptor)
    {
        std::cout << "[ANI] enter IPCObjectRemoteHolder ctor " << std::endl;
    }

    std::string GetDescriptor()
    {
        std::string ret = Str16ToStr8(descriptor_);
        std::cout << "[ANI] enter IPCObjectRemoteHolder GetDescriptor, descriptor:" << ret << std::endl;
        return ret;
    }

    sptr<IRemoteObject> Get()
    {
        if (object_ == nullptr) {
            object_ = new IPCAniStub(env_, saveRemote_, descriptor_);
        }
        return object_;
    }

    void Set(ani_ref saveRemote)
    {
        saveRemote_ = saveRemote;
    }

    ~IPCObjectRemoteHolder()
    {
        if (object_ != nullptr) {
            IPCAniStub* aniStub = reinterpret_cast<IPCAniStub*>(object_.GetRefPtr());
            delete aniStub;
            object_ = nullptr;
        }
        std::cout << "[ANI] enter IPCObjectRemoteHolder dtor " << std::endl;
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
        std::cout << "[ANI] enter IPCObjectRemoteHolder GetDescriptor" << std::endl;
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
    std::cout << "[ANI] enter AniGetNativeRemoteObject func " << std::endl;
    auto holder = AniObjectUtils::Unwrap<IPCObjectRemoteHolder>(env, obj);
    if (holder != nullptr) {
        return holder->Get();
    }
    return nullptr;
}

static ani_string MessageSequenceReadString([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    std::cout << "[ANI] enter MessageSequenceReadString func " << std::endl;
    auto parcel = AniObjectUtils::Unwrap<MessageParcel>(env, object);
    if (parcel != nullptr) {
        auto str = parcel->ReadString();
        return AniStringUtils::ToAni(env, str);
    }
    ani_string result_string{};
    return result_string;
}

static bool MessageSequenceWriteString([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_string str)
{
    std::cout << "[ANI] enter MessageSequenceWriteString func " << std::endl;
    auto parcel = AniObjectUtils::Unwrap<MessageParcel>(env, object);
    if (parcel != nullptr) {
        auto stringContent = AniStringUtils::ToStd(env, str);
        return parcel->WriteString(stringContent);
    }
    return false;
}

static ani_string MessageSequencereadInterfaceToken([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    std::cout << "[ANI] enter MessageSequencereadInterfaceToken func" << std::endl;
    auto parcel = AniObjectUtils::Unwrap<MessageParcel>(env, object);
    if (parcel != nullptr) {
        auto str = parcel->ReadInterfaceToken();
        std::string outString = Str16ToStr8(str.c_str());
        return AniStringUtils::ToAni(env, outString);
    }
    ani_string result_string{};
    return result_string;
}

static void RemoteObjectConstructor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_string descriptor)
{
    std::cout << "[ANI] enter RemoteObjectConstructor func " << std::endl;
    auto descriptorStr = AniStringUtils::ToStd(env, static_cast<ani_string>(descriptor));
    ani_ref saveRemote = nullptr;
    env->GlobalReference_Create(reinterpret_cast<ani_ref>(object), &saveRemote);
    auto objectRemoteHolder = new IPCObjectRemoteHolder(env, OHOS::Str8ToStr16(descriptorStr));
    objectRemoteHolder->Set(saveRemote);
    AniObjectUtils::Wrap<IPCObjectRemoteHolder>(env, object, objectRemoteHolder);
}

static ani_string GetRemoteObjectDescriptor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    std::cout << "[ANI] enter GetRemoteObjectDescriptor func " << std::endl;
    ani_string result_string{};
    auto objectRemoteHolder = AniObjectUtils::Unwrap<IPCObjectRemoteHolder>(env, object);
    if (objectRemoteHolder != nullptr) {
        auto descriptorStr = objectRemoteHolder->GetDescriptor();
        std::cout << "[ANI] get descriptor: " << descriptorStr << std::endl;
        env->String_NewUTF8(descriptorStr.c_str(), descriptorStr.size(), &result_string);
    } else {
        env->String_NewUTF8("", 0, &result_string);
    }
    return result_string;
}

static void OnRemoteMessageRequestCallback([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
                                           ani_boolean result)
{
    std::cout << "[ANI] enter OnRemoteMessageRequestCallback func, result: " << static_cast<bool>(result) << std::endl;
    sptr<IRemoteObject> stub = AniGetNativeRemoteObject(env, object);
    if (stub == nullptr) {
        return;
    }
    IPCAniStub* aniStub = reinterpret_cast<IPCAniStub*>(stub.GetRefPtr());
    aniStub->SetResult(static_cast<bool>(result));
}

static ani_string GetRemoteProxyDescriptor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    std::cout << "[ANI] enter GetRemoteProxyDescriptor func" << std::endl;
    ani_string result_string{};
    auto objectProxyHolder = AniObjectUtils::Unwrap<IPCObjectProxyHolder>(env, object);
    if (objectProxyHolder != nullptr) {
        auto descriptorStr = objectProxyHolder->GetDescriptor();
        std::cout << "[ANI] get descriptor: " << descriptorStr << std::endl;
        env->String_NewUTF8(descriptorStr.c_str(), descriptorStr.size(), &result_string);
    } else {
        env->String_NewUTF8("", 0, &result_string);
    }
    return result_string;
}

static void TestSendRequest([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_object remoteObj,
                            ani_double code, ani_string message)
{
    std::cout << "[ANI] enter SendRequest func(" << object << ", " << remoteObj << ")" << std::endl;

    auto objectRemoteHolder = AniObjectUtils::Unwrap<IPCObjectRemoteHolder>(env, remoteObj);
    std::cerr << "[ANI] unwrapped IPCObjectRemoteHolder addr=" << objectRemoteHolder << std::endl;
    if (objectRemoteHolder != nullptr) {
        auto descriptorStr = objectRemoteHolder->GetDescriptor();
        std::cout << "[ANI] get remote descriptor: " << descriptorStr << std::endl;
        sptr<IRemoteObject> stub = objectRemoteHolder->Get();
        IPCAniStub* aniStub = reinterpret_cast<IPCAniStub*>(stub.GetRefPtr());
        MessageParcel data;
        data.WriteString(AniStringUtils::ToStd(env, message));
        std::u16string interfaceToken = Str8ToStr16(AniStringUtils::ToStd(env, message).c_str());
        data.WriteInterfaceToken(interfaceToken);
        MessageParcel reply;
        MessageOption option;
        option.SetFlags(MESSAGE_OPTION_FLAGS);
        option.SetWaitTime(MESSAGE_OPTION_WAIT_TIME_MS);
        aniStub->OnRemoteRequest((int)code, data, reply, option);
    } else {
        std::cout << "[ANI] not find IPCObjectRemoteHolder" << std::endl;
    }
}

static void WaitSecond([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_double waitTime)
{
    std::cout << "[ANI] enter WaitSecond func, waitTime: " << static_cast<int32_t>(waitTime) << std::endl;
    const std::chrono::seconds waitSecond(static_cast<int32_t>(waitTime));
    std::this_thread::sleep_for(waitSecond);
}

static ani_status BindMessageSequenceClassMethods(ani_env* env, ani_namespace& ns)
{
    static const char *msgSeqClsName = "LMessageSequence;";
    ani_class msgSequenceClass;
    if (ANI_OK != env->Namespace_FindClass(ns, msgSeqClsName, &msgSequenceClass)) {
        std::cerr << "[ANI] Not found '" << msgSeqClsName << "'" << std::endl;
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"readString", nullptr, reinterpret_cast<void *>(MessageSequenceReadString)},
        ani_native_function {"writeString", nullptr, reinterpret_cast<void *>(MessageSequenceWriteString)},
        ani_native_function {"readInterfaceToken", nullptr,
                             reinterpret_cast<void *>(MessageSequencereadInterfaceToken)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(msgSequenceClass, methods.data(), methods.size())) {
        std::cerr << "[ANI] Cannot bind native methods to '" << msgSequenceClass << "'" << std::endl;
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindMessageOptionClassMethods(ani_env* env, ani_namespace& ns)
{
    static const char *msgOptClsName = "LMessageOption;";
    ani_class msgOptionClass;
    if (ANI_OK != env->Namespace_FindClass(ns, msgOptClsName, &msgOptionClass)) {
        std::cerr << "[ANI] Not found '" << msgOptClsName << "'" << std::endl;
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"init", nullptr, reinterpret_cast<void *>(InitMessageOption)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(msgOptionClass, methods.data(), methods.size())) {
        std::cerr << "[ANI] Cannot bind native methods to '" << msgOptionClass << "'" << std::endl;
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindRemoteObjectClassMethods(ani_env* env, ani_namespace& ns)
{
    static const char *remoteObjClsName = "LRemoteObject;";
    ani_class remoteObjClass;
    if (ANI_OK != env->Namespace_FindClass(ns, remoteObjClsName, &remoteObjClass)) {
        std::cerr << "[ANI] Not found '" << remoteObjClsName << "'" << std::endl;
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"getDescriptor", nullptr, reinterpret_cast<void *>(GetRemoteObjectDescriptor)},
        ani_native_function {"<ctor>", "Lstd/core/String;:V", reinterpret_cast<void *>(RemoteObjectConstructor)},
        ani_native_function {"onRemoteMessageRequestCallback", nullptr,
                             reinterpret_cast<void*>(OnRemoteMessageRequestCallback)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(remoteObjClass, methods.data(), methods.size())) {
        std::cerr << "[ANI] Cannot bind native methods to '" << remoteObjClass << "'" << std::endl;
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindRemoteProxyClassMethods(ani_env* env, ani_namespace& ns)
{
    static const char *remoteProxyClsName = "LRemoteProxy;";
    ani_class remoteProxyClass;
    if (ANI_OK != env->Namespace_FindClass(ns, remoteProxyClsName, &remoteProxyClass)) {
        std::cerr << "[ANI] Not found '" << remoteProxyClsName << "'" << std::endl;
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function {"getDescriptor", nullptr, reinterpret_cast<void *>(GetRemoteProxyDescriptor)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(remoteProxyClass, methods.data(), methods.size())) {
        std::cerr << "[ANI] Cannot bind native methods to '" << remoteProxyClass << "'" << std::endl;
        return ANI_ERROR;
    };

    return ANI_OK;
}

static ani_status BindEtsGlobalClassMethods(ani_env* env, ani_namespace& ns)
{
    static const char *globalClsName = "Ltest/ETSGLOBAL;";
    ani_class cls;
    if (ANI_OK != env->FindClass(globalClsName, &cls)) {
        std::cerr << "[ANI] Not found '" << globalClsName << "'" << std::endl;
        return ANI_ERROR;
    }

    std::array methods5 = {
        ani_native_function {"testSendRequest", nullptr, reinterpret_cast<void *>(TestSendRequest)},
        ani_native_function {"waitSecond", nullptr, reinterpret_cast<void*>(WaitSecond)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods5.data(), methods5.size())) {
        std::cerr << "[ANI] Cannot bind native methods to '" << globalClsName << "'" << std::endl;
        return ANI_ERROR;
    };

    return ANI_OK;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "[ANI] Unsupported ANI_VERSION_1" << std::endl;
        return ANI_ERROR;
    }

    static const char *nsName = "L@ohos/rpc/rpc;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(nsName, &ns)) {
        std::cerr << "[ANI] Not found '" << nsName << "'" << std::endl;
        return ANI_NOT_FOUND;
    }

    if (ANI_OK != BindMessageSequenceClassMethods(env, ns)) {
        std::cerr << "[ANI] BindMessageSequenceClassMethods failed" << std::endl;
        return ANI_ERROR;
    }

    if (ANI_OK != BindMessageOptionClassMethods(env, ns)) {
        std::cerr << "[ANI] BindMessageOptionClassMethods failed" << std::endl;
        return ANI_ERROR;
    }

    if (ANI_OK != BindRemoteObjectClassMethods(env, ns)) {
        std::cerr << "[ANI] BindRemoteObjectClassMethods failed" << std::endl;
        return ANI_ERROR;
    }

    if (ANI_OK != BindRemoteProxyClassMethods(env, ns)) {
        std::cerr << "[ANI] BindRemoteProxyClassMethods failed" << std::endl;
        return ANI_ERROR;
    }

    if (ANI_OK != BindEtsGlobalClassMethods(env, ns)) {
        std::cerr << "[ANI] BindEtsGlobalClassMethods failed" << std::endl;
        return ANI_ERROR;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}

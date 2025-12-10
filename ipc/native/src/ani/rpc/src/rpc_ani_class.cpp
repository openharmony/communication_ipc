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

#include "rpc_ani_class.h"

using namespace OHOS;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = {LOG_CORE, LOG_ID_IPC_NAPI, "ani_rpc_error"};

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
    static const char *className = "Lstd/core/Double;";
    ani_class aniClass;
    if (env == nullptr) {
        return aniObject;
    }
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
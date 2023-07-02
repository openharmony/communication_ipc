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

#include "napi_remote_object_holder.h"

#include <string_ex.h>

namespace OHOS {
NAPIRemoteObjectHolder::NAPIRemoteObjectHolder(napi_env env, const std::u16string &descriptor, napi_value thisVar)
{
    env_ = env;
    descriptor_ = descriptor;
    sptrCachedObject_ = nullptr;
    wptrCachedObject_ = nullptr;
    localInterfaceRef_ = nullptr;
    attachCount_ = 1;
    napi_create_reference(env, thisVar, 0, &jsObjectRef_);
}

NAPIRemoteObjectHolder::~NAPIRemoteObjectHolder()
{
    // free the reference of object.
    sptrCachedObject_ = nullptr;
    wptrCachedObject_ = nullptr;
    if (localInterfaceRef_ != nullptr) {
        napi_delete_reference(env_, localInterfaceRef_);
    }
    if (jsObjectRef_ != nullptr) {
        napi_delete_reference(env_, jsObjectRef_);
    }
}

sptr<NAPIRemoteObject> NAPIRemoteObjectHolder::Get(napi_env envNew)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    // grab an strong reference to the object,
    // so it will not be freed util this reference released.
    if (sptrCachedObject_ != nullptr) {
        return sptrCachedObject_;
    }
    sptr<NAPIRemoteObject> tmp = wptrCachedObject_.promote();
    if (tmp == nullptr) {
        tmp = new NAPIRemoteObject(envNew, env_, jsObjectRef_, descriptor_);
        wptrCachedObject_ = tmp;
    }
    tmp->SetNewEnv(envNew);
    return tmp;
}

void NAPIRemoteObjectHolder::Set(sptr<NAPIRemoteObject> object)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    IPCObjectStub *tmp = static_cast<IPCObjectStub *>(object.GetRefPtr());
    if (tmp->GetObjectType() == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT) {
        wptrCachedObject_ = object;
    } else {
        sptrCachedObject_ = object;
    }
}

void NAPIRemoteObjectHolder::attachLocalInterface(napi_value localInterface, std::string &descriptor)
{
    if (localInterfaceRef_ != nullptr) {
        napi_delete_reference(env_, localInterfaceRef_);
    }
    napi_create_reference(env_, localInterface, 1, &localInterfaceRef_);
    descriptor_ = Str8ToStr16(descriptor);
}

napi_value NAPIRemoteObjectHolder::queryLocalInterface(std::string &descriptor)
{
    if (!descriptor_.empty() && strcmp(Str16ToStr8(descriptor_).c_str(), descriptor.c_str()) == 0) {
        napi_value ret = nullptr;
        napi_get_reference_value(env_, localInterfaceRef_, &ret);
        return ret;
    }
    napi_value result = nullptr;
    napi_get_null(env_, &result);
    return result;
}
} // namespace OHOS
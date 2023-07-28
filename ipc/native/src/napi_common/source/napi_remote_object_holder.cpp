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

#include <uv.h>
#include <string_ex.h>
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "napi_remoteObject_holder" };

struct DeleteJsRefParam {
    napi_env env;
    napi_ref thisVarRef;
};

NAPIRemoteObjectHolder::NAPIRemoteObjectHolder(napi_env env, const std::u16string &descriptor, napi_value thisVar)
    : env_(env), descriptor_(descriptor), sptrCachedObject_(nullptr), wptrCachedObject_(nullptr),
      localInterfaceRef_(nullptr), attachCount_(1), jsObjectRef_(nullptr)
{
    jsThreadId_ = std::this_thread::get_id();
    // create weak ref, do not need to delete,
    // increase ref count when the JS object will transfer to another thread or process.
    napi_create_reference(env, thisVar, 0, &jsObjectRef_);
}

NAPIRemoteObjectHolder::~NAPIRemoteObjectHolder()
{
    // free the reference of object.
    if (localInterfaceRef_ != nullptr && env_ != nullptr) {
        napi_delete_reference(env_, localInterfaceRef_);
    }
}

sptr<IRemoteObject> NAPIRemoteObjectHolder::Get()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    // grab an strong reference to the object,
    // so it will not be freed util this reference released.
    if (sptrCachedObject_ != nullptr) {
        return sptrCachedObject_;
    }

    sptr<IRemoteObject> tmp = wptrCachedObject_.promote();
    if (tmp == nullptr && env_ != nullptr) {
        tmp = new NAPIRemoteObject(jsThreadId_, env_, jsObjectRef_, descriptor_);
        wptrCachedObject_ = tmp;
    }
    return tmp;
}

void NAPIRemoteObjectHolder::Set(sptr<IRemoteObject> object)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    IPCObjectStub *tmp = static_cast<IPCObjectStub *>(object.GetRefPtr());
    if (tmp->GetObjectType() == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT) {
        wptrCachedObject_ = object;
    } else {
        sptrCachedObject_ = object;
    }
}

napi_ref NAPIRemoteObjectHolder::GetJsObjectRef() const
{
    return jsObjectRef_;
}

napi_env NAPIRemoteObjectHolder::GetJsObjectEnv() const
{
    return env_;
}

void NAPIRemoteObjectHolder::CleanJsEnv()
{
    env_ = nullptr;
    jsObjectRef_ = nullptr;
    sptr<IRemoteObject> tmp = wptrCachedObject_.promote();
    if (tmp != nullptr) {
        NAPIRemoteObject *object = static_cast<NAPIRemoteObject *>(tmp.GetRefPtr());
        ZLOGI(LOG_LABEL, "reset env and napi_ref");
        object->ResetJsEnv();
    }
}

void NAPIRemoteObjectHolder::attachLocalInterface(napi_value localInterface, std::string &descriptor)
{
    if (env_ == nullptr) {
        ZLOGE(LOG_LABEL, "Js env has been destructed");
        return;
    }
    if (localInterfaceRef_ != nullptr) {
        napi_delete_reference(env_, localInterfaceRef_);
    }
    napi_create_reference(env_, localInterface, 1, &localInterfaceRef_);
    descriptor_ = Str8ToStr16(descriptor);
}

napi_value NAPIRemoteObjectHolder::queryLocalInterface(std::string &descriptor)
{
    if (env_ == nullptr) {
        ZLOGE(LOG_LABEL, "Js env has been destructed");
        return nullptr;
    }
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
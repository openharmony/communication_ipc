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
 
#ifndef RPC_ANI_CLASS_H
#define RPC_ANI_CLASS_H
 
#include <ani.h>
#include <array>
#include <cstring>
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
 
namespace OHOS {
 
class IPCAniStub : public IPCObjectStub {
public:
    IPCAniStub(ani_env *env, ani_object remoteObject, const std::u16string &descriptor);
 
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
 
    ~IPCAniStub();
 
private:
    ani_env *env_ = nullptr;
    ani_ref saveRemote_;
};
 
class IPCObjectRemoteHolder : public NativeObject {
public:
    IPCObjectRemoteHolder(ani_env *env, ani_object remoteObject, const std::u16string &descriptor)
        : env_(env), remoteObject_(remoteObject), descriptor_(descriptor)
    {
        if (env_ == nullptr) {
            return;
        }
        if (ANI_OK != env->GlobalReference_Create(reinterpret_cast<ani_ref>(remoteObject),
            reinterpret_cast<ani_ref*>(&remoteObject_))) {
            return;
        }
    }
 
    std::string GetDescriptor()
    {
        std::string ret = Str16ToStr8(descriptor_);
        return ret;
    }
 
    sptr<IRemoteObject> Get(ani_env *env)
    {
        sptr<IRemoteObject> tmp = object_.promote();
        if (nullptr == tmp && nullptr != env) {
            tmp = sptr<IPCAniStub>::MakeSptr(env, remoteObject_, descriptor_);
            object_ = tmp;
        }
        return tmp;
    }
 
    ~IPCObjectRemoteHolder()
    {
        if (env_ == nullptr) {
            return;
        }
        if (ANI_OK != env_->GlobalReference_Delete(remoteObject_)) {
            return;
        }
    }
 
private:
    ani_env *env_ = nullptr;
    ani_object remoteObject_;
    std::u16string descriptor_;
    wptr<IRemoteObject> object_;
};
 
class IPCObjectProxyHolder {
public:
    std::string GetDescriptor()
    {
        if (!object_) {
            return "";
        }
        return OHOS::Str16ToStr8(object_->GetInterfaceDescriptor());
    }
 
private:
    sptr<IPCObjectProxy> object_;
};
}  // namespace OHOS
#endif  // RPC_ANI_CLASS_H
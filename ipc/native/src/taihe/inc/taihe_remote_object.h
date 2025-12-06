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

#ifndef OHOS_IPC_TAIHE_REMOTEOBJECT_H
#define OHOS_IPC_TAIHE_REMOTEOBJECT_H

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <cinttypes>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "ipc_object_stub.h"
#include "taihe_ani_remote_object.h"

namespace OHOS {

class RemoteObjectImpl {
public:
    // ETS to ANI
    explicit RemoteObjectImpl(::taihe::string_view descriptor);

    // ANI to ETS
    explicit RemoteObjectImpl(uintptr_t nativePtr);
    
    int32_t GetCallingPid();

    int32_t GetCallingUid();

    void ModifyLocalInterface(::ohos::rpc::rpc::weak::IRemoteBroker localInterface, ::taihe::string_view descriptor);
    
    ::ohos::rpc::rpc::IRemoteBroker GetLocalInterface(::taihe::string_view descriptor);
    
    ::ohos::rpc::rpc::RequestResult SendMessageRequestSync(int32_t code, ::ohos::rpc::rpc::weak::MessageSequence data,
        ::ohos::rpc::rpc::weak::MessageSequence reply, ::ohos::rpc::rpc::weak::MessageOption options);
    
    void RegisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags);
    
    void UnregisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags);
    
    ::taihe::string GetDescriptor();
    
    bool IsObjectDead();
    
    bool OnRemoteMessageRequestWithCallingInfo(int32_t code, ::ohos::rpc::rpc::weak::MessageSequence data,
        ::ohos::rpc::rpc::weak::MessageSequence reply, ::ohos::rpc::rpc::weak::MessageOption options,
        ::ohos::rpc::rpc::CallingInfo const& callingInfo);

    bool OnRemoteMessageRequest(int32_t code, ::ohos::rpc::rpc::weak::MessageSequence data,
        ::ohos::rpc::rpc::weak::MessageSequence reply, ::ohos::rpc::rpc::weak::MessageOption options);
    
    OHOS::sptr<OHOS::IPCObjectStub> GetNativeObject();

    int64_t GetNativePtr();
    
    void AddJsObjWeakRef(::ohos::rpc::rpc::weak::RemoteObject obj, bool isNative, bool hasCallingInfo);
    
    static ::ohos::rpc::rpc::RemoteObject CreateRemoteObject(::ohos::rpc::rpc::weak::RemoteObject jsSelf,
        ::taihe::string_view descriptor, ::taihe::callback_view<bool()> hasCallingInfoCB);
    static ::ohos::rpc::rpc::RemoteObject CreateRemoteObjectFromNative(uintptr_t nativePtr);
    
private:
    std::mutex mutex_;
    OHOS::wptr<OHOS::IPCObjectStub> wptrCachedObject_;
    OHOS::sptr<OHOS::IPCObjectStub> sptrCachedObject_;
    ::taihe::string desc_;
    std::optional<::ohos::rpc::rpc::RemoteObject> jsObjRef_;
    std::optional<::ohos::rpc::rpc::IRemoteBroker> jsLocalInterface_;
    bool hasCallingInfo_;
};

} // namespace

#endif // OHOS_IPC_TAIHE_REMOTEOBJECT_H
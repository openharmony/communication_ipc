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

#ifndef OHOS_IPC_TAIHE_REMOTEPROXY_H
#define OHOS_IPC_TAIHE_REMOTEPROXY_H

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <cinttypes>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

#include "ipc_object_proxy.h"
#include "taihe_deathrecipient.h"

namespace OHOS {

class RemoteProxyImpl {
public:
    RemoteProxyImpl(uintptr_t nativePtr, bool isCreateJsRemoteObj = false);

    ::ohos::rpc::rpc::IRemoteBroker GetLocalInterface(::taihe::string_view descriptor);

    ::ohos::rpc::rpc::RequestResult SendMessageRequestSync(int32_t code, ::ohos::rpc::rpc::weak::MessageSequence data,
        ::ohos::rpc::rpc::weak::MessageSequence reply, ::ohos::rpc::rpc::weak::MessageOption options);

    void RegisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags);

    void UnregisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags);

    ::taihe::string GetDescriptor();

    bool IsObjectDead();

    int64_t GetNativePtr();

    void AddJsObjWeakRef(::ohos::rpc::rpc::weak::RemoteProxy obj);

    static ::ohos::rpc::rpc::RemoteProxy CreateRemoteProxyFromNative(uintptr_t nativePtr);
    static ::ohos::rpc::rpc::RemoteProxy RpcTransferStaticProxy(uintptr_t input);
    static uintptr_t RpcTransferDynamicProxy(::ohos::rpc::rpc::RemoteProxy obj);
private:
    OHOS::sptr<OHOS::IPCObjectProxy> cachedObject_;
    std::optional<::ohos::rpc::rpc::RemoteProxy> jsObjRef_;
    std::optional<::ohos::rpc::rpc::IRemoteBroker> jsLocalInterface_;
    std::map<::ohos::rpc::rpc::DeathRecipient*, OHOS::sptr<DeathRecipientImpl>> deathRecipientMap_;
};

} // namespace
#endif // OHOS_IPC_TAIHE_REMOTEPROXY_H
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ipc_inner_object.h"
#include "log_tags.h"
#include "ipc_debug.h"

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_CAPI, "IPCInternalObject" };

OHIPCRemoteProxy* CreateIPCRemoteProxy(OHOS::sptr<OHOS::IRemoteObject>& remote)
{
    if (remote == nullptr) {
        ZLOGE(LOG_LABEL, "remote object is nullptr!");
        return nullptr;
    }
    OHIPCRemoteProxy *proxy = new (std::nothrow) OHIPCRemoteProxy();
    if (proxy == nullptr) {
        ZLOGE(LOG_LABEL, "create remote proxy failed");
        return nullptr;
    }
    proxy->remote = remote;
    return proxy;
}

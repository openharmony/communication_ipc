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

#include "ipc_internal_utils.h"
#include "ipc_inner_object.h"
#include "log_tags.h"
#include "ipc_debug.h"

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_CAPI, "IPCInternalUtils" };

bool IsIPCParcelValid(const OHIPCParcel *parcel, const char *promot)
{
    if (parcel == nullptr || parcel->msgParcel == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: parcel is null!", promot);
        return false;
    }
    return true;
}

bool IsIPCRemoteProxyValid(const OHIPCRemoteProxy *proxy, const char *promot)
{
    if (proxy == nullptr || proxy->remote == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: proxy object is invalid!", promot);
        return false;
    }
    return true;
}

bool IsMemoryParamsValid(char **str, int32_t *len, OH_IPC_MemAllocator allocator, const char *promot)
{
    if (str == nullptr || len == nullptr || allocator == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: mem param is invalid!", promot);
        return false;
    }
    return true;
}

/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "peer_holder.h"

#include "ipc_debug.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "refbase.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_PEER_HOLDER, "PeerHolder" };

PeerHolder::PeerHolder(const sptr<IRemoteObject> &object) : remoteObject_(object) {}

sptr<IRemoteObject> PeerHolder::Remote()
{
    if (GetBeforeMagic() != BEFORE_MAGIC || GetAfterMagic() != AFTER_MAGIC) {
        ZLOGE(LOG_LABEL, "remoteObject invalid, beforeMagic:%{public}x afterMagic:%{public}x",
            beforeMagic_, afterMagic_);
        return nullptr;
    }
    return remoteObject_;
}
} // namespace OHOS

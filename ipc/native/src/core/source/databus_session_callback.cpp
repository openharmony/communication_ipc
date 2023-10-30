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

#include "databus_session_callback.h"

#include "dbinder_databus_invoker.h"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "log_tags.h"

namespace OHOS {
int DatabusSessionCallback::OnSessionOpened(std::shared_ptr<Session> session)
{
    if (session == nullptr) {
        ZLOGE(LOG_LABEL, "OnSessionOpened session is nullptr");
        return ERR_INVALID_DATA;
    }
    if (session->GetChannelId() < 0) {
        ZLOGE(LOG_LABEL, "fail to open session because of wrong channel ID");
        return SESSION_WRONG_FD_ERR;
    }

    if (!session->IsServerSide()) {
        ZLOGI(LOG_LABEL, "active end, deviceId:%{public}s channelId:%{public}" PRId64,
           IPCProcessSkeleton::ConvertToSecureString(session->GetPeerDeviceId()).c_str(), session->GetChannelId());
        return 0;
    }

    ZLOGI(LOG_LABEL, "passive end, deviceId:%{public}s channelId:%{public}" PRId64,
        IPCProcessSkeleton::ConvertToSecureString(session->GetPeerDeviceId()).c_str(), session->GetChannelId());
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LOG_LABEL, "fail to get invoker");
        return SESSION_INVOKER_NULL_ERR;
    }

    return invoker->OnReceiveNewConnection(session) ? 0 : SESSION_UNOPEN_ERR;
}

void DatabusSessionCallback::OnSessionClosed(std::shared_ptr<Session> session)
{
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LOG_LABEL, "fail to get invoker");
        return;
    }

    invoker->OnDatabusSessionClosed(session);
    ZLOGI(LOG_LABEL, "end, deviceId:%{public}s channelId:%{public}" PRId64,
        IPCProcessSkeleton::ConvertToSecureString(session->GetPeerDeviceId()).c_str(), session->GetChannelId());
}

void DatabusSessionCallback::OnBytesReceived(std::shared_ptr<Session> session, const char *data, ssize_t len)
{
    ZLOGD(LOG_LABEL, "channelId:%{public}" PRId64 " len:%{public}u",
        session->GetChannelId(), static_cast<uint32_t>(len));
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LOG_LABEL, "fail to get invoker");
        return;
    }

    invoker->OnMessageAvailable(session, data, len);
}
} // namespace OHOS

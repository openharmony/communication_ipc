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

#include "ipc_thread_skeleton.h"
#include "ipc_process_skeleton.h"
#include "dbinder_databus_invoker.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DatabusSessionCallback" };
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

int DatabusSessionCallback::OnSessionOpened(std::shared_ptr<Session> session)
{
    if (session->GetChannelId() < 0) {
        DBINDER_LOGE("fail to open session because of wrong channel ID");
        return SESSION_WRONG_FD_ERR;
    }

    if (!session->IsServerSide()) {
        DBINDER_LOGI("active end");
        return 0;
    }

    DBINDER_LOGI("passive end");
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        DBINDER_LOGE("fail to get invoker");
        return SESSION_INVOKER_NULL_ERR;
    }

    return invoker->OnReceiveNewConnection(session) ? 0 : SESSION_UNOPEN_ERR;
}

void DatabusSessionCallback::OnSessionClosed(std::shared_ptr<Session> session)
{
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        DBINDER_LOGE("fail to get invoker");
        return;
    }

    invoker->OnDatabusSessionClosed(session);
}

void DatabusSessionCallback::OnBytesReceived(std::shared_ptr<Session> session, const char *data, ssize_t len)
{
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        DBINDER_LOGE("fail to get invoker");
        return;
    }

    invoker->OnMessageAvailable(session, data, len);
}
} // namespace OHOS

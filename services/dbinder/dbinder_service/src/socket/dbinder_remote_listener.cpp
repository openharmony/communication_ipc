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

#include "dbinder_remote_listener.h"
#include "securec.h"
#include "ipc_types.h"
#include "dbinder_log.h"
#include "dbinder_error_code.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DbinderRemoteListener" };

DBinderRemoteListener::DBinderRemoteListener(const sptr<DBinderService> &dBinderService)
    : dBinderService_(dBinderService)
{
    DBINDER_LOGI(LOG_LABEL, "create dbinder remote listener");
}

DBinderRemoteListener::~DBinderRemoteListener()
{
    DBINDER_LOGI(LOG_LABEL, "delete dbinder remote listener");
}

bool DBinderRemoteListener::StartListener(std::shared_ptr<DBinderRemoteListener> &listener)
{
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    std::shared_ptr<ISessionService> softbusManager_ = ISessionService::GetInstance();
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to get softbus service");
        return false;
    }
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());
    if (softbusManager_->GrantPermission(uid, pid, OWN_SESSION_NAME) != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "fail to Grant Permission softbus name %{public}s", OWN_SESSION_NAME.c_str());
        return false;
    }

    int ret = softbusManager_->CreateSessionServer(OWN_SESSION_NAME, PEER_SESSION_NAME, listener);
    if (ret != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to create softbus server with ret = %{public}d", ret);
        return false;
    }
    return true;
}

bool DBinderRemoteListener::StopListener()
{
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    std::shared_ptr<ISessionService> softbusManager_ = ISessionService::GetInstance();
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "softbus manager is null");
        return false;
    }

    int ret = softbusManager_->RemoveSessionServer(OWN_SESSION_NAME, PEER_SESSION_NAME);
    if (ret != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to remove softbus server");
        return false;
    }
    softbusManager_ = nullptr;
    return true;
}

bool DBinderRemoteListener::SendDataToRemote(const std::string &deviceId, const struct DHandleEntryTxRx *msg)
{
    if (msg == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "msg is null");
        return false;
    }

    std::shared_ptr<Session> session = OpenSoftbusSession(deviceId);
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to open session");
        return false;
    }

    int ret = session->SendBytes(msg, msg->head.len);
    DBINDER_LOGI(LOG_LABEL, "SendBytes len: %{public}u, ret: %{public}d", msg->head.len, ret);
    if (ret != 0) {
        return false;
    }
    return true;
}

bool DBinderRemoteListener::CloseDatabusSession(const std::string &deviceId)
{
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    std::shared_ptr<ISessionService> softbusManager_ = ISessionService::GetInstance();
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "softbus manager is null");
        return false;
    }

    std::shared_ptr<Session> session = softbusManager_->OpenSession(OWN_SESSION_NAME, PEER_SESSION_NAME, deviceId,
        std::string(""), Session::TYPE_BYTES);
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to open session before closing it");
        return false;
    }

    return softbusManager_->CloseSession(session) == 0;
}

std::shared_ptr<Session> DBinderRemoteListener::OpenSoftbusSession(const std::string &peerDeviceId)
{
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    std::shared_ptr<ISessionService> softbusManager_ = ISessionService::GetInstance();
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "softbus manager is null");
        return nullptr;
    }

    return softbusManager_->OpenSession(OWN_SESSION_NAME, PEER_SESSION_NAME, peerDeviceId, std::string(""),
        Session::TYPE_BYTES);
}

int DBinderRemoteListener::OnSessionOpened(std::shared_ptr<Session> session)
{
    DBINDER_LOGI(LOG_LABEL, "peer session is open");
    if (session->GetPeerSessionName() != PEER_SESSION_NAME) {
        DBINDER_LOGE(LOG_LABEL, "invalid session name, peer session name = %{public}s",
            session->GetPeerSessionName().c_str());
        return -DBINDER_SERVICE_WRONG_SESSION;
    }
    return 0;
}

void DBinderRemoteListener::OnSessionClosed(std::shared_ptr<Session> session)
{
    if (session->IsServerSide()) {
        DBINDER_LOGI(LOG_LABEL, "server peer session name = %{public}s is closed",
            session->GetPeerSessionName().c_str());
        return;
    }
    DBINDER_LOGI(LOG_LABEL, "client peer session name = %{public}s is closed",
        session->GetPeerSessionName().c_str());
    dBinderService_->ProcessOnSessionClosed(session);
}

void DBinderRemoteListener::OnBytesReceived(std::shared_ptr<Session> session, const char *data, ssize_t len)
{
    DBINDER_LOGI(LOG_LABEL, "OnBytesReceived len: %{public}u", static_cast<uint32_t>(len));
    if (data == nullptr || len < static_cast<ssize_t>(sizeof(struct DHandleEntryTxRx))) {
        DBINDER_LOGE(LOG_LABEL, "session has wrong input, peer session name = %s, data length = %zd",
            session->GetPeerSessionName().c_str(), len);
        // ignore the package
        return;
    }

    if (dBinderService_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "dbinder service is not started");
        return;
    }

    struct DHandleEntryTxRx *handleEntry = (struct DHandleEntryTxRx *)data;
    if (handleEntry == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "msg is null");
        return;
    }

    if (!dBinderService_->OnRemoteMessageTask(handleEntry)) {
        DBINDER_LOGE(LOG_LABEL, "process remote message fail");
    }
}
} // namespace OHOS

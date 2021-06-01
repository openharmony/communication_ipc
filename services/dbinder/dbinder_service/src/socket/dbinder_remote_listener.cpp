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
#include <cinttypes>
#include "securec.h"
#include "ipc_types.h"
#include "dbinder_log.h"
#include "dbinder_error_code.h"

namespace OHOS {
DBinderRemoteListener::DBinderRemoteListener(const sptr<DBinderService> &dBinderService)
    : dBinderService_(dBinderService)
{
    DBINDER_LOGI("create dbinder remote listener");
}

DBinderRemoteListener::~DBinderRemoteListener()
{
    DBINDER_LOGI("delete dbinder remote listener");
}

bool DBinderRemoteListener::StartListener()
{
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    softbusManager_ = ISessionService::GetInstance();
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE("fail to get softbus service");
        return false;
    }
    std::shared_ptr<ISessionListener> callbacks(this);
    int ret = softbusManager_->CreateSessionServer(OWN_SESSION_NAME, PEER_SESSION_NAME, callbacks);
    if (ret != 0) {
        DBINDER_LOGE("fail to create softbus server with ret = %{public}d", ret);
        return false;
    }
    return true;
}

bool DBinderRemoteListener::StopListener()
{
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE("softbus manager is null");
        return false;
    }

    int ret = softbusManager_->RemoveSessionServer(OWN_SESSION_NAME, PEER_SESSION_NAME);
    if (ret != 0) {
        DBINDER_LOGE("fail to remove softbus server");
        return false;
    }
    softbusManager_ = nullptr;
    return true;
}

bool DBinderRemoteListener::SendDataToRemote(const std::string &deviceId, const struct DHandleEntryTxRx *msg)
{
    if (msg == nullptr) {
        DBINDER_LOGE("msg is null");
        return false;
    }

    std::shared_ptr<Session> session = OpenSoftbusSession(deviceId);
    if (session == nullptr) {
        DBINDER_LOGE("fail to open session");
        return false;
    }

    int ret = session->SendBytes(msg, msg->head.len);
    if (ret != 0) {
        DBINDER_LOGE("fail to send bytes, ret = %{public}d", ret);
        return false;
    }
    return true;
}

bool DBinderRemoteListener::CloseDatabusSession(const std::string &deviceId)
{
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE("softbus manager is null");
        return false;
    }

    std::shared_ptr<Session> session = softbusManager_->OpenSession(OWN_SESSION_NAME, PEER_SESSION_NAME, deviceId,
        std::string(""), Session::TYPE_BYTES);
    if (session == nullptr) {
        DBINDER_LOGE("fail to open session before closing it");
        return false;
    }

    return softbusManager_->CloseSession(session) == 0;
}

std::shared_ptr<Session> DBinderRemoteListener::OpenSoftbusSession(const std::string &peerDeviceId)
{
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE("softbus manager is null");
        return nullptr;
    }

    return softbusManager_->OpenSession(OWN_SESSION_NAME, PEER_SESSION_NAME, peerDeviceId, std::string(""),
        Session::TYPE_BYTES);
}

int DBinderRemoteListener::OnSessionOpened(std::shared_ptr<Session> session)
{
    DBINDER_LOGI("peer session is open");
    if (session->GetPeerUid() != getuid() || session->GetPeerSessionName() != PEER_SESSION_NAME) {
        DBINDER_LOGE("invalid session name, peer session name = %{public}s", session->GetPeerSessionName().c_str());
        return -DBINDER_SERVICE_WRONG_SESSION;
    }
    return 0;
}

void DBinderRemoteListener::OnSessionClosed(std::shared_ptr<Session> session)
{
    DBINDER_LOGI("peer session name = %{public}s is closed", session->GetPeerSessionName().c_str());
}

void DBinderRemoteListener::OnBytesReceived(std::shared_ptr<Session> session, const char *data, ssize_t len)
{
    if (data == nullptr || len != static_cast<ssize_t>(sizeof(struct DHandleEntryTxRx))) {
        DBINDER_LOGE("session has wrong input, peer session name = %s, data length = %zd",
            session->GetPeerSessionName().c_str(), len);
        // ignore the package
        return;
    }

    if (dBinderService_ == nullptr) {
        DBINDER_LOGE("dbinder service is not started");
        return;
    }

    struct DHandleEntryTxRx *handleEntry = (struct DHandleEntryTxRx *)data;
    if (handleEntry == nullptr) {
        DBINDER_LOGE("msg is null");
        return;
    }

    if (!dBinderService_->OnRemoteMessageTask(handleEntry)) {
        DBINDER_LOGE("process remote message fail");
    }
}
} // namespace OHOS

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
    softbusManager_ = ISessionService::GetInstance();
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
    ClearDeviceLock();
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "softbus manager is null");
        return false;
    }
    for (auto it = clientSessionMap_.begin(); it != clientSessionMap_.end(); it++) {
        std::shared_ptr<Session> session = it->second;
        if (session != nullptr) {
            softbusManager_->CloseSession(session);
        }
    }
    clientSessionMap_.clear();
    int ret = softbusManager_->RemoveSessionServer(OWN_SESSION_NAME, PEER_SESSION_NAME);
    if (ret != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to remove softbus server");
        return false;
    }
    softbusManager_ = nullptr;
    return true;
}

std::shared_ptr<DeviceLock> DBinderRemoteListener::QueryOrNewDeviceLock(const std::string &deviceId)
{
    std::lock_guard<std::mutex> lockGuard(deviceMutex_);
    auto it = deviceLockMap_.find(deviceId);
    if (it != deviceLockMap_.end()) {
        return it->second;
    }
    std::shared_ptr<DeviceLock> lockInfo = std::make_shared<struct DeviceLock>();
    if (lockInfo == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "failed to create mutex of device: %{public}s",
            DBinderService::ConvertToSecureDeviceID(deviceId).c_str());
        return nullptr;
    }
    deviceLockMap_.insert(std::pair<std::string, std::shared_ptr<DeviceLock>>(deviceId, lockInfo));
    return lockInfo;
}

void DBinderRemoteListener::ClearDeviceLock()
{
    std::lock_guard<std::mutex> lockGuard(deviceMutex_);
    deviceLockMap_.clear();
}

void DBinderRemoteListener::EraseDeviceLock(const std::string &deviceId)
{
    std::lock_guard<std::mutex> lockGuard(deviceMutex_);
    deviceLockMap_.erase(deviceId);
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
    DBINDER_LOGE(LOG_LABEL, "SendDataToRemote device: %{public}s ret: %{public}d",
            DBinderService::ConvertToSecureDeviceID(deviceId).c_str(), ret);
    if (ret != 0) {
        return false;
    }
    return true;
}

bool DBinderRemoteListener::SendDataReply(const std::string &deviceId, const struct DHandleEntryTxRx *msg)
{
    if (msg == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "msg is null");
        return false;
    }

    std::shared_ptr<Session> session = GetPeerSession(deviceId);
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "failed to get peer session, device: %{public}s",
            DBinderService::ConvertToSecureDeviceID(deviceId).c_str());
        return false;
    }

    int result = session->SendBytes(msg, msg->head.len);
    DBINDER_LOGE(LOG_LABEL, "SendDataReply device: %{public}s ret: %{public}d",
            DBinderService::ConvertToSecureDeviceID(deviceId).c_str(), result);
    return ((result != 0) ? false : true);
}

bool DBinderRemoteListener::CloseDatabusSession(const std::string &deviceId)
{
    EraseDeviceLock(deviceId);
    std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
    if (softbusManager_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "softbus manager is null");
        return false;
    }
    auto it = clientSessionMap_.find(deviceId);
    if (it != clientSessionMap_.end()) {
        bool result = softbusManager_->CloseSession(it->second) == 0;
        clientSessionMap_.erase(deviceId);
        DBINDER_LOGI(LOG_LABEL, "device: %{public}s offline, close session result: %{public}d",
            DBinderService::ConvertToSecureDeviceID(deviceId).c_str(), result);
        return result;
    }
    DBINDER_LOGI(LOG_LABEL, "no session of device: %{public}s",
        DBinderService::ConvertToSecureDeviceID(deviceId).c_str());
    return false;
}

std::shared_ptr<Session> DBinderRemoteListener::OpenSoftbusSession(const std::string &peerDeviceId)
{
    {
        std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
        if (softbusManager_ == nullptr) {
            DBINDER_LOGE(LOG_LABEL, "softbus manager is null");
            return nullptr;
        }
        auto it = clientSessionMap_.find(peerDeviceId);
        if (it != clientSessionMap_.end()) {
            return it->second;
        }
    }
    std::shared_ptr<DeviceLock> lockInfo = QueryOrNewDeviceLock(peerDeviceId);
    if (lockInfo == nullptr) {
        return nullptr;
    }
    // OpenSession is not thread-safe
    std::lock_guard<std::mutex> lock_unique(lockInfo->mutex);
    std::shared_ptr<Session> session = softbusManager_->OpenSession(OWN_SESSION_NAME, PEER_SESSION_NAME,
        peerDeviceId, std::string(""), Session::TYPE_BYTES);
    if (session == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "open session for dbinder service failed, device: %{public}s",
            DBinderService::ConvertToSecureDeviceID(peerDeviceId).c_str());
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
        clientSessionMap_.insert(std::pair<std::string, std::shared_ptr<Session>>(peerDeviceId, session));
    }
    return session;
}

std::shared_ptr<Session> DBinderRemoteListener::GetPeerSession(const std::string &peerDeviceId)
{
    std::lock_guard<std::mutex> lockGuard(serverSessionMutex_);
    auto it = serverSessionMap_.find(peerDeviceId);
    if (it != serverSessionMap_.end()) {
        return it->second;
    }
    return nullptr;
}

int DBinderRemoteListener::OnSessionOpened(std::shared_ptr<Session> session)
{
    DBINDER_LOGI(LOG_LABEL, "peer session is open, peer device: %{public}s, serverSide: %{public}d, "
        "channelId: %{public}" PRIu64,
        DBinderService::ConvertToSecureDeviceID(session->GetPeerDeviceId()).c_str(), session->IsServerSide(),
        session->GetChannelId());
    if (session->GetPeerSessionName() != PEER_SESSION_NAME) {
        DBINDER_LOGE(LOG_LABEL, "invalid session name, peer session name = %{public}s",
            session->GetPeerSessionName().c_str());
        return -DBINDER_SERVICE_WRONG_SESSION;
    }
    if (session->IsServerSide()) {
        std::lock_guard<std::mutex> lockGuard(serverSessionMutex_);
        std::string peerDeviceId = session->GetPeerDeviceId();
        serverSessionMap_[peerDeviceId] = session; // replace left session
    }
    return 0;
}

void DBinderRemoteListener::OnSessionClosed(std::shared_ptr<Session> session)
{
    DBINDER_LOGI(LOG_LABEL, "close session of device: %{public}s serverSide: %{public}d channelId: %{public}" PRIu64,
        DBinderService::ConvertToSecureDeviceID(session->GetPeerDeviceId()).c_str(), session->IsServerSide(),
        session->GetChannelId());
    if (session->IsServerSide()) {
        std::lock_guard<std::mutex> lockGuard(serverSessionMutex_);
        for (auto it = serverSessionMap_.begin(); it != serverSessionMap_.end(); it++) {
            if (it->second->GetChannelId() == session->GetChannelId()) {
                serverSessionMap_.erase(it);
                return;
            }
        }
    } else {
        EraseDeviceLock(session->GetPeerDeviceId());
        std::lock_guard<std::mutex> lockGuard(busManagerMutex_);
        for (auto it = clientSessionMap_.begin(); it != clientSessionMap_.end(); it++) {
            if (it->second->GetChannelId() == session->GetChannelId()) {
                clientSessionMap_.erase(it);
                break;
            }
        }
        dBinderService_->ProcessOnSessionClosed(session);
    }
}

void DBinderRemoteListener::OnBytesReceived(std::shared_ptr<Session> session, const char *data, ssize_t len)
{
    DBINDER_LOGI(LOG_LABEL, "OnBytesReceived len: %{public}u", static_cast<uint32_t>(len));
    if (data == nullptr || len != static_cast<ssize_t>(sizeof(struct DHandleEntryTxRx))) {
        DBINDER_LOGE(LOG_LABEL, "session has wrong input, peer session name = %s, data length = %zd",
            session->GetPeerSessionName().c_str(), len);
        // ignore the package
        return;
    }

    if (dBinderService_ == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "dbinder service is not started");
        return;
    }

    std::shared_ptr<struct DHandleEntryTxRx> message = std::make_shared<struct DHandleEntryTxRx>();
    if (message == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to create buffer with length = %{public}zu", sizeof(struct DHandleEntryTxRx));
        return;
    }
    auto res = memcpy_s(message.get(), sizeof(struct DHandleEntryTxRx), data, sizeof(struct DHandleEntryTxRx));
    if (res != 0) {
        DBINDER_LOGE(LOG_LABEL, "memcpy copy failed");
        return;
    }
    dBinderService_->AddAsynMessageTask(message);
}
} // namespace OHOS

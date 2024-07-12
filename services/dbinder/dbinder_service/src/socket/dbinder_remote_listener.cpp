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

#include "dbinder_error_code.h"
#include "dbinder_log.h"
#include "ipc_types.h"
#include "softbus_error_code.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_REMOTE_LISTENER,
    "DbinderRemoteListener" };

DBinderRemoteListener::DBinderRemoteListener()
{
    DBINDER_LOGI(LOG_LABEL, "create dbinder remote listener");

    clientListener_.OnBind = DBinderRemoteListener::ClientOnBind;
    clientListener_.OnShutdown = DBinderRemoteListener::ClientOnShutdown;
    clientListener_.OnBytes = DBinderRemoteListener::OnBytesReceived;
    clientListener_.OnMessage = DBinderRemoteListener::OnBytesReceived;

    serverListener_.OnBind = DBinderRemoteListener::ServerOnBind;
    serverListener_.OnShutdown = DBinderRemoteListener::ServerOnShutdown;
    serverListener_.OnBytes = DBinderRemoteListener::OnBytesReceived;
    serverListener_.OnMessage = DBinderRemoteListener::OnBytesReceived;
}

DBinderRemoteListener::~DBinderRemoteListener()
{
    DBINDER_LOGI(LOG_LABEL, "delete dbinder remote listener");
}

void DBinderRemoteListener::ServerOnBind(int32_t socket, PeerSocketInfo info)
{
    DBINDER_LOGI(LOG_LABEL, "socketId:%{public}d, peerNetworkId:%{public}s, peerName:%{public}s",
        socket, DBinderService::ConvertToSecureDeviceID(info.networkId).c_str(), info.name);
    std::lock_guard<std::mutex> lockGuard(serverSocketMutex_);
    serverSocketInfos_[info.networkId] = socket;
    return;
}

void DBinderRemoteListener::ServerOnShutdown(int32_t socket, ShutdownReason reason)
{
    DBINDER_LOGI(LOG_LABEL, "socketId:%{public}d, ShutdownReason:%{public}d", socket, reason);
    std::lock_guard<std::mutex> lockGuard(serverSocketMutex_);
    for (auto it = serverSocketInfos_.begin(); it != serverSocketInfos_.end(); it++) {
        if (it->second == socket) {
            serverSocketInfos_.erase(it);
            DBINDER_LOGI(LOG_LABEL, "Shutdown end");
            return;
        }
    }
}

void DBinderRemoteListener::ClientOnBind(int32_t socket, PeerSocketInfo info)
{
    return;
}

void DBinderRemoteListener::ClientOnShutdown(int32_t socket, ShutdownReason reason)
{
    DBINDER_LOGI(LOG_LABEL, "socketId:%{public}d, ShutdownReason:%{public}d", socket, reason);
    std::string networkId;
    {
        std::lock_guard<std::mutex> lockGuard(clientSocketMutex_);
        for (auto it = clientSocketInfos_.begin(); it != clientSocketInfos_.end(); it++) {
            if (it->second == socket) {
                networkId = it->first;
                DBINDER_LOGI(LOG_LABEL, "erase socket:%{public}d", socket);
                clientSocketInfos_.erase(it);
                break;
            }
        }
    }
    if (!networkId.empty()) {
        EraseDeviceLock(networkId);
        DBinderService::GetInstance()->ProcessOnSessionClosed(networkId);
    }
    DBINDER_LOGI(LOG_LABEL, "Shutdown end");
}

void DBinderRemoteListener::OnBytesReceived(int32_t socket, const void *data, uint32_t dataLen)
{
    DBINDER_LOGI(LOG_LABEL, "socketId:%{public}d len:%{public}u", socket, dataLen);
    if (data == nullptr || dataLen != static_cast<uint32_t>(sizeof(DHandleEntryTxRx))) {
        DBINDER_LOGE(LOG_LABEL, "wrong input, data length:%{public}u "
            "socketId:%{public}d", dataLen, socket);
        // ignore the package
        return;
    }

    std::shared_ptr<DHandleEntryTxRx> message = std::make_shared<DHandleEntryTxRx>();
    if (message == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "fail to create buffer with length:%{public}zu", sizeof(DHandleEntryTxRx));
        return;
    }
    auto res = memcpy_s(message.get(), sizeof(DHandleEntryTxRx), data, sizeof(DHandleEntryTxRx));
    if (res != 0) {
        DBINDER_LOGE(LOG_LABEL, "memcpy copy failed");
        return;
    }
    if (message->head.len != sizeof(DHandleEntryTxRx)) {
        DBINDER_LOGE(LOG_LABEL, "msg head len error, len:%{public}u", message->head.len);
        return;
    }
    DBINDER_LOGI(LOG_LABEL, "service:%{public}llu seq:%{public}u,"
        " stubIndex:%{public}" PRIu64 " code:%{public}u", message->binderObject,
        message->seqNumber, message->stubIndex, message->dBinderCode);

    DBinderService::GetInstance()->AddAsynMessageTask(message);
    return;
}

int32_t DBinderRemoteListener::CreateClientSocket(const std::string &peerNetworkId)
{
    std::shared_ptr<DeviceLock> lockInfo = QueryOrNewDeviceLock(peerNetworkId);
    if (lockInfo == nullptr) {
        return SOCKET_ID_INVALID;
    }
    std::lock_guard<std::mutex> lockUnique(lockInfo->mutex);

    {
        std::lock_guard<std::mutex> lockGuard(clientSocketMutex_);
        auto it = clientSocketInfos_.find(peerNetworkId);
        if (it != clientSocketInfos_.end()) {
            return it->second;
        }
    }

    SocketInfo socketInfo = {
        .name =  const_cast<char*>(OWN_SESSION_NAME.c_str()),
        .peerName = const_cast<char*>(PEER_SESSION_NAME.c_str()),
        .peerNetworkId = const_cast<char*>(peerNetworkId.c_str()),
        .pkgName = const_cast<char*>(DBINDER_SERVER_PKG_NAME.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    int32_t socketId = DBinderSoftbusClient::GetInstance().Socket(socketInfo);
    if (socketId <= 0) {
        DBINDER_LOGE(LOG_LABEL, "create socket error, socket is invalid");
        return SOCKET_ID_INVALID;
    }

    int32_t ret = DBinderSoftbusClient::GetInstance().Bind(socketId, QOS_TV, QOS_COUNT, &clientListener_);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_SOCKET_IN_USE) {
        DBINDER_LOGE(LOG_LABEL, "Bind failed, ret:%{public}d, socketId:%{public}d, peerNetworkId:%{public}s",
            ret, socketId, DBinderService::ConvertToSecureDeviceID(peerNetworkId).c_str());
        DBinderSoftbusClient::GetInstance().Shutdown(socketId);
        EraseDeviceLock(peerNetworkId);
        return SOCKET_ID_INVALID;
    }

    DBINDER_LOGI(LOG_LABEL, "Bind succ socketId:%{public}d, peerNetworkId:%{public}s",
        socketId, DBinderService::ConvertToSecureDeviceID(peerNetworkId).c_str());
    {
        std::lock_guard<std::mutex> lockGuard(clientSocketMutex_);

        clientSocketInfos_[peerNetworkId] = socketId;
    }

    return socketId;
}

int32_t DBinderRemoteListener::GetPeerSocketId(const std::string &peerNetworkId)
{
    std::lock_guard<std::mutex> lockGuard(serverSocketMutex_);
    auto it = serverSocketInfos_.find(peerNetworkId);
    if (it != serverSocketInfos_.end()) {
        return it->second;
    }
    return SOCKET_ID_INVALID;
}

bool DBinderRemoteListener::StartListener()
{
    DBINDER_LOGI(LOG_LABEL, "create socket server");
    int pid = static_cast<int>(getpid());
    int uid = static_cast<int>(getuid());

    int32_t ret = DBinderSoftbusClient::GetInstance().DBinderGrantPermission(uid, pid, OWN_SESSION_NAME);
    if (ret != ERR_NONE) {
        DBINDER_LOGE(LOG_LABEL, "GrantPermission failed softbus name:%{public}s", OWN_SESSION_NAME.c_str());
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_GRANT_PERMISSION_FAIL, __FUNCTION__);
        return false;
    }
    SocketInfo serverSocketInfo = {
        .name = const_cast<char*>(OWN_SESSION_NAME.c_str()),
        .pkgName = const_cast<char*>(DBINDER_SERVER_PKG_NAME.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    int32_t socketId = DBinderSoftbusClient::GetInstance().Socket(serverSocketInfo);
    if (socketId <= 0) {
        DBINDER_LOGE(LOG_LABEL, "create socket server error, socket is invalid");
        return false;
    }
    ret = DBinderSoftbusClient::GetInstance().Listen(socketId, QOS_TV, QOS_COUNT, &serverListener_);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_SOCKET_IN_USE) {
        DBINDER_LOGE(LOG_LABEL, "Listen failed, ret:%{public}d", ret);
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_CREATE_SOFTBUS_SERVER_FAIL, __FUNCTION__);
        DBinderSoftbusClient::GetInstance().Shutdown(socketId);
        return false;
    }
    DBINDER_LOGI(LOG_LABEL, "Listen ok, socketId:%{public}d", socketId);
    listenSocketId_ = socketId;

    return true;
}

bool DBinderRemoteListener::StopListener()
{
    ClearDeviceLock();
    {
        std::lock_guard<std::mutex> lockGuard(clientSocketMutex_);
        for (auto it = clientSocketInfos_.begin(); it != clientSocketInfos_.end(); it++) {
            DBinderSoftbusClient::GetInstance().Shutdown(it->second);
        }
        clientSocketInfos_.clear();
    }
    DBinderSoftbusClient::GetInstance().Shutdown(listenSocketId_);
    return true;
}

std::shared_ptr<DeviceLock> DBinderRemoteListener::QueryOrNewDeviceLock(const std::string &networkId)
{
    std::lock_guard<std::mutex> lockGuard(deviceMutex_);
    auto it = deviceLockMap_.find(networkId);
    if (it != deviceLockMap_.end()) {
        return it->second;
    }
    std::shared_ptr<DeviceLock> lockInfo = std::make_shared<struct DeviceLock>();
    if (lockInfo == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "failed to create mutex of device:%{public}s",
            DBinderService::ConvertToSecureDeviceID(networkId).c_str());
        return nullptr;
    }
    deviceLockMap_.insert(std::pair<std::string, std::shared_ptr<DeviceLock>>(networkId, lockInfo));
    return lockInfo;
}

void DBinderRemoteListener::ClearDeviceLock()
{
    std::lock_guard<std::mutex> lockGuard(deviceMutex_);
    deviceLockMap_.clear();
}

void DBinderRemoteListener::EraseDeviceLock(const std::string &networkId)
{
    std::lock_guard<std::mutex> lockGuard(deviceMutex_);
    deviceLockMap_.erase(networkId);
}

bool DBinderRemoteListener::SendDataToRemote(const std::string &networkId, const struct DHandleEntryTxRx *msg)
{
    DBINDER_LOGI(LOG_LABEL, "device:%{public}s",
        DBinderService::ConvertToSecureDeviceID(networkId).c_str());
    if (msg == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "msg is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return false;
    }

    int32_t socketId = CreateClientSocket(networkId);
    if (socketId <= 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to creat client Socket");
        return false;
    }

    int32_t ret = DBinderSoftbusClient::GetInstance().SendBytes(socketId, msg, msg->head.len);
    if (ret != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to send bytes, ret:%{public}d socketId:%{public}d, networkId:%{public}s",
            ret, socketId, DBinderService::ConvertToSecureDeviceID(networkId).c_str());
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_SEND_BYTES_FAIL, __FUNCTION__);
        return false;
    }
    DBINDER_LOGI(LOG_LABEL, "socketId:%{public}d device:%{public}s succ",
        socketId, DBinderService::ConvertToSecureDeviceID(networkId).c_str());
    return true;
}

bool DBinderRemoteListener::SendDataReply(const std::string &networkId, const struct DHandleEntryTxRx *msg)
{
    if (msg == nullptr) {
        DBINDER_LOGE(LOG_LABEL, "msg is null");
        DfxReportFailEvent(DbinderErrorCode::RPC_DRIVER, RADAR_ERR_INVALID_DATA, __FUNCTION__);
        return false;
    }

    int32_t socketId = GetPeerSocketId(networkId);
    if (socketId == SOCKET_ID_INVALID) {
        DBINDER_LOGE(LOG_LABEL, "failed to get peer SocketId, device:%{public}s",
            DBinderService::ConvertToSecureDeviceID(networkId).c_str());
        DfxReportFailDeviceEvent(DbinderErrorCode::RPC_DRIVER,
            DBinderService::ConvertToSecureDeviceID(networkId).c_str(), RADAR_GET_PEER_SESSION_FAIL, __FUNCTION__);
        return false;
    }

    int32_t result = DBinderSoftbusClient::GetInstance().SendBytes(socketId, msg, msg->head.len);
    if (result != 0) {
        DBINDER_LOGE(LOG_LABEL, "fail to send bytes of reply, result:%{public}d device:%{public}s"
            " socketId:%{public}d", result, DBinderService::ConvertToSecureDeviceID(networkId).c_str(), socketId);
        DfxReportFailDeviceEvent(DbinderErrorCode::RPC_DRIVER,
            DBinderService::ConvertToSecureDeviceID(networkId).c_str(), RADAR_SEND_BYTES_FAIL, __FUNCTION__);
        return false;
    }
    DBINDER_LOGI(LOG_LABEL, "socketId:%{public}d, networkId:%{public}s",
        socketId, DBinderService::ConvertToSecureDeviceID(networkId).c_str());
    return true;
}

bool DBinderRemoteListener::ShutdownSocket(const std::string &networkId)
{
    EraseDeviceLock(networkId);
    std::lock_guard<std::mutex> lockGuard(clientSocketMutex_);
    auto it = clientSocketInfos_.find(networkId);
    if (it != clientSocketInfos_.end()) {
        DBINDER_LOGI(LOG_LABEL, "networkId:%{public}s offline, Shutdown socketId:%{public}d ",
            DBinderService::ConvertToSecureDeviceID(networkId).c_str(), it->second);
        DBinderSoftbusClient::GetInstance().Shutdown(it->second);
        clientSocketInfos_.erase(it);
        return true;
    }
    DBINDER_LOGI(LOG_LABEL, "no socketId of networkId:%{public}s",
        DBinderService::ConvertToSecureDeviceID(networkId).c_str());
    return false;
}
} // namespace OHOS

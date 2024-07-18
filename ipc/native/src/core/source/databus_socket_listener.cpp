/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "databus_socket_listener.h"

#include "dbinder_databus_invoker.h"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "log_tags.h"
#include "softbus_error_code.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC_REMOTE_LISTENER, "DatabusSocketListener" };

DBinderSocketInfo::DBinderSocketInfo(const std::string &ownName, const std::string &peerName,
    const std::string &networkId) : ownName_(ownName), peerName_(peerName), networkId_(networkId)
{}

std::string DBinderSocketInfo::GetOwnName() const
{
    return ownName_;
}

std::string DBinderSocketInfo::GetPeerName() const
{
    return peerName_;
}

std::string DBinderSocketInfo::GetNetworkId() const
{
    return networkId_;
}

DatabusSocketListener::DatabusSocketListener()
{
    serverListener_.OnBind = DatabusSocketListener::ServerOnBind;
    serverListener_.OnShutdown = DatabusSocketListener::ServerOnShutdown;
    serverListener_.OnBytes = DatabusSocketListener::OnBytesReceived;
    serverListener_.OnMessage = DatabusSocketListener::OnBytesReceived;

    clientListener_.OnBind = DatabusSocketListener::ClientOnBind;
    clientListener_.OnShutdown = DatabusSocketListener::ClientOnShutdown;
    clientListener_.OnBytes = DatabusSocketListener::OnBytesReceived;
    clientListener_.OnMessage = DatabusSocketListener::OnBytesReceived;
}

DatabusSocketListener::~DatabusSocketListener() {}

void DatabusSocketListener::ServerOnBind(int32_t socket, PeerSocketInfo info)
{
    ZLOGI(LABEL, "socketId:%{public}d, deviceId:%{public}s, peerName:%{public}s",
        socket, IPCProcessSkeleton::ConvertToSecureString(info.networkId).c_str(), info.name);

    std::string networkId = info.networkId;
    std::string peerName = info.name;
    std::string str = peerName.substr(DBINDER_SOCKET_NAME_PREFIX.length());
    std::string::size_type pos = str.find("_");
    std::string peerUid = str.substr(0, pos);
    std::string peerPid = str.substr(pos + 1);

    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "fail to get invoker");
        return;
    }

    invoker->OnReceiveNewConnection(socket, std::stoi(peerPid), std::stoi(peerUid), peerName, networkId);
}

void DatabusSocketListener::ServerOnShutdown(int32_t socket, ShutdownReason reason)
{
    ZLOGI(LABEL, "socketId:%{public}d, ShutdownReason:%{public}d", socket, reason);
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "fail to get invoker");
        return;
    }
    invoker->OnDatabusSessionServerSideClosed(socket);
}

void DatabusSocketListener::ClientOnBind(int32_t socket, PeerSocketInfo info)
{
    return;
}

void DatabusSocketListener::ClientOnShutdown(int32_t socket, ShutdownReason reason)
{
    ZLOGI(LABEL, "socketId:%{public}d, ShutdownReason:%{public}d", socket, reason);
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "fail to get invoker");
        return;
    }

    DBinderSocketInfo socketInfo;
    {
        std::lock_guard<std::mutex> lockGuard(socketInfoMutex_);
        for (auto it = socketInfoMap_.begin(); it != socketInfoMap_.end(); it++) {
            if (it->second == socket) {
                socketInfo = it->first;
                ZLOGI(LOG_LABEL, "erase socketId:%{public}d ", it->second);
                socketInfoMap_.erase(it);
                break;
            }
        }
    }
    EraseDeviceLock(socketInfo);
    invoker->OnDatabusSessionClientSideClosed(socket);
}

void DatabusSocketListener::OnBytesReceived(int32_t socket, const void *data, uint32_t dataLen)
{
    ZLOGI(LABEL, "socketId:%{public}d len:%{public}u", socket, dataLen);
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "fail to get invoker");
        return;
    }

    invoker->OnMessageAvailable(socket, static_cast<const char*>(data), dataLen);
}

int32_t DatabusSocketListener::StartServerListener(const std::string &ownName)
{
    std::string pkgName = DBINDER_PKG_NAME + "_" + std::to_string(getpid());

    SocketInfo serverSocketInfo = {
        .name = const_cast<char*>(ownName.c_str()),
        .pkgName = const_cast<char*>(pkgName.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    int32_t socketId = DBinderSoftbusClient::GetInstance().Socket(serverSocketInfo);
    if (socketId <= 0) {
        ZLOGE(LABEL, "create socket server error, socket is invalid");
        return SOCKET_ID_INVALID;
    }
    int32_t ret = DBinderSoftbusClient::GetInstance().Listen(socketId, QOS_TV, QOS_COUNT, &serverListener_);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_SOCKET_IN_USE) {
        ZLOGE(LABEL, "Listen failed, ret:%{public}d", ret);
        DBinderSoftbusClient::GetInstance().Shutdown(socketId);
        return SOCKET_ID_INVALID;
    }
    ZLOGI(LABEL, "Listen ok, socketId:%{public}d, ownName:%{public}s", socketId, ownName.c_str());
    return socketId;
}

std::shared_ptr<std::mutex> DatabusSocketListener::QueryOrNewInfoMutex(DBinderSocketInfo socketInfo)
{
    std::lock_guard<std::mutex> lockGuard(deviceMutex_);
    auto it = infoMutexMap_.find(socketInfo);
    if (it != infoMutexMap_.end()) {
        return it->second;
    }
    std::shared_ptr<std::mutex> infoMutex = std::make_shared<std::mutex>();
    if (infoMutex == nullptr) {
        ZLOGE(LOG_LABEL, "failed to create mutex, ownName:%{public}s, peerName:%{public}s, networkId:%{public}s",
            socketInfo.GetOwnName().c_str(), socketInfo.GetPeerName().c_str(),
            IPCProcessSkeleton::ConvertToSecureString(socketInfo.GetNetworkId()).c_str());
        return nullptr;
    }
    infoMutexMap_[socketInfo] = infoMutex;
    return infoMutex;
}

int32_t DatabusSocketListener::CreateClientSocket(const std::string &ownName, const std::string &peerName,
    const std::string &networkId)
{
    DBinderSocketInfo info(ownName, peerName, networkId);
    std::shared_ptr<std::mutex> infoMutex = QueryOrNewInfoMutex(info);
    if (infoMutex == nullptr) {
        return SOCKET_ID_INVALID;
    }
    std::lock_guard<std::mutex> lockUnique(*infoMutex);

    {
        std::lock_guard<std::mutex> lockGuard(socketInfoMutex_);
        auto it = socketInfoMap_.find(info);
        if (it != socketInfoMap_.end()) {
            return it->second;
        }
    }

    std::string pkgName = std::string(DBINDER_PKG_NAME) + "_" + std::to_string(getpid());
    SocketInfo socketInfo = {
        .name =  const_cast<char*>(ownName.c_str()),
        .peerName = const_cast<char*>(peerName.c_str()),
        .peerNetworkId = const_cast<char*>(networkId.c_str()),
        .pkgName = const_cast<char*>(pkgName.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    int32_t socketId = DBinderSoftbusClient::GetInstance().Socket(socketInfo);
    if (socketId <= 0) {
        ZLOGE(LABEL, "create socket error, socket is invalid");
        return SOCKET_ID_INVALID;
    }
    int32_t ret = DBinderSoftbusClient::GetInstance().Bind(socketId, QOS_TV, QOS_COUNT, &clientListener_);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_SOCKET_IN_USE) {
        ZLOGE(LABEL, "Bind failed, ret:%{public}d, socketId:%{public}d,"
            "ownName:%{public}s, peerName:%{public}s, peerNetworkId:%{public}s",
            ret, socketId, ownName.c_str(), peerName.c_str(),
            IPCProcessSkeleton::ConvertToSecureString(networkId).c_str());
        DBinderSoftbusClient::GetInstance().Shutdown(socketId);
        EraseDeviceLock(info);
        return SOCKET_ID_INVALID;
    }
    ZLOGI(LABEL, "Bind succ, ownName:%{public}s peer:%{public}s deviceId:%{public}s "
        "socketId:%{public}d", ownName.c_str(), peerName.c_str(),
        IPCProcessSkeleton::ConvertToSecureString(networkId).c_str(), socketId);
    {
        std::lock_guard<std::mutex> lockGuard(socketInfoMutex_);
        socketInfoMap_[info] = socketId;
    }
    return socketId;
}

void DatabusSocketListener::ShutdownSocket(int32_t socketId)
{
    DBinderSocketInfo socketInfo;
    {
        std::lock_guard<std::mutex> lockGuard(socketInfoMutex_);
        for (auto it = socketInfoMap_.begin(); it != socketInfoMap_.end(); it++) {
            if (it->second == socketId) {
                ZLOGI(LOG_LABEL, "Shutdown socketId:%{public}d ", it->second);
                DBinderSoftbusClient::GetInstance().Shutdown(it->second);
                socketInfo = it->first;
                it = socketInfoMap_.erase(it);
                break;
            }
        }
    }
    EraseDeviceLock(socketInfo);
}

void DatabusSocketListener::EraseDeviceLock(DBinderSocketInfo info)
{
    std::lock_guard<std::mutex> lockGuard(deviceMutex_);
    auto it = infoMutexMap_.find(info);
    if (it != infoMutexMap_.end()) {
        infoMutexMap_.erase(it);
    }
}

void DatabusSocketListener::RemoveSessionName(void)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "get current is null");
        return;
    }
    sptr<IRemoteObject> object = current->GetSAMgrObject();
    if (object == nullptr) {
        ZLOGE(LABEL, "get object is null");
        return;
    }

    IPCObjectProxy *samgr = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());
    const std::string sessionName = current->GetDatabusName();
    samgr->RemoveSessionName(sessionName);
    ZLOGI(LABEL, "%{public}s", sessionName.c_str());
}
} // namespace OHOS

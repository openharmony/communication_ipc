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

#include "databus_socket_listener.h"

#include "dbinder_databus_invoker.h"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "log_tags.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC_REMOTE_LISTENER, "DatabusSocketListener" };

DatabusSocketListener::DatabusSocketListener()
{
    serverListener_.OnBind = DatabusSocketListener::ServerOnBind;
    serverListener_.OnShutdown = DatabusSocketListener::ServerOnShutdown;
    serverListener_.OnBytes = DatabusSocketListener::OnBytesReceived;

    clientListener_.OnBind = DatabusSocketListener::ClientOnBind;
    clientListener_.OnShutdown = DatabusSocketListener::ClientOnShutdown;
    clientListener_.OnBytes = DatabusSocketListener::OnBytesReceived;
}

DatabusSocketListener::~DatabusSocketListener() {}

void DatabusSocketListener::ServerOnBind(int32_t socket, PeerSocketInfo info)
{
    ZLOGI(LABEL, "socketId:%{public}d, deviceId:%{public}s", socket,
        IPCProcessSkeleton::ConvertToSecureString(info.networkId).c_str());

    std::string peerName = info.name;    
    std::string networkId = info.networkId;
    std::string str = peerName.substr(DBINDER_SOCKET_NAME_PREFIX.length());
    std::string peerUid = str.substr(0, str.find("_"));
    std::string peerPid = str.substr(str.find("_") + 1);

    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "fail to get invoker");
        return;
    }

    invoker->OnReceiveNewConnection(socket, std::stoi(peerPid), std::stoi(peerUid), peerName, networkId);
    return;
}

void DatabusSocketListener::ServerOnShutdown(int32_t socket, ShutdownReason reason)
{
    ZLOGI(LABEL, "socket:%{public}d, ShutdownReason:%{public}d", socket, reason);
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "fail to get invoker");
        return;
    }

    invoker->OnDatabusSessionServerSideClosed(socket);
    ZLOGI(LABEL, "end, socket:%{public}d", socket);

    return;
}

void DatabusSocketListener::ClientOnBind(int32_t socket, PeerSocketInfo info)
{
    return;
}

void DatabusSocketListener::ClientOnShutdown(int32_t socket, ShutdownReason reason)
{
    ZLOGI(LABEL, "socket:%{public}d, ShutdownReason:%{public}d", socket, reason);
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "fail to get invoker");
        return;
    }

    invoker->OnDatabusSessionClientSideClosed(socket);
    ZLOGI(LABEL, "end, socket:%{public}d", socket);
    return;
}

void DatabusSocketListener::OnBytesReceived(int32_t socket, const void *data, uint32_t dataLen)
{
    ZLOGI(LABEL, "socket:%{public}d len:%{public}u", socket, dataLen);
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "fail to get invoker");
        return;
    }

    invoker->OnMessageAvailable(socket, static_cast<const char*>(data), dataLen);
    return;
}

int32_t DatabusSocketListener::StartServerListener(const std::string &ownName)
{
    std::string pkgName = DBINDER_PKG_NAME + "_" + std::to_string(getpid());

    SocketInfo serverSocketInfo = {
        .name = const_cast<char*>(ownName.c_str()),
        .pkgName = const_cast<char*>(pkgName.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    int32_t socketId = Socket(serverSocketInfo);
    if (socketId <= 0) {
        ZLOGE(LABEL, "create socket server error, socket is invalid");
        return INVALID_ID;
    }
    int32_t ret = Listen(socketId, QOS_TV, QOS_COUNT, &serverListener_);
    if (ret != 0) {
        ZLOGE(LABEL, "Listen failed, ret:%{public}d", ret);
        Shutdown(socketId);
        return INVALID_ID;
    }
    ZLOGI(LABEL, "Listen ok, socketId:%{public}d, ownName:%{public}s", socketId, ownName.c_str());
    return socketId;
}

int32_t DatabusSocketListener::CreateClientSocket(const std::string &ownName,
    const std::string &peerName, const std::string &networkId)
{    
    std::string pkgName = std::string(DBINDER_PKG_NAME) + "_" + std::to_string(getpid());

    SocketInfo socketInfo = {
        .name =  const_cast<char*>(ownName.c_str()),
        .peerName = const_cast<char*>(peerName.c_str()),
        .peerNetworkId = const_cast<char*>(networkId.c_str()),
        .pkgName = const_cast<char*>(pkgName.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES,
    };
    int32_t socketId = Socket(socketInfo);
    if (socketId <= 0) {
        ZLOGE(LABEL, "create socket error, socket is invalid");
        return INVALID_ID;
    }
    int32_t ret = Bind(socketId, QOS_TV, QOS_COUNT, &clientListener_);
    if (ret != ERR_NONE) {
        ZLOGE(LABEL, "Bind failed, ret:%{public}d, socketid:%{public}d,"
            "own:%{public}s peer:%{public}s  ,peerNetworkId:%{public}s",
            ret, socketId, ownName.c_str(), peerName.c_str(),
            IPCProcessSkeleton::ConvertToSecureString(networkId).c_str());
        Shutdown(socketId);
        return INVALID_ID;
    }
    ZLOGI(LABEL, "Bind succ, own:%{public}s peer:%{public}s deviceId:%{public}s "
        "socketId:%{public}d", ownName.c_str(), peerName.c_str(),
        IPCProcessSkeleton::ConvertToSecureString(networkId).c_str(), socketId);

    return socketId;
}
} // namespace OHOS

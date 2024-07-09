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

#ifndef OHOS_IPC_DBINDER_DATABUS_SOCKET_LISTENER_H
#define OHOS_IPC_DBINDER_DATABUS_SOCKET_LISTENER_H

#include <list>
#include <unordered_map>

#include "singleton.h"

#include "dbinder_softbus_client.h"
#include "ipc_types.h"

namespace OHOS {
static constexpr QosTV QOS_TV[] = {
    { .qos = QOS_TYPE_MIN_BW, .value = RPC_QOS_MIN_BW },
    { .qos = QOS_TYPE_MAX_LATENCY, .value = RPC_QOS_MAX_LATENCY },
    { .qos = QOS_TYPE_MIN_LATENCY, .value = RPC_QOS_MIN_LATENCY }
};
static constexpr uint32_t QOS_COUNT = static_cast<uint32_t>(sizeof(QOS_TV) / sizeof(QosTV));

static const std::string DBINDER_PKG_NAME = "DBinderBus";
static const std::string DBINDER_SOCKET_NAME_PREFIX = "DBinder";

class DBinderSocketInfo {
public:
    DBinderSocketInfo(const std::string &ownName, const std::string &peerName, const std::string &networkId);
    DBinderSocketInfo() = default;
    virtual ~DBinderSocketInfo() = default;
    std::string GetOwnName() const;
    std::string GetPeerName() const;
    std::string GetNetworkId() const;

    bool operator==(const DBinderSocketInfo &info) const
    {
        return (info.GetOwnName().compare(ownName_) == 0 &&
            info.GetPeerName().compare(peerName_) == 0 &&
            info.GetNetworkId().compare(networkId_) == 0);
    }

private:
    std::string ownName_;
    std::string peerName_;
    std::string networkId_;
};

struct SocketInfoHash {
    size_t operator()(const DBinderSocketInfo &info) const
    {
        return std::hash<std::string>()(info.GetOwnName()) ^
            std::hash<std::string>()(info.GetPeerName()) ^
            std::hash<std::string>()(info.GetNetworkId());
    }
};

class DatabusSocketListener {
    DECLARE_DELAYED_SINGLETON(DatabusSocketListener)
public:
    int32_t StartServerListener(const std::string &ownName);
    int32_t CreateClientSocket(const std::string &ownName, const std::string &peerName,
        const std::string &networkId);
    void ShutdownSocket(int32_t socket);

    static void ServerOnBind(int32_t socket, PeerSocketInfo info);
    static void ServerOnShutdown(int32_t socket, ShutdownReason reason);
    static void ClientOnBind(int32_t socket, PeerSocketInfo info);
    static void ClientOnShutdown(int32_t socket, ShutdownReason reason);
    static void OnBytesReceived(int32_t socket, const void *data, uint32_t dataLen);
    static void EraseDeviceLock(DBinderSocketInfo info);
    static void RemoveSessionName(void);

private:
    std::shared_ptr<std::mutex> QueryOrNewInfoMutex(DBinderSocketInfo socketInfo);

    ISocketListener clientListener_ {};
    ISocketListener serverListener_ {};

    static inline std::mutex socketInfoMutex_;
    static inline std::mutex deviceMutex_;
    static inline std::unordered_map<DBinderSocketInfo, std::shared_ptr<std::mutex>, SocketInfoHash> infoMutexMap_ {};
    static inline std::unordered_map<DBinderSocketInfo, int32_t, SocketInfoHash> socketInfoMap_ {};
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_DATABUS_SOCKET_LISTENER_H

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

#ifndef OHOS_IPC_DBINDER_REMOTE_LISTENER_H
#define OHOS_IPC_DBINDER_REMOTE_LISTENER_H

#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <map>
#include <mutex>

#include "dbinder_service.h"
#include "dbinder_softbus_client.h"

namespace OHOS {
struct DeviceLock {
    std::mutex mutex;
};

class DBinderRemoteListener {
public:
    DBinderRemoteListener();
    ~DBinderRemoteListener();

    static void ServerOnBind(int32_t socket, PeerSocketInfo info);
    static void ServerOnShutdown(int32_t socket, ShutdownReason reason);
    static void ClientOnBind(int32_t socket, PeerSocketInfo info);
    static void ClientOnShutdown(int32_t socket, ShutdownReason reason);
    static void OnBytesReceived(int32_t socket, const void *data, uint32_t dataLen);
    static void EraseDeviceLock(const std::string &networkId);

    bool StartListener();
    bool StopListener();
    bool SendDataToRemote(const std::string &networkId, const struct DHandleEntryTxRx *msg);
    bool SendDataReply(const std::string &networkId, const struct DHandleEntryTxRx *msg);
    bool ShutdownSocket(const std::string &networkId);

private:
    DISALLOW_COPY_AND_MOVE(DBinderRemoteListener);

    std::shared_ptr<DeviceLock> QueryOrNewDeviceLock(const std::string &networkId);
    void ClearDeviceLock();

    int32_t CreateClientSocket(const std::string &peerNetworkId);
    static int32_t GetPeerSocketId(const std::string &peerNetworkId);

    const std::string DBINDER_SERVER_PKG_NAME = "DBinderBus";
    const std::string OWN_SESSION_NAME = "DBinderService";
    const std::string PEER_SESSION_NAME = "DBinderService";

    static constexpr QosTV QOS_TV[] = {
        { .qos = QOS_TYPE_MIN_BW, .value = RPC_QOS_MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = RPC_QOS_MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = RPC_QOS_MIN_LATENCY },
        { .qos = QOS_TYPE_MAX_IDLE_TIMEOUT, .value = RPC_QOS_MAX_IDLE_TIME }
    };
    static constexpr uint32_t QOS_COUNT = static_cast<uint32_t>(sizeof(QOS_TV) / sizeof(QosTV));

    int32_t listenSocketId_ = SOCKET_ID_INVALID;
    ISocketListener clientListener_ {};
    ISocketListener serverListener_ {};

    static inline std::mutex deviceMutex_;
    static inline std::mutex clientSocketMutex_;
    static inline std::mutex serverSocketMutex_;
    static inline std::map<std::string, std::shared_ptr<DeviceLock>> deviceLockMap_ {};
    static inline std::map<std::string, int32_t> clientSocketInfos_ {};
    static inline std::map<std::string, int32_t> serverSocketInfos_ {};
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_REMOTE_LISTENER_H

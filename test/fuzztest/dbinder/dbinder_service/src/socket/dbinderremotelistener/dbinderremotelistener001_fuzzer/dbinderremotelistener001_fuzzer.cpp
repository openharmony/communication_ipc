/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dbinderremotelistener_fuzzer.h"

namespace OHOS {
    void ServerOnBindTest(FuzzedDataProvider &provider)
    {
        int32_t socket = provider.ConsumeIntegral<int32_t>();
        PeerSocketInfo info;
        std::string networkId = provider.ConsumeRandomLengthString();
        std::string name = provider.ConsumeRandomLengthString();
        info.networkId = const_cast<char *>(networkId.c_str());
        info.name = const_cast<char *>(name.c_str());
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        dBinderRemoteListener->ServerOnBind(socket, info);
    }

    void ServerOnShutdownTest(FuzzedDataProvider &provider)
    {
        int32_t socket = provider.ConsumeIntegral<int32_t>();
        std::string networkId = provider.ConsumeRandomLengthString();
        ShutdownReason reason = SHUTDOWN_REASON_UNKNOWN;
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        dBinderRemoteListener->ServerOnShutdown(socket, reason);

        dBinderRemoteListener->serverSocketInfos_[networkId] = socket;
        dBinderRemoteListener->ServerOnShutdown(socket, reason);
    }

    void ClientOnShutdownTest(FuzzedDataProvider &provider)
    {
        int32_t socket = provider.ConsumeIntegral<int32_t>();
        std::string networkId = provider.ConsumeRandomLengthString();
        ShutdownReason reason = SHUTDOWN_REASON_UNKNOWN;
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        dBinderRemoteListener->ClientOnShutdown(socket, reason);

        dBinderRemoteListener->clientSocketInfos_[networkId] = socket;
        dBinderRemoteListener->ClientOnShutdown(socket, reason);
    }

    void CreateClientSocketTest(FuzzedDataProvider &provider)
    {
        std::string peerNetworkId = provider.ConsumeRandomLengthString();
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        dBinderRemoteListener->CreateClientSocket(peerNetworkId);
        int32_t socketId = provider.ConsumeIntegral<int32_t>();
        dBinderRemoteListener->clientSocketInfos_[peerNetworkId] = socketId;
        dBinderRemoteListener->CreateClientSocket(peerNetworkId);
    }

    void QueryOrNewDeviceLockTest(FuzzedDataProvider &provider)
    {
        std::string networkId = provider.ConsumeRandomLengthString();
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        dBinderRemoteListener->QueryOrNewDeviceLock(networkId);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ServerOnBindTest(provider);
    OHOS::ServerOnShutdownTest(provider);
    OHOS::ClientOnShutdownTest(provider);
    OHOS::CreateClientSocketTest(provider);
    OHOS::QueryOrNewDeviceLockTest(provider);
    return 0;
}

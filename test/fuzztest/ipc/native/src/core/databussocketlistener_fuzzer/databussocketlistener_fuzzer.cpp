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

#include "databussocketlistener_fuzzer.h"

#define private public
#define protected public
#include "databus_socket_listener.h"
#undef protected
#undef private
#include "securec.h"

using OHOS::DatabusSocketListener;

namespace OHOS {
static std::string TEST_SOCKET_NAME = "DBinder1_1";
static std::string TEST_SOCKET_PEER_NAME = "DBinderService";
static std::string TEST_SOCKET_PEER_NETWORKID = "wad213hkad213jh123jk213j1h2312h3jk12dadadeawd721hledhjlad22djhla";
static std::string TEST_SOCKET_PKG_NAME = "DBinderBus";

static void DBinderSocketInfoFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::string ownName(reinterpret_cast<const char *>(data), size);
    std::string peerName(reinterpret_cast<const char *>(data), size);
    std::string networkId(reinterpret_cast<const char *>(data), size);
    OHOS::DBinderSocketInfo info(ownName, peerName, networkId);
    (void)info.GetOwnName();
    (void)info.GetPeerName();
    (void)info.GetNetworkId();
}

static void ServerOnBindFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t socketId = -1;
    if (memcpy_s(&socketId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    PeerSocketInfo info = {
        .name = const_cast<char *>(TEST_SOCKET_NAME.c_str()),
        .networkId = const_cast<char *>(TEST_SOCKET_PEER_NETWORKID.c_str()),
        .pkgName = const_cast<char *>(TEST_SOCKET_PKG_NAME.c_str()),
        .dataType = DATA_TYPE_MESSAGE,
    };

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }

    listener->ServerOnBind(socketId, info);
}

static void ServerOnShutdownFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(int32_t) + sizeof(ShutdownReason))) {
        return;
    }

    int32_t socketId = -1;
    if (memcpy_s(&socketId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    ShutdownReason reason = SHUTDOWN_REASON_UNKNOWN;
    if (memcpy_s(&reason, sizeof(ShutdownReason), data, sizeof(ShutdownReason)) != EOK) {
        return;
    }

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }

    listener->ServerOnShutdown(socketId, reason);
}

static void ClientOnShutdownFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(int32_t) + sizeof(ShutdownReason))) {
        return;
    }

    int32_t socketId = -1;
    if (memcpy_s(&socketId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    ShutdownReason reason = SHUTDOWN_REASON_UNKNOWN;
    if (memcpy_s(&reason, sizeof(ShutdownReason), data, sizeof(ShutdownReason)) != EOK) {
        return;
    }

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }

    listener->ClientOnShutdown(socketId, reason);
}

static void OnBytesRecivedFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size <= sizeof(int32_t)) {
        return;
    }

    int32_t socketId = -1;
    if (memcpy_s(&socketId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    const void *recivedData = data + sizeof(int32_t);
    uint32_t recivedLen = size - sizeof(int32_t);

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }

    listener->OnBytesReceived(socketId, recivedData, recivedLen);
}

static void StartServerListenerFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string name(reinterpret_cast<const char *>(data), size);

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    (void)listener->StartServerListener(name);
}

static void QueryOrNewInfoMutexFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::string ownName(reinterpret_cast<const char *>(data), size);
    std::string peerName(reinterpret_cast<const char *>(data), size);
    std::string networkId(reinterpret_cast<const char *>(data), size);

    OHOS::DBinderSocketInfo info1(ownName, TEST_SOCKET_PEER_NAME, TEST_SOCKET_PEER_NETWORKID);
    OHOS::DBinderSocketInfo info2(TEST_SOCKET_NAME, peerName, TEST_SOCKET_PEER_NETWORKID);
    OHOS::DBinderSocketInfo info3(TEST_SOCKET_NAME, TEST_SOCKET_PEER_NAME, networkId);

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    (void)listener->QueryOrNewInfoMutex(info1);
    (void)listener->QueryOrNewInfoMutex(info2);
    (void)listener->QueryOrNewInfoMutex(info3);
}

static void CreateClientSocketFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::string ownName(reinterpret_cast<const char *>(data), size);
    std::string peerName(reinterpret_cast<const char *>(data), size);
    std::string networkId(reinterpret_cast<const char *>(data), size);

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }

    listener->CreateClientSocket(TEST_SOCKET_NAME, TEST_SOCKET_PEER_NAME, TEST_SOCKET_PEER_NETWORKID);
    listener->CreateClientSocket(ownName, peerName, TEST_SOCKET_PEER_NETWORKID);
    listener->CreateClientSocket(TEST_SOCKET_NAME, TEST_SOCKET_PEER_NAME, networkId);
}

static void ShutdownSocketFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size <= sizeof(int32_t)) {
        return;
    }

    int32_t socketId = -1;
    if (memcpy_s(&socketId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }

    listener->ShutdownSocket(socketId);
}

static void EraseDeviceLockFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::string ownName(reinterpret_cast<const char *>(data), size);
    std::string peerName(reinterpret_cast<const char *>(data), size);
    std::string networkId(reinterpret_cast<const char *>(data), size);

    OHOS::DBinderSocketInfo info1(ownName, TEST_SOCKET_PEER_NAME, TEST_SOCKET_PEER_NETWORKID);
    OHOS::DBinderSocketInfo info2(TEST_SOCKET_NAME, peerName, TEST_SOCKET_PEER_NETWORKID);
    OHOS::DBinderSocketInfo info3(TEST_SOCKET_NAME, TEST_SOCKET_PEER_NAME, networkId);

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    listener->EraseDeviceLock(info1);
    listener->EraseDeviceLock(info2);
    listener->EraseDeviceLock(info3);
    listener->RemoveSessionName();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DBinderSocketInfoFuzzTest(data, size);
    OHOS::ServerOnBindFuzzTest(data, size);
    OHOS::ServerOnShutdownFuzzTest(data, size);
    OHOS::ClientOnShutdownFuzzTest(data, size);
    OHOS::OnBytesRecivedFuzzTest(data, size);
    OHOS::StartServerListenerFuzzTest(data, size);
    OHOS::QueryOrNewInfoMutexFuzzTest(data, size);
    OHOS::CreateClientSocketFuzzTest(data, size);
    OHOS::ShutdownSocketFuzzTest(data, size);
    OHOS::EraseDeviceLockFuzzTest(data, size);
    return 0;
}

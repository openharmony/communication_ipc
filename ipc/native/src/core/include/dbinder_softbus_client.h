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

#ifndef OHOS_IPC_DBINDER_SOFTBUS_CLIENT_H
#define OHOS_IPC_DBINDER_SOFTBUS_CLIENT_H

#include <mutex>
#include <string>
#include <atomic>

#include "inner_socket.h"
#include "nocopyable.h"
#include "socket.h"
#include "softbus_bus_center.h"

namespace OHOS {
enum {
    SOFTBUS_CLIENT_SUCCESS = 0,
    SOFTBUS_CLIENT_DLOPEN_FAILED,
    SOFTBUS_CLIENT_DLSYM_FAILED,
    SOFTBUS_CLIENT_INSTANCE_EXIT,
    SOFTBUS_CLIENT_GET_DEVICE_INFO_FAILED,
};

static constexpr int MAX_SEND_MESSAGE_LENGTH = 4 * 1024;

class DBinderSoftbusClient {
public:
    static DBinderSoftbusClient& GetInstance();
    DBinderSoftbusClient();
    ~DBinderSoftbusClient();

    int32_t DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName);
    int32_t DBinderRemovePermission(const std::string &socketName);
    int32_t GetLocalNodeDeviceId(const std::string &pkgName, std::string &devId);
    int32_t Socket(SocketInfo info);
    int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener);
    int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener);
    int32_t SendBytes(int32_t socket, const void *data, uint32_t len);
    int32_t SendMessage(int32_t socket, const void *data, uint32_t len);
    void Shutdown(int32_t socket);

private:
    DISALLOW_COPY_AND_MOVE(DBinderSoftbusClient);
    bool OpenSoftbusClientSo();

    using DBinderGrantPermissionFunc = int32_t (*)(int32_t, int32_t, const char*);
    using DBinderRemovePermissionFunc = int32_t (*)(const char*);
    using GetLocalNodeDeviceInfoFunc = int32_t (*)(const char*, NodeBasicInfo*);
    using SocketFunc = int32_t (*)(SocketInfo);
    using ListenFunc = int32_t (*)(int32_t, const QosTV[], uint32_t, const ISocketListener*);
    using BindFunc = int32_t (*)(int32_t, const QosTV[], uint32_t, const ISocketListener*);
    using SendBytesFunc = int32_t (*)(int32_t, const void*, uint32_t);
    using SendMessageFunc = int32_t (*)(int32_t, const void*, uint32_t);
    using ShutdownFunc = void (*)(int32_t);

    DBinderGrantPermissionFunc grantPermissionFunc_ = nullptr;
    DBinderRemovePermissionFunc removePermissionFunc_ = nullptr;
    GetLocalNodeDeviceInfoFunc getLocalNodeDeviceInfoFunc_ = nullptr;
    SocketFunc socketFunc_ = nullptr;
    ListenFunc listenFunc_ = nullptr;
    BindFunc bindFunc_ = nullptr;
    SendBytesFunc sendBytesFunc_ = nullptr;
    SendMessageFunc sendMessageFunc_ = nullptr;
    ShutdownFunc shutdownFunc_ = nullptr;

    std::mutex loadSoMutex_;
    std::atomic<bool> exitFlag_ = false;
    bool isLoaded_ = false;
    void *soHandle_ = nullptr;
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_SOFTBUS_CLIENT_H

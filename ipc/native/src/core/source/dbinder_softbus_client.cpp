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

#include "dbinder_softbus_client.h"

#include <dlfcn.h>
#include "check_instance_exit.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {

using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_DBINDER_SOFTBUS_CLIENT, "DBinderSoftbusClient"};

#ifdef __aarch64__
static constexpr const char *SOFTBUS_PATH_NAME = "/system/lib64/platformsdk/libsoftbus_client.z.so";
#else
static constexpr const char *SOFTBUS_PATH_NAME = "/system/lib/platformsdk/libsoftbus_client.z.so";
#endif

DBinderSoftbusClient& DBinderSoftbusClient::GetInstance()
{
    static DBinderSoftbusClient instance;
    return instance;
}

DBinderSoftbusClient::DBinderSoftbusClient()
{
}

DBinderSoftbusClient::~DBinderSoftbusClient()
{
    exitFlag_ = true;
    ZLOGI(LOG_LABEL, "destroy");
}

bool DBinderSoftbusClient::OpenSoftbusClientSo()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);

    if (isLoaded_ && (soHandle_ != nullptr)) {
        return true;
    }

    soHandle_ = dlopen(SOFTBUS_PATH_NAME, RTLD_NOW | RTLD_NODELETE);
    if (soHandle_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed, err msg:%{public}s", SOFTBUS_PATH_NAME, dlerror());
        return false;
    }

    isLoaded_ = true;
    ZLOGI(LOG_LABEL, "dlopen %{public}s SOFTBUS_CLIENT_SUCCESS", SOFTBUS_PATH_NAME);

    return true;
}

int32_t DBinderSoftbusClient::DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    if (grantPermissionFunc_ != nullptr) {
        return grantPermissionFunc_(uid, pid, socketName.c_str());
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    grantPermissionFunc_ = (DBinderGrantPermissionFunc)dlsym(soHandle_, "DBinderGrantPermission");
    if (grantPermissionFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym DBinderGrantPermission fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }

    return grantPermissionFunc_(uid, pid, socketName.c_str());
}

int32_t DBinderSoftbusClient::DBinderRemovePermission(const std::string &socketName)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    if (removePermissionFunc_ != nullptr) {
        return removePermissionFunc_(socketName.c_str());
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    removePermissionFunc_ = (DBinderRemovePermissionFunc)dlsym(soHandle_, "DBinderRemovePermission");
    if (removePermissionFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym DBinderRemovePermission fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }

    return removePermissionFunc_(socketName.c_str());
}

int32_t DBinderSoftbusClient::GetLocalNodeDeviceId(const std::string &pkgName, std::string &devId)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    NodeBasicInfo nodeBasicInfo;
    if (getLocalNodeDeviceInfoFunc_ != nullptr) {
        if (getLocalNodeDeviceInfoFunc_(pkgName.c_str(), &nodeBasicInfo) != 0) {
            ZLOGE(LOG_LABEL, "Get local node device info failed");
            return SOFTBUS_CLIENT_GET_DEVICE_INFO_FAILED;
        }
        devId = nodeBasicInfo.networkId;
        return SOFTBUS_CLIENT_SUCCESS;
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    getLocalNodeDeviceInfoFunc_ = (GetLocalNodeDeviceInfoFunc)dlsym(soHandle_, "GetLocalNodeDeviceInfo");
    if (getLocalNodeDeviceInfoFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym GetLocalNodeDeviceInfo fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }

    if (getLocalNodeDeviceInfoFunc_(pkgName.c_str(), &nodeBasicInfo) != 0) {
        ZLOGE(LOG_LABEL, "Get local node device info failed");
        return SOFTBUS_CLIENT_GET_DEVICE_INFO_FAILED;
    }
    devId = nodeBasicInfo.networkId;
    return SOFTBUS_CLIENT_SUCCESS;
}

int32_t DBinderSoftbusClient::Socket(SocketInfo info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    if (socketFunc_ != nullptr) {
        return socketFunc_(info);
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    socketFunc_ = (SocketFunc)dlsym(soHandle_, "Socket");
    if (socketFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Socket fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }

    return socketFunc_(info);
}

int32_t DBinderSoftbusClient::Listen(
    int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    if (listenFunc_ != nullptr) {
        return listenFunc_(socket, qos, qosCount, listener);
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    listenFunc_ = (ListenFunc)dlsym(soHandle_, "Listen");
    if (listenFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Listen fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }

    return listenFunc_(socket, qos, qosCount, listener);
}

int32_t DBinderSoftbusClient::Bind(
    int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    if (bindFunc_ != nullptr) {
        return bindFunc_(socket, qos, qosCount, listener);
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    bindFunc_ = (BindFunc)dlsym(soHandle_, "Bind");
    if (bindFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Bind fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }

    return bindFunc_(socket, qos, qosCount, listener);
}

int32_t DBinderSoftbusClient::SendBytes(int32_t socket, const void *data, uint32_t len)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    if (sendBytesFunc_ != nullptr) {
        return sendBytesFunc_(socket, data, len);
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    sendBytesFunc_ = (SendBytesFunc)dlsym(soHandle_, "SendBytes");
    if (sendBytesFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym SendBytes fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }
    return sendBytesFunc_(socket, data, len);
}

int32_t DBinderSoftbusClient::SendMessage(int32_t socket, const void *data, uint32_t len)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    if (sendMessageFunc_ != nullptr) {
        return sendMessageFunc_(socket, data, len);
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    sendMessageFunc_ = (SendMessageFunc)dlsym(soHandle_, "SendMessage");
    if (sendMessageFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym SendMessage fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }
    return sendMessageFunc_(socket, data, len);
}

void DBinderSoftbusClient::Shutdown(int32_t socket)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    if (shutdownFunc_ != nullptr) {
        shutdownFunc_(socket);
        return;
    }

    if (!OpenSoftbusClientSo()) {
        return;
    }

    shutdownFunc_ = (ShutdownFunc)dlsym(soHandle_, "Shutdown");
    if (shutdownFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Shutdown fail, err msg:%{public}s", dlerror());
        return;
    }

    shutdownFunc_(socket);
}
} // namespace OHOS

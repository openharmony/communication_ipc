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

namespace {
    constexpr int32_t DLOPNE_FAILED = -1;
    constexpr int32_t DLSYM_FAILED = -2;
    constexpr int32_t INSTANCE_EXIT = -5;
}

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
    dlclose(soHandle_);
    exitFlag_ = true;

    ZLOGI(LOG_LABEL, "destroy");
}

bool DBinderSoftbusClient::OpenSoftbusClientSo()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);  // 单例对象退出时的保护
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);
    if (isLoaded_ && soHandle_ != nullptr) {
        return true;
    }

    soHandle_ = dlopen(SOFTBUS_PATH_NAME, RTLD_NOW | RTLD_NODELETE);
    if (soHandle_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed, err = %{public}s", SOFTBUS_PATH_NAME, dlerror());
        return false;
    }

    isLoaded_ = true;
    ZLOGI(LOG_LABEL, "dlopen %{public}s success", SOFTBUS_PATH_NAME);

    return true;
}

int32_t DBinderSoftbusClient::DBinderGrantPermission(int32_t uid, int32_t pid, const char *socketName)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, INSTANCE_EXIT);
    if (grantPermissionFunc_ != nullptr) {
        return grantPermissionFunc_(uid, pid, socketName);
    }

    if (!OpenSoftbusClientSo()) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed.", SOFTBUS_PATH_NAME);
        return DLOPNE_FAILED;
    }

    grantPermissionFunc_ = (DBinderGrantPermissionFunc)dlsym(soHandle_, "DBinderGrantPermission");
    if (grantPermissionFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym DBinderGrantPermission funcation fail, err = %{public}s", dlerror());
        return DLSYM_FAILED;
    }

    return grantPermissionFunc_(uid, pid, socketName);
}

int32_t DBinderSoftbusClient::GetLocalNodeDeviceInfo(const char *pkgName, NodeBasicInfo *info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, INSTANCE_EXIT);
    if (getLocalNodeDeviceInfoFunc_ != nullptr) {
        return getLocalNodeDeviceInfoFunc_(pkgName, info);
    }

    if (!OpenSoftbusClientSo()) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed.", SOFTBUS_PATH_NAME);
        return DLOPNE_FAILED;
    }

    getLocalNodeDeviceInfoFunc_ = (GetLocalNodeDeviceInfoFunc)dlsym(soHandle_, "GetLocalNodeDeviceInfo");
    if (getLocalNodeDeviceInfoFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym DBinderGrantPermission funcation fail, err = %{public}s", dlerror());
        return DLSYM_FAILED;
    }

    return getLocalNodeDeviceInfoFunc_(pkgName, info);
}

int32_t DBinderSoftbusClient::Socket(SocketInfo info)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, INSTANCE_EXIT);
    if (socketFunc_ != nullptr) {
        return socketFunc_(info);
    }

    if (!OpenSoftbusClientSo()) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed.", SOFTBUS_PATH_NAME);
        return DLOPNE_FAILED;
    }

    socketFunc_ = (SocketFunc)dlsym(soHandle_, "Socket");
    if (socketFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Socket funcation fail, err = %{public}s", dlerror());
        return DLSYM_FAILED;
    }

    return socketFunc_(info);
}

int32_t DBinderSoftbusClient::Listen(
    int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, INSTANCE_EXIT);
    if (listenFunc_ != nullptr) {
        return listenFunc_(socket, qos, qosCount, listener);
    }

    if (!OpenSoftbusClientSo()) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed.", SOFTBUS_PATH_NAME);
        return DLOPNE_FAILED;
    }

    listenFunc_ = (ListenFunc)dlsym(soHandle_, "Listen");
    if (listenFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Listen funcation fail, err = %{public}s", dlerror());
        return DLSYM_FAILED;
    }

    return listenFunc_(socket, qos, qosCount, listener);
}

int32_t DBinderSoftbusClient::Bind(
    int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, INSTANCE_EXIT);
    if (bindFunc_ != nullptr) {
        return bindFunc_(socket, qos, qosCount, listener);
    }

    if (!OpenSoftbusClientSo()) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed.", SOFTBUS_PATH_NAME);
        return DLOPNE_FAILED;
    }

    bindFunc_ = (BindFunc)dlsym(soHandle_, "Bind");
    if (bindFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Bind funcation fail, err = %{public}s", dlerror());
        return DLSYM_FAILED;
    }

    return bindFunc_(socket, qos, qosCount, listener);
}

int32_t DBinderSoftbusClient::SendBytes(int32_t socket, const void *data, uint32_t len)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, INSTANCE_EXIT);
    if (sendBytesFunc_ != nullptr) {
        return sendBytesFunc_(socket, data, len);
    }

    if (!OpenSoftbusClientSo()) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed.", SOFTBUS_PATH_NAME);
        return DLOPNE_FAILED;
    }

    sendBytesFunc_ = (SendBytesFunc)dlsym(soHandle_, "SendBytes");
    if (sendBytesFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Bind funcation fail, err = %{public}s", dlerror());
        return DLSYM_FAILED;
    }

    return sendBytesFunc_(socket, data, len);
}

void DBinderSoftbusClient::Shutdown(int32_t socket)
{
    CHECK_INSTANCE_EXIT(exitFlag_);
    if (shutdownFunc_ != nullptr) {
        shutdownFunc_(socket);
        return;
    }

    if (!OpenSoftbusClientSo()) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed.", SOFTBUS_PATH_NAME);
        return;
    }

    shutdownFunc_ = (ShutdownFunc)dlsym(soHandle_, "Shutdown");
    if (shutdownFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym Shutdown funcation fail, err = %{public}s", dlerror());
        return;
    }

    shutdownFunc_(socket);
    return;
}
} // namespace OHOS
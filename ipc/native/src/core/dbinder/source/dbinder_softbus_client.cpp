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
#include "dbinder_softbus_client_death_recipient.h"
#include "ipc_skeleton.h"
#include "ipc_debug.h"
#include "ipc_types.h"
#include "log_tags.h"

namespace OHOS {

using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_DBINDER_SOFTBUS_CLIENT, "DBinderSoftbusClient" };
static constexpr const char *SOFTBUS_PATH_NAME = "libsoftbus_client.z.so";
std::mutex g_mutex;
OHOS::sptr<OHOS::IRemoteObject> g_serverProxy = nullptr;
OHOS::sptr<OHOS::IRemoteObject> g_oldServerProxy = nullptr;
OHOS::sptr<OHOS::IRemoteObject::DeathRecipient> g_clientDeath = nullptr;
constexpr uint32_t PRINT_INTERVAL = 200;
constexpr int32_t CYCLE_NUMBER_MAX = 100;
constexpr uint32_t WAIT_SERVER_INTERVAL = 50;
uint32_t g_getSystemAbilityId = 2;
uint32_t g_printRequestFailedCount = 0;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";

#define SOFTBUS_SERVER_SA_ID_INNER 4700
DBinderSoftbusClient& DBinderSoftbusClient::GetInstance()
{
    static DBinderSoftbusClient instance;
    return instance;
}

static OHOS::sptr<OHOS::IRemoteObject> GetSystemAbility()
{
    OHOS::MessageParcel data;
    if (!data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN)) {
        ZLOGE(LOG_LABEL, "write interface token failed!");
        return nullptr;
    }

    data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::sptr<OHOS::IRemoteObject> samgr = OHOS::IPCSkeleton::GetContextObject();
    if (samgr == nullptr) {
        ZLOGE(LOG_LABEL, "Get samgr failed!");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        if ((++g_printRequestFailedCount) % PRINT_INTERVAL == 0) {
            ZLOGD(LOG_LABEL, "GetSystemAbility failed!");
        }
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

static int32_t SoftbusServerProxyInit(void)
{
    std::lock_guard<std::mutex> lockGuard(g_mutex);
    if (g_serverProxy == nullptr) {
        g_serverProxy = GetSystemAbility();
        if (g_serverProxy == nullptr) {
            return SOFTBUS_IPC_ERR;
        }

        if (g_serverProxy == g_oldServerProxy) {
            g_serverProxy = nullptr;
            ZLOGE(LOG_LABEL, "g_serverProxy not update");
            return SOFTBUS_IPC_ERR;
        }

        g_clientDeath =
        OHOS::sptr<OHOS::IRemoteObject::DeathRecipient>(new (std::nothrow) OHOS::DbinderSoftbusClientDeathRecipient());
        if (g_clientDeath == nullptr) {
            ZLOGE(LOG_LABEL, "DeathRecipient object nullptr");
            return SOFTBUS_CLIENT_DEATH_RECIPIENT_INVALID;
        }
        if (!g_serverProxy->AddDeathRecipient(g_clientDeath)) {
            ZLOGE(LOG_LABEL, "AddDeathRecipient failed");
            return SOFTBUS_CLIENT_ADD_DEATH_RECIPIENT_FAILED;
        }
    }
    return ERR_NONE;
}

DBinderSoftbusClient::DBinderSoftbusClient()
{
    SoftbusServerProxyInit();
}

DBinderSoftbusClient::~DBinderSoftbusClient()
{
    exitFlag_ = true;
    ZLOGI(LOG_LABEL, "destroy");
}

void DBinderSoftbusClient::SoftbusDeathProcTask()
{
    {
        std::lock_guard<std::mutex> lockGuard(g_mutex);
        g_oldServerProxy = g_serverProxy;
        if (g_serverProxy != nullptr && g_clientDeath != nullptr) {
            g_serverProxy->RemoveDeathRecipient(g_clientDeath);
        }
        g_serverProxy.clear();
    }
    std::lock_guard<std::mutex> lockGuard(permissionMutex_);
    mapSessionRefCount_.clear();

    int32_t cnt = 0;
    for (cnt = 0; cnt < CYCLE_NUMBER_MAX; cnt++) {
        if (SoftbusServerProxyInit() == ERR_NONE) {
            break;
        }
        usleep(WAIT_SERVER_INTERVAL);
    }
    if (cnt == CYCLE_NUMBER_MAX) {
        ZLOGE(LOG_LABEL, "server proxy init reached the maxnum count= %{public}d", cnt);
        return;
    }
}

// LCOV_EXCL_START
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
    ZLOGI(LOG_LABEL, "dlopen %{public}s succ", SOFTBUS_PATH_NAME);

    return true;
}
// LCOV_EXCL_STOP

int32_t DBinderSoftbusClient::DBinderGrantPermission(int32_t uid, int32_t pid, const std::string &socketName)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    std::lock_guard<std::mutex> lockGuard(permissionMutex_);
    if (grantPermissionFunc_ != nullptr) {
        goto DO_GRANT;
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    grantPermissionFunc_ = (DBinderGrantPermissionFunc)dlsym(soHandle_, "DBinderGrantPermission");
    if (grantPermissionFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym DBinderGrantPermission fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }
    goto DO_GRANT;

DO_GRANT:
    auto it = mapSessionRefCount_.find(socketName);
    if (it != mapSessionRefCount_.end()) {
        it->second++;
        ZLOGI(LOG_LABEL, "had permission socName:%{public}s refCount:%{public}d", socketName.c_str(), it->second);
        return grantPermissionFunc_(uid, pid, socketName.c_str());
    }
    mapSessionRefCount_.insert(std::pair<std::string, int32_t>(socketName, 1));
    ZLOGI(LOG_LABEL, "refCount +1  socketName:%{public}s", socketName.c_str());
    return grantPermissionFunc_(uid, pid, socketName.c_str());
}

int32_t DBinderSoftbusClient::DBinderRemovePermission(const std::string &socketName)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    std::lock_guard<std::mutex> lockGuard(permissionMutex_);
    if (removePermissionFunc_ != nullptr) {
        goto DO_REMOVE;
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    removePermissionFunc_ = (DBinderRemovePermissionFunc)dlsym(soHandle_, "DBinderRemovePermission");
    if (removePermissionFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym DBinderRemovePermission fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }

    goto DO_REMOVE;

DO_REMOVE:
    auto it = mapSessionRefCount_.find(socketName);
    if (it != mapSessionRefCount_.end()) {
        it->second--;
        if (it->second <= 0) {
            mapSessionRefCount_.erase(socketName);
            return removePermissionFunc_(socketName.c_str());
        }
        ZLOGI(LOG_LABEL, "need permission socketName:%{public}s refCount:%{public}d", socketName.c_str(), it->second);
        return ERR_NONE;
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

int32_t DBinderSoftbusClient::GetAllNodeDeviceId(const std::string &pkgName, std::vector<std::string> &devIds)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, SOFTBUS_CLIENT_INSTANCE_EXIT);
    int32_t devNum = 0;
    NodeBasicInfo *nodeBasicInfo = nullptr;
    if (getAllNodeDeviceInfoFunc_ != nullptr) {
        if (getAllNodeDeviceInfoFunc_(pkgName.c_str(), &nodeBasicInfo, &devNum) != 0) {
            ZLOGE(LOG_LABEL, "Get local node device info failed");
            return SOFTBUS_CLIENT_GET_DEVICE_INFO_FAILED;
        }
        if (nodeBasicInfo == nullptr) {
            ZLOGI(LOG_LABEL, "nodeBasicInfo is nullptr, devNum:%{public}d", devNum);
            return SOFTBUS_CLIENT_SUCCESS;
        }
        for (int32_t i = 0; i < devNum; ++i) {
            devIds.push_back(nodeBasicInfo[i].networkId);
        }
        if (freeNodeInfoFunc_ != nullptr) {
            freeNodeInfoFunc_(nodeBasicInfo);
        }
        return SOFTBUS_CLIENT_SUCCESS;
    }

    if (!OpenSoftbusClientSo()) {
        return SOFTBUS_CLIENT_DLOPEN_FAILED;
    }

    getAllNodeDeviceInfoFunc_ = (GetAllNodeDeviceInfoFunc)dlsym(soHandle_, "GetAllNodeDeviceInfo");
    if (getAllNodeDeviceInfoFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym GetAllNodeDeviceInfo fail, err msg:%{public}s", dlerror());
        return SOFTBUS_CLIENT_DLSYM_FAILED;
    }
    freeNodeInfoFunc_ = (FreeNodeInfoFunc)dlsym(soHandle_, "FreeNodeInfo");
    if (freeNodeInfoFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym FreeNodeInfo fail, err msg:%{public}s", dlerror());
    }

    if (getAllNodeDeviceInfoFunc_(pkgName.c_str(), &nodeBasicInfo, &devNum) != 0) {
        ZLOGE(LOG_LABEL, "Get local node device info failed");
        return SOFTBUS_CLIENT_GET_DEVICE_INFO_FAILED;
    }
    if (nodeBasicInfo == nullptr) {
        ZLOGI(LOG_LABEL, "nodeBasicInfo is nullptr, devNum:%{public}d", devNum);
        return SOFTBUS_CLIENT_SUCCESS;
    }
    for (int32_t i = 0; i < devNum; ++i) {
        devIds.push_back(nodeBasicInfo[i].networkId);
    }
    if (freeNodeInfoFunc_ != nullptr) {
        freeNodeInfoFunc_(nodeBasicInfo);
    }
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

int32_t DBinderSoftbusClient::Listen(int32_t socket, const QosTV qos[], uint32_t qosCount,
    const ISocketListener *listener)
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

int32_t DBinderSoftbusClient::Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
    const ISocketListener *listener)
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

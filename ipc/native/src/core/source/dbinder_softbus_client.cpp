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

#include <cerrno>
#include <dlfcn.h>

#include "check_instance_exit.h"
#include "ipc_debug.h"
#include "ipc_process_skeleton.h"
#include "log_tags.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_DBINDER_SOFTBUS_CLIENT,
    "DBinderSoftbusClient" };
#ifdef __aarch64__
static constexpr const char *SOFTBUS_ADAPTOR_PATH = "/system/lib64/platformsdk/";
#else
static constexpr const char *SOFTBUS_ADAPTOR_PATH = "/system/lib/platformsdk/";
#endif
static constexpr const char *SOFTBUS_ADAPTOR_NAME = "libdbinder_softbus_adaptor.z.so";

DBinderSoftbusClient &DBinderSoftbusClient::GetInstance()
{
    static DBinderSoftbusClient instance;
    return instance;
}

DBinderSoftbusClient::DBinderSoftbusClient() : exitFlag_(false), isLoaded_(false), soHandle_(nullptr)
{
}

DBinderSoftbusClient::~DBinderSoftbusClient()
{
    exitFlag_ = true;
    ZLOGI(LOG_LABEL, "destroy");
}

bool DBinderSoftbusClient::LoadSoftbusAdaptor()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, false);
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);
    if (isLoaded_ && soHandle_ != nullptr) {
        return true;
    }

    std::string path = std::string(SOFTBUS_ADAPTOR_PATH) + std::string(SOFTBUS_ADAPTOR_NAME);
    soHandle_ = dlopen(path.c_str(), RTLD_NOW | RTLD_NODELETE);
    if (soHandle_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlopen %{public}s failed, err:%{public}s", path.c_str(), dlerror());
        return false;
    }
    isLoaded_ = true;
    ZLOGI(LOG_LABEL, "dlopen %{public}s success", SOFTBUS_ADAPTOR_NAME);
    return true;
}

std::shared_ptr<ISessionService> DBinderSoftbusClient::GetSessionService()
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, nullptr);
    if (sessionManager_ != nullptr) {
        return sessionManager_;
    }
    if (sessionServiceFunc_ != nullptr) {
        sessionManager_ = sessionServiceFunc_();
        return sessionManager_;
    }
    if (!LoadSoftbusAdaptor()) {
        return nullptr;
    }

    sessionServiceFunc_ = (GetSessionServiceFunc)dlsym(soHandle_, "GetSessionService");
    if (sessionServiceFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "GetSessionServiceFunc fail, err:%{public}s", dlerror());
        return nullptr;
    }

    sessionManager_ = sessionServiceFunc_();
    if (sessionManager_ == nullptr) {
        ZLOGE(LOG_LABEL, "GetSessionService fail");
        return nullptr;
    }
    ZLOGD(LOG_LABEL, "success");
    return sessionManager_;
}

std::string DBinderSoftbusClient::GetLocalDeviceId(const std::string &pkgName)
{
    CHECK_INSTANCE_EXIT_WITH_RETVAL(exitFlag_, "");
    if (localDeviceIdFunc_ != nullptr) {
        return localDeviceIdFunc_(pkgName.c_str());
    }
    if (!LoadSoftbusAdaptor()) {
        ZLOGE(LOG_LABEL, "LoadSoftbusAdaptor fail");
        return "";
    }

    localDeviceIdFunc_ = (GetLocalDeviceIdFunc)dlsym(soHandle_, "GetLocalDeviceId");
    if (localDeviceIdFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "GetLocalDeviceIdFunc fail, err:%{public}s", dlerror());
        return "";
    }

    std::string deviceId = localDeviceIdFunc_(pkgName.c_str());
    if (deviceId.empty()) {
        ZLOGE(LOG_LABEL, "failed, deviceId is empty");
        return "";
    }
    ZLOGD(LOG_LABEL, "GetLocalDeviceId succ, deviceId:%{public}s",
        IPCProcessSkeleton::ConvertToSecureString(deviceId).c_str());
    return deviceId;
}
} // namespace OHOS
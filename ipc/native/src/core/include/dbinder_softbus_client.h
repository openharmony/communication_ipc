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

#include <memory>
#include <mutex>
#include <string>

#include "ISessionService.h"
#include "nocopyable.h"

using Communication::SoftBus::ISessionService;

namespace OHOS {
class DBinderSoftbusClient {
public:
    static DBinderSoftbusClient &GetInstance();
    std::shared_ptr<ISessionService> GetSessionService();
    std::string GetLocalDeviceId(const std::string &pkgName);

private:
    DISALLOW_COPY_AND_MOVE(DBinderSoftbusClient);
    DBinderSoftbusClient();
    ~DBinderSoftbusClient();

    bool LoadSoftbusAdaptor();
private:
    using GetSessionServiceFunc = std::shared_ptr<ISessionService>(*)();
    using GetLocalDeviceIdFunc = std::string(*)(const char*);
    GetSessionServiceFunc sessionServiceFunc_ = nullptr;
    GetLocalDeviceIdFunc localDeviceIdFunc_ = nullptr;
    std::atomic<bool> exitFlag_;
    std::mutex loadSoMutex_;
    std::shared_ptr<ISessionService> sessionManager_;
    bool isLoaded_;
    void *soHandle_;
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_SOFTBUS_CLIENT_H
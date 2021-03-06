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

#include "dbinder_death_recipient.h"
#include "dbinder_service.h"
#include "dbinder_log.h"
#include "ISessionService.h"
#include "log_tags.h"

namespace OHOS {
using Communication::SoftBus::ISessionService;

#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "DbinderDeathRecipient" };
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

void DbinderDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    DBINDER_LOGE("DbinderDeathRecipient OnRemoteDied");
    if (remote == nullptr) {
        DBINDER_LOGE("remote object is null");
        return;
    }

    sptr<IRemoteObject> object = remote.promote();
    IPCObjectProxy *callbackProxy = reinterpret_cast<IPCObjectProxy *>(object.GetRefPtr());

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    if (dBinderService == nullptr) {
        DBINDER_LOGE("dBinderService is null");
        return;
    }

    std::shared_ptr<ISessionService> softbusManager = ISessionService::GetInstance();
    if (softbusManager == nullptr) {
        DBINDER_LOGE("fail to get softbus service");
        return;
    }
    std::string sessionName = dBinderService->QueryBusNameObject(callbackProxy);
    if (sessionName.empty()) {
        DBINDER_LOGE("proxy sessionName not found");
        return;
    }
    softbusManager->RemovePermission(sessionName);

    sptr<IRemoteObject::DeathRecipient> death = dBinderService->QueryDeathRecipient(object);
    if (death != nullptr) {
        // Continue to clear subsequent data
        callbackProxy->RemoveDeathRecipient(death);
    }

    if (!dBinderService->DetachDeathRecipient(object)) {
        DBINDER_LOGE("detaching death recipient is failed");
        return;
    }

    if (!dBinderService->DetachCallbackProxy(object)) {
        DBINDER_LOGE("detaching callback proxy is failed");
        return;
    }
}
} // namespace OHOS

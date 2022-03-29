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

#ifndef OHOS_IPC_DBINDER_DATABUS_SESSION_CALLBACK_H
#define OHOS_IPC_DBINDER_DATABUS_SESSION_CALLBACK_H

#include "ISessionListener.h"

using Communication::SoftBus::ISessionListener;
using Communication::SoftBus::Session;

namespace OHOS {
static const std::string DBINDER_SERVER_PKG_NAME = "DBinderBus";

class DatabusSessionCallback : public ISessionListener {
public:
    explicit DatabusSessionCallback() = default;
    ~DatabusSessionCallback() = default;

    int OnSessionOpened(std::shared_ptr<Session> session) override;
    void OnSessionClosed(std::shared_ptr<Session> session) override;
    void OnMessageReceived(std::shared_ptr<Session> session, const char* data, ssize_t len) override {}
    void OnBytesReceived(std::shared_ptr<Session> session, const char *data, ssize_t len) override;
    bool OnDataAvailable(std::shared_ptr<Session> session, uint32_t status) override
    {
        return true;
    };
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_DATABUS_SESSION_CALLBACK_H

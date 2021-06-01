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

#ifndef OHOS_IPC_DBINDER_REMOTE_LISTENER_H
#define OHOS_IPC_DBINDER_REMOTE_LISTENER_H

#include <string>
#include <map>
#include <mutex>

#include "dbinder_service.h"
#include "ISessionService.h"
#include "Session.h"
#include "ISessionListener.h"

using Communication::SoftBus::ISessionListener;
using Communication::SoftBus::ISessionService;
using Communication::SoftBus::Session;

namespace OHOS {
class DBinderRemoteListener : public ISessionListener {
public:
    DBinderRemoteListener(const sptr<DBinderService> &dBinderService);
    ~DBinderRemoteListener();
    int OnSessionOpened(std::shared_ptr<Session> session) override;
    void OnSessionClosed(std::shared_ptr<Session> session) override;
    void OnMessageReceived(std::shared_ptr<Session> session, const char *data, ssize_t len) override {};
    void OnBytesReceived(std::shared_ptr<Session> session, const char *data, ssize_t len) override;
    bool OnDataAvailable(std::shared_ptr<Session> session, uint32_t status) override
    {
        return true;
    };

    bool SendDataToRemote(const std::string &deviceId, const struct DHandleEntryTxRx *msg);
    bool StartListener();
    bool StopListener();
    bool CloseDatabusSession(const std::string &deviceId);

private:
    std::shared_ptr<Session> OpenSoftbusSession(const std::string &deviceId);

    const std::string OWN_SESSION_NAME = "DBinderService";
    const std::string PEER_SESSION_NAME = "DBinderService";
    static constexpr int PACKET_SIZE = 64 * 1024;
    static constexpr int SEND_MSG_TIMEOUT_MS = 200;

    DISALLOW_COPY_AND_MOVE(DBinderRemoteListener);
    std::mutex busManagerMutex_;
    std::shared_ptr<ISessionService> softbusManager_;
    sptr<DBinderService> dBinderService_;
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_REMOTE_LISTENER_H

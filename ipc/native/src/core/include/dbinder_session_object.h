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

#ifndef OHOS_IPC_DBINDER_SESSION_OBJECT_H
#define OHOS_IPC_DBINDER_SESSION_OBJECT_H

#include <string>
#include <mutex>
#include "nocopyable.h"
#include "buffer_object.h"

#include "Session.h"
#include "ISessionService.h"

using Communication::SoftBus::ISessionService;
using Communication::SoftBus::Session;

namespace OHOS {
constexpr int DEVICEID_LENGTH = 64;
constexpr int SERVICENAME_LENGTH = 200;

/* struct FlatDBinderSession is for flat DatabusSessionObject to transfer to another device */
struct FlatDBinderSession {
    uint64_t stubIndex;
    uint16_t deviceIdLength;
    uint16_t serviceNameLength;
    char deviceId[DEVICEID_LENGTH + 1];
    char serviceName[SERVICENAME_LENGTH + 1];
};

class DBinderSessionObject {
public:
    static uint32_t GetFlatSessionLen();
    explicit DBinderSessionObject(std::shared_ptr<Session> session, const std::string &serviceName,
        const std::string &serverDeviceId);

    ~DBinderSessionObject();

    void SetBusSession(std::shared_ptr<Session> session);
    void SetServiceName(const std::string &serviceName);
    void SetDeviceId(const std::string &serverDeviceId);
    std::shared_ptr<BufferObject> GetSessionBuff();
    std::shared_ptr<Session> GetBusSession() const;
    std::string GetServiceName() const;
    std::string GetDeviceId() const;
    uint32_t GetSessionHandle() const;

private:
    DISALLOW_COPY_AND_MOVE(DBinderSessionObject);
    /* Session is defined from softBus session, when import socket driver, we need use interface abstraction */
    std::shared_ptr<Session> session_;
    std::mutex buffMutex_;
    std::shared_ptr<BufferObject> buff_;
    std::string serviceName_;
    std::string serverDeviceId_;
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_SESSION_OBJECT_H
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
#include "databus_socket_listener.h"
#include "ipc_object_proxy.h"

namespace OHOS {
constexpr int DEVICEID_LENGTH = 64;
constexpr int NOT_SUPPORT_TOKENID_SERVICENAME_LENGTH = 200;
constexpr int SUPPORT_TOKENID_SERVICENAME_LENGTH = 64;
constexpr int RESERVED_FROM_SERVICENAME_LENGTH = 125;

/* struct FlatDBinderSession is for flat DatabusSessionObject to transfer to another device */
struct FlatDBinderSession {
    uint64_t stubIndex;
    uint16_t deviceIdLength;
    uint16_t serviceNameLength;
    char deviceId[DEVICEID_LENGTH + 1];
    char serviceName[SUPPORT_TOKENID_SERVICENAME_LENGTH + 1];
    uint16_t version; // for alignment
    uint32_t magic;
    uint32_t tokenId;
    char reserved[RESERVED_FROM_SERVICENAME_LENGTH];
    // if not support tokenid, this is end of serviceName, which is '\0', this position equal to
    // NOT_SUPPORT_TOKENID_SERVICENAME_LENGTH = 200 + 1
    char canNotUse;
};

class DBinderSessionObject {
public:
    static uint32_t GetFlatSessionLen();
    explicit DBinderSessionObject(const std::string &serviceName, const std::string &serverDeviceId,
        uint64_t stubIndex, IPCObjectProxy *proxy, uint32_t tokenId);
    ~DBinderSessionObject();

    void SetServiceName(const std::string &serviceName);
    void SetDeviceId(const std::string &serverDeviceId);
    void SetProxy(IPCObjectProxy *proxy);
    std::shared_ptr<BufferObject> GetSessionBuff();
    std::string GetServiceName() const;
    std::string GetDeviceId() const;
    IPCObjectProxy *GetProxy() const;
    uint64_t GetStubIndex() const;

    void CloseDatabusSession();
    uint32_t GetTokenId() const;
    int32_t GetSocketId() const;
    void SetSocketId(int32_t socketId);
    void SetPeerPid(int peerPid);
    void SetPeerUid(int peerUid);
    int GetPeerPid() const;
    int GetPeerUid() const;

private:
    DISALLOW_COPY_AND_MOVE(DBinderSessionObject);

    int32_t socket_ = SOCKET_ID_INVALID;
    std::mutex buffMutex_;
    std::shared_ptr<BufferObject> buff_;
    std::string serviceName_;
    std::string serverDeviceId_;
    uint64_t stubIndex_;
    IPCObjectProxy *proxy_;
    uint32_t tokenId_;
    int pid_;
    int uid_;
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_SESSION_OBJECT_H

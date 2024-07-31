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

#include "dbinder_session_object.h"

#include "ipc_process_skeleton.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_SESSION_OBJ, "dbinder_session_object" };

DBinderSessionObject::DBinderSessionObject(const std::string &serviceName,
    const std::string &serverDeviceId, uint64_t stubIndex, IPCObjectProxy *proxy, uint32_t tokenId)
    :serviceName_(serviceName), serverDeviceId_(serverDeviceId),
    stubIndex_(stubIndex), proxy_(proxy), tokenId_(tokenId), pid_(0), uid_(0)
{}

DBinderSessionObject::~DBinderSessionObject()
{
    buff_ = nullptr;
}

void DBinderSessionObject::CloseDatabusSession()
{
    std::shared_ptr<DatabusSocketListener> listener =
        DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        ZLOGE(LOG_LABEL, "fail to get socket listener");
        return;
    }
    ZLOGI(LOG_LABEL, "Shutdown, deviceId:%{public}s socketId:%{public}d",
        IPCProcessSkeleton::ConvertToSecureString(GetDeviceId()).c_str(), socket_);
    listener->ShutdownSocket(socket_);
    socket_ = SOCKET_ID_INVALID;
}

std::shared_ptr<BufferObject> DBinderSessionObject::GetSessionBuff()
{
    if (buff_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(buffMutex_);
        if (buff_ == nullptr) {
            std::shared_ptr<BufferObject> temp = std::make_shared<BufferObject>();
            buff_ = temp;
        }
    }

    return buff_;
}

void DBinderSessionObject::SetServiceName(const std::string &serviceName)
{
    serviceName_ = serviceName;
}

std::string DBinderSessionObject::GetServiceName() const
{
    return serviceName_;
}

void DBinderSessionObject::SetDeviceId(const std::string &serverDeviceId)
{
    serverDeviceId_ = serverDeviceId;
}

std::string DBinderSessionObject::GetDeviceId() const
{
    return serverDeviceId_;
}

void DBinderSessionObject::SetProxy(IPCObjectProxy *proxy)
{
    proxy_ = proxy;
}

IPCObjectProxy *DBinderSessionObject::GetProxy() const
{
    return proxy_;
}

uint64_t DBinderSessionObject::GetStubIndex() const
{
    return stubIndex_;
}

uint32_t DBinderSessionObject::GetFlatSessionLen()
{
    auto length = sizeof(struct FlatDBinderSession);
    ZLOGD(LOG_LABEL, "FlatDBinderSession size:%{public}zu", length);
    return length;
}

int32_t DBinderSessionObject::GetSocketId() const
{
    return socket_;
}

void DBinderSessionObject::SetSocketId(int32_t socketId)
{
    socket_ = socketId;
}

uint32_t DBinderSessionObject::GetTokenId() const
{
    return tokenId_;
}

void DBinderSessionObject::SetPeerPid(int peerPid)
{
    pid_ = peerPid;
}

void DBinderSessionObject::SetPeerUid(int peerUid)
{
    uid_ = peerUid;
}

int DBinderSessionObject::GetPeerPid() const
{
    return pid_;
}

int DBinderSessionObject::GetPeerUid() const
{
    return uid_;
}
} // namespace OHOS

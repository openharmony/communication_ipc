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
#include "ISessionService.h"

namespace OHOS {
DBinderSessionObject::DBinderSessionObject(std::shared_ptr<Session> session, const std::string &serviceName,
    const std::string &serverDeviceId)
    : session_(session), serviceName_(serviceName), serverDeviceId_(serverDeviceId)
{}

DBinderSessionObject::~DBinderSessionObject()
{
    if (session_ != nullptr) {
        std::shared_ptr<ISessionService> manager = ISessionService::GetInstance();
        if (manager != nullptr) {
            (void)manager->CloseSession(session_);
        }
    }

    session_ = nullptr;
    buff_ = nullptr;
}

void DBinderSessionObject::SetBusSession(std::shared_ptr<Session> session)
{
    session_ = session;
}

std::shared_ptr<Session> DBinderSessionObject::GetBusSession() const
{
    return session_;
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

uint32_t DBinderSessionObject::GetFlatSessionLen()
{
    return sizeof(struct FlatDBinderSession);
}

uint32_t DBinderSessionObject::GetSessionHandle() const
{
    if (session_ != nullptr) {
        return IPCProcessSkeleton::ConvertChannelID2Int(session_->GetChannelId());
    }
    return 0;
}
} // namespace OHOS

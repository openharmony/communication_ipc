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

#include "comm_auth_info.h"

namespace OHOS {
CommAuthInfo::CommAuthInfo(IRemoteObject *stub, int pid, int uid, uint32_t tokenId,
    const std::string &deviceId, int32_t socketId)
    : stub_(stub), remotePid_(pid), remoteUid_(uid),
      tokenId_(tokenId), deviceId_(deviceId), socketId_(socketId)
{}

CommAuthInfo::~CommAuthInfo()
{
    stub_ = nullptr;
}

IRemoteObject *CommAuthInfo::GetStubObject() const
{
    return stub_;
}

int CommAuthInfo::GetRemotePid() const
{
    return remotePid_;
}

int CommAuthInfo::GetRemoteUid() const
{
    return remoteUid_;
}

uint32_t CommAuthInfo::GetRemoteTokenId() const
{
    return tokenId_;
}

std::string CommAuthInfo::GetRemoteDeviceId() const
{
    return deviceId_;
}

int32_t CommAuthInfo::GetRemoteSocketId() const
{
    return socketId_;
}

void CommAuthInfo::SetRemoteSocketId(int32_t socketId)
{
    socketId_ = socketId;
}
} // namespace OHOS

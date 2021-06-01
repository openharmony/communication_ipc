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

#ifndef OHOS_IPC_COMMAUTHINFO_H
#define OHOS_IPC_COMMAUTHINFO_H

#include "iremote_object.h"
#include "ipc_object_stub.h"

namespace OHOS {
class CommAuthInfo {
public:
    CommAuthInfo(IRemoteObject *stub, int pid, int uid, const std::string &deviceId);
    virtual ~CommAuthInfo();
    const IRemoteObject *GetStubObject() const;
    int GetRemotePid() const;
    int GetRemoteUid() const;
    std::string GetRemoteDeviceId() const;

private:
    IRemoteObject *stub_;
    int remotePid_;
    int remoteUid_;
    std::string deviceId_;
};
} // namespace OHOS
#endif // OHOS_IPC_COMMAUTHINFO_H
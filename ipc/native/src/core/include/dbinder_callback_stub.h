/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_IPC_DBINDER_CALLBACK_STUB_H
#define OHOS_IPC_DBINDER_CALLBACK_STUB_H

#include <string>
#include "ipc_object_stub.h"

namespace OHOS {
class DBinderCallbackStub : public IPCObjectStub {
public:
    explicit DBinderCallbackStub(const std::string &serviceName, const std::string &peerDeviceID,
        const std::string &localDeviceID, uint64_t stubIndex, uint32_t handle, uint32_t tokenId);
    ~DBinderCallbackStub();
    static bool Marshalling(Parcel &parcel, const sptr<IRemoteObject> &object);
    bool Marshalling(Parcel &parcel) const override;
    int GetAndSaveDBinderData(pid_t pid, uid_t uid) override;
    int32_t ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    const std::string &GetServiceName();
    const std::string &GetDeviceID();
    uint64_t GetStubIndex() const;
    uint32_t GetTokenId() const;

private:
    int32_t ProcessData(int uid, int pid, const std::string &sessionName, MessageParcel &data, MessageParcel &reply);
    int AddDBinderCommAuth(pid_t pid, uid_t uid, const std::string &sessionName);
    int SaveDBinderData(const std::string &sessionName);
    const std::string serviceName_;
    const std::string deviceID_;
    const std::string localDeviceID_;
    uint64_t stubIndex_;
    uint32_t handle_;
    uint32_t tokenId_;
    std::unique_ptr<uint8_t[]> dbinderData_ {nullptr};
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_CALLBACK_STUB_H
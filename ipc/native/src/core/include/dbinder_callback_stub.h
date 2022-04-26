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
#include "rpc_feature_set.h"

namespace OHOS {
class DBinderCallbackStub : public IPCObjectStub {
public:
    explicit DBinderCallbackStub(const std::string &serviceName, const std::string &peerDeviceID,
        const std::string &localDeviceID, uint64_t stubIndex, uint32_t handle,
        std::shared_ptr<FeatureSetData> feature);
    ~DBinderCallbackStub();
    int32_t ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    const std::string &GetServiceName();
    const std::string &GetDeviceID();
    uint64_t GetStubIndex() const;
    std::shared_ptr<FeatureSetData> GetFeatureSet() const;

private:
    uint32_t ConstructAuthData(MessageParcel &authData, uint32_t featureSet);

private:
    const std::string serviceName_;
    const std::string deviceID_;
    const std::string localDeviceID_;
    uint64_t stubIndex_;
    uint32_t handle_;
    std::shared_ptr<FeatureSetData> rpcFeatureSet_;
};
} // namespace OHOS
#endif // OHOS_IPC_DBINDER_CALLBACK_STUB_H
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

#ifndef OHOS_IPC_SERVICES_DBINDER_DBINDER_STUB_H
#define OHOS_IPC_SERVICES_DBINDER_DBINDER_STUB_H

#include <string>
#include <parcel.h>
#include "ipc_object_stub.h"

namespace OHOS {
#ifdef BINDER_IPC_32BIT
typedef unsigned int binder_uintptr_t;
#else
typedef unsigned long long binder_uintptr_t;
#endif

class DBinderServiceStub : public IPCObjectStub {
public:
    explicit DBinderServiceStub(const std::string& serviceName, const std::string& deviceID,
        binder_uintptr_t binderObject);
    ~DBinderServiceStub();
    int32_t ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    const std::string& GetServiceName();
    const std::string& GetDeviceID();
    binder_uintptr_t GetBinderObject() const;

private:
    const std::string serviceName_;
    const std::string deviceID_;
    binder_uintptr_t binderObject_;
    int32_t ProcessDeathRecipient(MessageParcel &data, MessageParcel &reply);
    int32_t AddDbinderDeathRecipient(MessageParcel &data, MessageParcel &reply);
    int32_t RemoveDbinderDeathRecipient(MessageParcel &data, MessageParcel &reply);
};
} // namespace OHOS
#endif // OHOS_IPC_SERVICES_DBINDER_DBINDER_STUB_H

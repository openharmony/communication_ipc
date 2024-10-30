/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_DEATH_RECIPIENT_H
#define OHOS_MOCK_DEATH_RECIPIENT_H

#include <string>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ipc_object_proxy.h"

namespace OHOS {
class MockDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    MockDeathRecipient() = default;
    ~MockDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object)
    {
        (void)object;
    }
};

class MockIPCObjectProxy : public IPCObjectProxy {
public:
    MockIPCObjectProxy() : IPCObjectProxy(1, u"mockProxyService") {};
    ~MockIPCObjectProxy() {};

    MOCK_METHOD0(GetObjectRefCount, int32_t());
    MOCK_METHOD0(GetSessionName, std::string());
    MOCK_METHOD0(GetInterfaceDescriptor, std::u16string());
    MOCK_METHOD1(AddDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD1(RemoveDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD2(Dump, int(int fd, const std::vector<std::u16string> &args));
    MOCK_METHOD2(InvokeListenThread, int(MessageParcel &data, MessageParcel &reply));
    MOCK_METHOD4(SendRequest, int(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));

    MOCK_CONST_METHOD0(GetProto, int());
    MOCK_CONST_METHOD0(IsProxyObject, bool());
    MOCK_CONST_METHOD0(IsObjectDead, bool());
    MOCK_CONST_METHOD0(CheckObjectLegality, bool());
    MOCK_CONST_METHOD0(GetObjectDescriptor, std::u16string());
    MOCK_CONST_METHOD1(Marshalling, bool(Parcel &parcel));
};
} // namespace OHOS
#endif // OHOS_MOCK_DEATH_RECIPIENT_H

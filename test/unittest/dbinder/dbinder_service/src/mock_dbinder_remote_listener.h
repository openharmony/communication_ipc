/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_DBINDER_REMOTE_LISTENER_H
#define OHOS_MOCK_DBINDER_REMOTE_LISTENER_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "dbinder_remote_listener.h"
#include "ipc_object_proxy.h"

namespace OHOS {
class MockDBinderRemoteListener : public DBinderRemoteListener {
public:
    MockDBinderRemoteListener();
    ~MockDBinderRemoteListener();
    static MockDBinderRemoteListener& GetInstance();
    void SetResult(int32_t result);
    int32_t GetResult();
    static int32_t SendBytes(int32_t socket, const void *data, uint32_t len);
private:
    int32_t result_;
};

class MockIPCObjectProxy : public IPCObjectProxy {
public:
    MockIPCObjectProxy() : IPCObjectProxy(1, u"mockProxyService") {};
    ~MockIPCObjectProxy() {};

#ifdef OHOS_PLATFORM
    MOCK_METHOD0(CanPromote, bool());
#endif
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

MockDBinderRemoteListener::MockDBinderRemoteListener() : DBinderRemoteListener()
{
}

MockDBinderRemoteListener::~MockDBinderRemoteListener()
{
}

void MockDBinderRemoteListener::SetResult(int32_t result)
{
    result_ = result;
}

int32_t MockDBinderRemoteListener::GetResult()
{
    return result_;
}

MockDBinderRemoteListener& MockDBinderRemoteListener::GetInstance()
{
    static MockDBinderRemoteListener instance;
    return instance;
}

int32_t MockDBinderRemoteListener::SendBytes(int32_t socket, const void *data, uint32_t len)
{
    (void)socket;
    (void)len;
    auto msg = reinterpret_cast<const struct DHandleEntryTxRx *>(data);
    MockDBinderRemoteListener::GetInstance().SetResult(msg->transType);
    return 0;
}

} // namespace OHOS
#endif // OHOS_MOCK_DBINDER_REMOTE_LISTENER_H
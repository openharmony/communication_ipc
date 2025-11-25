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

#include "dbinderdatabusinvokermock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterface() {};
    virtual ~DBinderDataBusInvokerInterface() {};

    virtual IPCProcessSkeleton *GetCurrent() = 0;
    virtual sptr<IRemoteObject> FindOrNewObject(int handle, const dbinder_negotiation_data *dbinderData) = 0;
    virtual std::string GetSessionName() = 0;
    virtual int InvokeListenThread(MessageParcel &data, MessageParcel &reply) = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
};

class DBinderDataBusInvokerInterfaceMock : public DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterfaceMock();
    ~DBinderDataBusInvokerInterfaceMock() override;

    MOCK_METHOD(IPCProcessSkeleton *, GetCurrent, (), (override));
    MOCK_METHOD(sptr<IRemoteObject>, FindOrNewObject, (int handle, const dbinder_negotiation_data *dbinderData),
        (override));
    MOCK_METHOD(std::string, GetSessionName, (), (override));
    MOCK_METHOD(int, InvokeListenThread, (MessageParcel &data, MessageParcel &reply), (override));
    MOCK_METHOD(bool, WriteUint32, (uint32_t value), (override));
};

static void *g_interface = nullptr;

DBinderDataBusInvokerInterfaceMock::DBinderDataBusInvokerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DBinderDataBusInvokerInterfaceMock::~DBinderDataBusInvokerInterfaceMock()
{
    g_interface = nullptr;
}

static DBinderDataBusInvokerInterfaceMock *GetDBinderDataBusInvokerInterfaceMock()
{
    return reinterpret_cast<DBinderDataBusInvokerInterfaceMock *>(g_interface);
}

extern "C" {
IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetDBinderDataBusInvokerInterfaceMock()->GetCurrent();
}

sptr<IRemoteObject> IPCProcessSkeleton::FindOrNewObject(int handle, const dbinder_negotiation_data *dbinderData)
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetDBinderDataBusInvokerInterfaceMock()->FindOrNewObject(handle, dbinderData);
}

std::string IPCObjectProxy::GetSessionName()
{
    if (g_interface == nullptr) {
        return "SessionName";
    }
    return GetDBinderDataBusInvokerInterfaceMock()->GetSessionName();
}

int IPCObjectProxy::InvokeListenThread(MessageParcel &data, MessageParcel &reply)
{
    if (g_interface == nullptr) {
        return 0;
    }
    return GetDBinderDataBusInvokerInterfaceMock()->InvokeListenThread(data, reply);
}

bool Parcel::WriteUint32(uint32_t value)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetDBinderDataBusInvokerInterfaceMock()->WriteUint32(value);
}
}

void NewSessionOfBinderProxyFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    invoker.NewSessionOfBinderProxy(handle, session);

    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr) {
        return;
    }
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    std::u16string descriptor = std::u16string();
    sptr<IPCObjectProxy> ipcProxy = sptr<IPCObjectProxy>::MakeSptr(handle, descriptor);
    if (ipcProxy == nullptr) {
        return;
    }
    EXPECT_CALL(mock, FindOrNewObject(handle, _)).WillRepeatedly(Return(ipcProxy));
    invoker.NewSessionOfBinderProxy(handle, session);

    ipcProxy->SetProto(IRemoteObject::IF_PROT_BINDER);
    invoker.NewSessionOfBinderProxy(handle, session);
    delete current;
}

void GetSessionForProxyFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> ipcProxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (ipcProxy == nullptr || session == nullptr) {
        return;
    }
    const std::string localDeviceID = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    const std::string sessionName = "SessionName";
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetSessionName()).WillRepeatedly(Return(sessionName));
    EXPECT_CALL(mock, WriteUint32(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, InvokeListenThread(_, _)).WillRepeatedly([&](MessageParcel &data, MessageParcel &reply) {
        reply.WriteUint64(1);
        return ERR_NONE;
    });
    DBinderDatabusInvoker invoker;
    invoker.GetSessionForProxy(ipcProxy, session, localDeviceID);
}

void GetSessionForProxyFuzzTest002(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> ipcProxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (ipcProxy == nullptr || session == nullptr) {
        return;
    }
    const std::string localDeviceID = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    const std::string sessionName = "SessionName";
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetSessionName()).WillRepeatedly(Return(sessionName));
    EXPECT_CALL(mock, WriteUint32(_)).WillOnce(Return(false));
    DBinderDatabusInvoker invoker;
    invoker.GetSessionForProxy(ipcProxy, session, localDeviceID);

    EXPECT_CALL(mock, WriteUint32(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, InvokeListenThread(_, _)).WillRepeatedly(Return(-1));
    invoker.GetSessionForProxy(ipcProxy, session, localDeviceID);

    EXPECT_CALL(mock, InvokeListenThread(_, _)).WillRepeatedly(Return(ERR_NONE));
    invoker.GetSessionForProxy(ipcProxy, session, localDeviceID);
}

void AuthSession2ProxyFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }

    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteUint32(_)).WillOnce(Return(false));
    invoker.AuthSession2Proxy(handle, session);
}

void QueryClientSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t databusHandle = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.QueryClientSessionObject(databusHandle);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::NewSessionOfBinderProxyFuzzTest(provider);
    OHOS::GetSessionForProxyFuzzTest001(provider);
    OHOS::GetSessionForProxyFuzzTest002(provider);
    OHOS::AuthSession2ProxyFuzzTest(provider);
    OHOS::QueryClientSessionObjectFuzzTest(provider);
    return 0;
}
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

#include "ipcobjectproxymock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class IPCObjectProxyInterface {
public:
    IPCObjectProxyInterface() {};
    virtual ~IPCObjectProxyInterface() {};

    virtual IPCProcessSkeleton *GetCurrent() = 0;
    virtual bool UpdateDatabusClientSession() = 0;
    virtual bool CreateSoftbusServer(const std::string &name) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
};

class IPCObjectProxyInterfaceMock : public IPCObjectProxyInterface {
public:
    IPCObjectProxyInterfaceMock();
    ~IPCObjectProxyInterfaceMock() override;

    MOCK_METHOD(IPCProcessSkeleton *, GetCurrent, (), (override));
    MOCK_METHOD(bool, UpdateDatabusClientSession, (), (override));
    MOCK_METHOD(bool, CreateSoftbusServer, (const std::string &name), (override));
    MOCK_METHOD(IRemoteInvoker *, GetRemoteInvoker, (int proto), (override));
};

static void *g_interface = nullptr;

IPCObjectProxyInterfaceMock::IPCObjectProxyInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCObjectProxyInterfaceMock::~IPCObjectProxyInterfaceMock()
{
    g_interface = nullptr;
}

static IPCObjectProxyInterfaceMock *GetIPCObjectProxyInterfaceMock()
{
    return reinterpret_cast<IPCObjectProxyInterfaceMock *>(g_interface);
}

extern "C" {
IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCObjectProxyInterfaceMock()->GetCurrent();
}

bool IPCObjectProxy::UpdateDatabusClientSession()
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetIPCObjectProxyInterfaceMock()->UpdateDatabusClientSession();
}

bool IPCProcessSkeleton::CreateSoftbusServer(const std::string &name)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetIPCObjectProxyInterfaceMock()->CreateSoftbusServer(name);
}

IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCObjectProxyInterfaceMock()->GetRemoteInvoker(proto);
}
}

void UpdateProtoFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    proxy->UpdateProto(nullptr);
    dbinder_negotiation_data data;
    data.proto = IRemoteObject::IF_PROT_DATABUS;
    NiceMock<IPCObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, UpdateDatabusClientSession()).WillOnce(Return(true));
    proxy->UpdateProto(&data);
}

void MakeDBinderTransSessionFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    DBinderNegotiationData data;
    NiceMock<IPCObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS)).WillOnce(Return(nullptr));
    proxy->MakeDBinderTransSession(data);
    std::shared_ptr<DBinderDatabusInvoker> invoker = std::make_shared<DBinderDatabusInvoker>();
    if (invoker == nullptr) {
        return;
    }
    EXPECT_CALL(mock, GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS)).WillOnce(Return(invoker.get()));
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    proxy->MakeDBinderTransSession(data);

    std::shared_ptr<IPCProcessSkeleton> current = std::make_shared<IPCProcessSkeleton>();
    if (current == nullptr) {
        return;
    }
    data.peerServiceName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    if (data.peerServiceName.empty()) {
        return;
    }
    EXPECT_CALL(mock, GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS)).WillRepeatedly(Return(invoker.get()));
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current.get()));
    EXPECT_CALL(mock, CreateSoftbusServer(_)).WillOnce(Return(true));
    proxy->MakeDBinderTransSession(data);
}

void GetDBinderNegotiationDataFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    DBinderNegotiationData dbinderData;
    proxy->dbinderData_ = nullptr;
    proxy->GetDBinderNegotiationData(dbinderData);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::UpdateProtoFuzzTest(provider);
    OHOS::MakeDBinderTransSessionFuzzTest(provider);
    OHOS::GetDBinderNegotiationDataFuzzTest(provider);
    return 0;
}
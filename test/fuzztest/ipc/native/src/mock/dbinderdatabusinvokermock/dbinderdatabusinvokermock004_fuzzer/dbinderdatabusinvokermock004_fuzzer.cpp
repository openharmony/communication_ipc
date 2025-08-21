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
    virtual bool GetPidAndUidFromServiceName(const std::string &serviceName, int32_t &pid, int32_t &uid) = 0;
    virtual int32_t CreateClientSocket(const std::string &ownName, const std::string &peerName,
        const std::string &networkId) = 0;
};

class DBinderDataBusInvokerInterfaceMock : public DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterfaceMock();
    ~DBinderDataBusInvokerInterfaceMock() override;

    MOCK_METHOD(IPCProcessSkeleton *, GetCurrent, (), (override));
    MOCK_METHOD(bool, GetPidAndUidFromServiceName, (const std::string &serviceName, int32_t &pid, int32_t &uid),
        (override));
    MOCK_METHOD(int32_t, CreateClientSocket, (const std::string &ownName, const std::string &peerName,
        const std::string &networkId), (override));
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

bool DatabusSocketListener::GetPidAndUidFromServiceName(const std::string &serviceName, int32_t &pid, int32_t &uid)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetDBinderDataBusInvokerInterfaceMock()->GetPidAndUidFromServiceName(serviceName, pid, uid);
}

int32_t DatabusSocketListener::CreateClientSocket(const std::string &ownName, const std::string &peerName,
    const std::string &networkId)
{
    if (g_interface == nullptr) {
        return 1;
    }
    return GetDBinderDataBusInvokerInterfaceMock()->CreateClientSocket(ownName, peerName, networkId);
}
}

void FlattenSessionFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> connectSession = CreateDBinderSessionObject(provider);
    if (connectSession == nullptr) {
        return;
    }
    connectSession->SetDeviceId("deviceId");
    uint32_t binderVersion = provider.ConsumeIntegral<uint32_t>();
    FlatDBinderSession flatSession;
    DBinderDatabusInvoker invoker;
    invoker.FlattenSession(reinterpret_cast<unsigned char *>(&flatSession), connectSession, binderVersion);

    connectSession->SetServiceName("serviceName");
    invoker.FlattenSession(reinterpret_cast<unsigned char *>(&flatSession), connectSession, binderVersion);
}

void UnFlattenSessionFuzzTest(FuzzedDataProvider &provider)
{
    FlatDBinderSession flatSession;
    flatSession.stubIndex = provider.ConsumeIntegral<uint64_t>();
    flatSession.version = provider.ConsumeIntegralInRange<uint16_t>(0, SUPPORT_TOKENID_VERSION_NUM);
    flatSession.magic = TOKENID_MAGIC;
    uint32_t binderVersion = provider.ConsumeIntegralInRange<uint32_t>(0, SUPPORT_TOKENID_VERSION_NUM);

    DBinderDatabusInvoker invoker;
    invoker.UnFlattenSession(reinterpret_cast<unsigned char *>(&flatSession), binderVersion);
}

void UpdateClientSessionFuzzTest001(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (sessionObject == nullptr) {
        return;
    }
    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr) {
        return;
    }
    current->exitFlag_ = false;
    current->sessionName_ = "sessionName";
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    EXPECT_CALL(mock, GetPidAndUidFromServiceName(_, _, _)).WillOnce(Return(true));
    EXPECT_CALL(mock, CreateClientSocket(current->sessionName_, _, _)).WillOnce(Return(1));
    DBinderDatabusInvoker invoker;
    invoker.UpdateClientSession(sessionObject);
    delete current;
}

void UpdateClientSessionFuzzTest002(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (sessionObject == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.UpdateClientSession(sessionObject);

    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr) {
        return;
    }
    current->exitFlag_ = false;
    current->sessionName_ = "sessionName";
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    EXPECT_CALL(mock, GetPidAndUidFromServiceName(_, _, _)).WillOnce(Return(false));
    invoker.UpdateClientSession(sessionObject);

    EXPECT_CALL(mock, GetPidAndUidFromServiceName(_, _, _)).WillOnce(Return(true));
    EXPECT_CALL(mock, CreateClientSocket(current->sessionName_, _, _)).WillOnce(Return(0));
    invoker.UpdateClientSession(sessionObject);
    delete current;
}

void OnDatabusSessionClientSideClosedFuzzTest001(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr) {
        return;
    }
    current->exitFlag_ = false;
    std::shared_ptr<DBinderSessionObject> object = CreateDBinderSessionObject(provider);
    if (object == nullptr) {
        return;
    }
    object->SetSocketId(socketId);
    current->ProxyAttachDBinderSession(socketId, object);
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    invoker.OnDatabusSessionClientSideClosed(socketId);

    auto processSkeleton = ProcessSkeleton::GetInstance();
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> ipcProxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (processSkeleton == nullptr || ipcProxy == nullptr) {
        return;
    }
    std::u16string descriptor = current->MakeHandleDescriptor(socketId);
    wptr<IRemoteObject> wp = ipcProxy.GetRefPtr();
    processSkeleton->objects_.insert_or_assign(descriptor, wp);
    invoker.OnDatabusSessionClientSideClosed(socketId);
    delete current;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FlattenSessionFuzzTest(provider);
    OHOS::UnFlattenSessionFuzzTest(provider);
    OHOS::UpdateClientSessionFuzzTest001(provider);
    OHOS::UpdateClientSessionFuzzTest002(provider);
    OHOS::OnDatabusSessionClientSideClosedFuzzTest001(provider);
    return 0;
}
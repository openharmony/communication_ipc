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
    virtual std::string GetLocalDeviceID() = 0;
};

class DBinderDataBusInvokerInterfaceMock : public DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterfaceMock();
    ~DBinderDataBusInvokerInterfaceMock() override;

    MOCK_METHOD(IPCProcessSkeleton *, GetCurrent, (), (override));
    MOCK_METHOD(std::string, GetLocalDeviceID, (), (override));
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

std::string IPCProcessSkeleton::GetLocalDeviceID()
{
    if (g_interface == nullptr) {
        return "localDeviceID";
    }
    return GetDBinderDataBusInvokerInterfaceMock()->GetLocalDeviceID();
}
}

void MakeStubIndexByRemoteObjectFuzzTest002(FuzzedDataProvider &provider)
{
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(nullptr));
    DBinderDatabusInvoker invoker;
    invoker.MakeStubIndexByRemoteObject(nullptr);
}

void MakeDefaultServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.MakeDefaultServerSessionObject(stubIndex, session);

    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr) {
        return;
    }
    current->exitFlag_ = false;
    current->sessionName_ = "sessionName";
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    EXPECT_CALL(mock, GetLocalDeviceID()).WillOnce(Return("localDeviceID"));
    invoker.MakeDefaultServerSessionObject(stubIndex, session);
    delete current;
}

void ConnectRemoteObject2SessionFuzzTest(FuzzedDataProvider &provider)
{
    int handle = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> stubObject = sptr<IPCObjectProxy>::MakeSptr(handle);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (stubObject == nullptr || sessionObject == nullptr) {
        return;
    }
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    DBinderDatabusInvoker invoker;
    invoker.ConnectRemoteObject2Session(stubObject, stubIndex, sessionObject);
}

void CreateServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectStub> stub = sptr<IPCObjectStub>::MakeSptr();
    std::shared_ptr<DBinderSessionObject> sessionObject = CreateDBinderSessionObject(provider);
    if (stub == nullptr || sessionObject == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    binder_uintptr_t binder = reinterpret_cast<binder_uintptr_t>(stub.GetRefPtr());
    invoker.CreateServerSessionObject(binder, sessionObject);
}

void FlushCommandsFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = sptr<IPCObjectProxy>::MakeSptr(handle);
    if (object == nullptr) {
        return;
    }
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    DBinderDatabusInvoker invoker;
    invoker.FlushCommands(object.GetRefPtr());
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::MakeStubIndexByRemoteObjectFuzzTest002(provider);
    OHOS::MakeDefaultServerSessionObjectFuzzTest(provider);
    OHOS::ConnectRemoteObject2SessionFuzzTest(provider);
    OHOS::CreateServerSessionObjectFuzzTest(provider);
    OHOS::FlushCommandsFuzzTest(provider);
    return 0;
}
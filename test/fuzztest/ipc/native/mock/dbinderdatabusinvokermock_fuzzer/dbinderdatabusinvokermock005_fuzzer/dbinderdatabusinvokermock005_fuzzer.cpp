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
    virtual std::list<uint64_t> DetachAppAuthInfoBySocketId(int32_t socketId) = 0;
};

class DBinderDataBusInvokerInterfaceMock : public DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterfaceMock();
    ~DBinderDataBusInvokerInterfaceMock() override;

    MOCK_METHOD(IPCProcessSkeleton *, GetCurrent, (), (override));
    MOCK_METHOD(std::list<uint64_t>, DetachAppAuthInfoBySocketId, (int32_t socketId), (override));
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

std::list<uint64_t> IPCProcessSkeleton::DetachAppAuthInfoBySocketId(int32_t socketId)
{
    if (g_interface == nullptr) {
        return {};
    }
    return GetDBinderDataBusInvokerInterfaceMock()->DetachAppAuthInfoBySocketId(socketId);
}
}

void OnDatabusSessionClientSideClosedFuzzTest002(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.OnDatabusSessionClientSideClosed(socketId);

    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr) {
        return;
    }
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    invoker.OnDatabusSessionClientSideClosed(socketId);
    delete current;
}

void OnDatabusSessionServerSideClosedFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;

    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (current == nullptr || stubObject == nullptr) {
        return;
    }
    current->exitFlag_ = false;
    current->AddStubByIndex(stubObject.GetRefPtr());
    uint64_t stubIndex = current->randNum_;
    std::list<uint64_t> stubIndexs = {stubIndex};
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    EXPECT_CALL(mock, DetachAppAuthInfoBySocketId(socketId)).WillOnce(Return(stubIndexs));
    invoker.OnDatabusSessionServerSideClosed(socketId);
    delete current;
}

void QueryHandleBySessionFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.QueryHandleBySession(session);
}

void CheckAndSetCallerInfoFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (current == nullptr || session == nullptr) {
        return;
    }
    current->exitFlag_ = false;
    session->SetPeerUid(-1);
    current->StubAttachDBinderSession(socketId, session);
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    DBinderDatabusInvoker invoker;
    invoker.CheckAndSetCallerInfo(socketId, stubIndex);

    session->SetPeerUid(1);
    uint32_t pid = static_cast<uint32_t>(session->GetPeerPid());
    uint32_t uid = static_cast<uint32_t>(session->GetPeerUid());
    uint32_t callerTokenId = session->GetTokenId();
    std::string deviceId = session->GetDeviceId();
    int32_t listenFd = provider.ConsumeIntegral<int32_t>();
    current->AttachAppInfoToStubIndex(pid, uid, callerTokenId, deviceId, stubIndex, listenFd);
    invoker.CheckAndSetCallerInfo(socketId, stubIndex);
    delete current;
}

void MakeStubIndexByRemoteObjectFuzzTest001(FuzzedDataProvider &provider)
{
    DBinderDatabusInvoker invoker;
    const std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    const std::u16string descriptor16 = Str8ToStr16(descriptor);
    sptr<IPCObjectStub> object = sptr<IPCObjectStub>::MakeSptr(descriptor16);
    if (object == nullptr) {
        return;
    }
    auto processSkeleton = ProcessSkeleton::GetInstance();
    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr || processSkeleton == nullptr) {
        return;
    }
    current->exitFlag_ = false;
    current->stubObjects_[0] = object.GetRefPtr();
    processSkeleton->AttachObject(object.GetRefPtr(), descriptor16, true);
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    invoker.MakeStubIndexByRemoteObject(object.GetRefPtr());

    current->stubObjects_.clear();
    current->stubObjects_[1] = object.GetRefPtr();
    invoker.MakeStubIndexByRemoteObject(object.GetRefPtr());
    delete current;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::OnDatabusSessionClientSideClosedFuzzTest002(provider);
    OHOS::OnDatabusSessionServerSideClosedFuzzTest(provider);
    OHOS::QueryHandleBySessionFuzzTest(provider);
    OHOS::CheckAndSetCallerInfoFuzzTest(provider);
    OHOS::MakeStubIndexByRemoteObjectFuzzTest001(provider);
    return 0;
}
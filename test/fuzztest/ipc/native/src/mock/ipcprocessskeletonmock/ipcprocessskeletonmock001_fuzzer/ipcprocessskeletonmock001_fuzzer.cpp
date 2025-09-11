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

#include "ipcprocessskeletonmock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class IPCProcessSkeletonInterface {
public:
    IPCProcessSkeletonInterface() {};
    virtual ~IPCProcessSkeletonInterface() {};

    virtual ProcessSkeleton *GetInstance() = 0;
    virtual sptr<IRemoteObject> QueryObject(const std::u16string &descriptor, bool lockFlag) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual bool PingService(int32_t handle) = 0;
    virtual bool AttachObject(IRemoteObject *object, bool lockFlag) = 0;
};

class IPCProcessSkeletonInterfaceMock : public IPCProcessSkeletonInterface {
public:
    IPCProcessSkeletonInterfaceMock();
    ~IPCProcessSkeletonInterfaceMock() override;

    MOCK_METHOD(ProcessSkeleton *, GetInstance, (), (override));
    MOCK_METHOD(sptr<IRemoteObject>, QueryObject, (const std::u16string &descriptor, bool lockFlag), (override));
    MOCK_METHOD(IRemoteInvoker *, GetRemoteInvoker, (int proto), (override));
    MOCK_METHOD(bool, PingService, (int32_t handle), (override));
    MOCK_METHOD(bool, AttachObject, (IRemoteObject * object, bool lockFlag), (override));
};

static void *g_interface = nullptr;

IPCProcessSkeletonInterfaceMock::IPCProcessSkeletonInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCProcessSkeletonInterfaceMock::~IPCProcessSkeletonInterfaceMock()
{
    g_interface = nullptr;
}

static IPCProcessSkeletonInterface *GetIPCProcessSkeletonInterface()
{
    return reinterpret_cast<IPCProcessSkeletonInterface *>(g_interface);
}

extern "C" {
ProcessSkeleton *ProcessSkeleton::GetInstance()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCProcessSkeletonInterface()->GetInstance();
}

sptr<IRemoteObject> IPCProcessSkeleton::QueryObject(const std::u16string &descriptor, bool lockFlag)
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCProcessSkeletonInterface()->QueryObject(descriptor, lockFlag);
}

IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCProcessSkeletonInterface()->GetRemoteInvoker(proto);
}

bool BinderInvoker::PingService(int32_t handle)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetIPCProcessSkeletonInterface()->PingService(handle);
}

bool IPCProcessSkeleton::AttachObject(IRemoteObject *object, bool lockFlag)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetIPCProcessSkeletonInterface()->AttachObject(object, lockFlag);
}
}

void FindOrNewObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).WillOnce(Return(nullptr));
    current->FindOrNewObject(handle, nullptr);
}

void GetProxyObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int handle = provider.ConsumeIntegral<int>();
    bool newFlag = provider.ConsumeBool();
    current->GetProxyObject(handle, newFlag);

    ProcessSkeleton *processSkeleton = new (std::nothrow) ProcessSkeleton();
    sptr<IPCObjectStub> object = new (std::nothrow) IPCObjectStub();
    if (processSkeleton == nullptr || object == nullptr) {
        return;
    }
    processSkeleton->exitFlag_ = true;
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).WillRepeatedly(Return(processSkeleton));
    current->GetProxyObject(handle, newFlag);

    handle = REGISTRY_HANDLE;
    processSkeleton->exitFlag_ = false;
    EXPECT_CALL(mock, QueryObject(_, false)).WillRepeatedly(Return(nullptr));
    current->GetProxyObject(handle, newFlag);

    BinderInvoker *invoker = new (std::nothrow) BinderInvoker();
    if (invoker == nullptr) {
        delete processSkeleton;
        return;
    }
    EXPECT_CALL(mock, GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(mock, PingService(_)).WillRepeatedly(Return(false));
    current->GetProxyObject(handle, newFlag);

    EXPECT_CALL(mock, PingService(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AttachObject(_, false)).WillOnce(Return(false));
    current->GetProxyObject(handle, newFlag);
    delete invoker;
    delete processSkeleton;
}

void SetRegistryObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectStub(descriptor16);
    if (current == nullptr || object == nullptr) {
        return;
    }
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).WillRepeatedly(Return(nullptr));
    current->SetRegistryObject(object);

    ProcessSkeleton *processSkeleton = new (std::nothrow) ProcessSkeleton();
    if (processSkeleton == nullptr) {
        return;
    }
    processSkeleton->exitFlag_ = false;
    EXPECT_CALL(mock, GetInstance()).WillRepeatedly(Return(processSkeleton));
    EXPECT_CALL(mock, GetRemoteInvoker(_)).WillRepeatedly(Return(nullptr));
    current->SetRegistryObject(object);
    delete processSkeleton;
}

void SpawnThreadFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int policy = provider.ConsumeIntegral<int>();
    int proto = provider.ConsumeIntegral<int>();
    current->threadPool_ = nullptr;
    current->SpawnThread(policy, proto);
}

void OnThreadTerminatedFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    std::string threadName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    current->threadPool_ = nullptr;
    current->OnThreadTerminated(threadName);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FindOrNewObjectFuzzTest(provider);
    OHOS::GetProxyObjectFuzzTest(provider);
    OHOS::SetRegistryObjectFuzzTest(provider);
    OHOS::SpawnThreadFuzzTest(provider);
    OHOS::OnThreadTerminatedFuzzTest(provider);
    return 0;
}

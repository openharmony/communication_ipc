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

#include "ipcskeletonmock_fuzzer.h"

#include "dbinder_databus_invoker.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "string_ex.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static constexpr size_t MAX_STR_LEN = 100;

class IPCSkeletonInterface {
public:
    IPCSkeletonInterface() {};
    virtual ~IPCSkeletonInterface() {};

    virtual IRemoteInvoker *GetProxyInvoker(IRemoteObject *object) = 0;
    virtual IRemoteInvoker *GetActiveInvoker() = 0;
    virtual IRemoteInvoker *GetDefaultInvoker() = 0;
};

class IPCSkeletonInterfaceMock : public IPCSkeletonInterface {
public:
    IPCSkeletonInterfaceMock();
    ~IPCSkeletonInterfaceMock() override;

    MOCK_METHOD(IRemoteInvoker *, GetProxyInvoker, (IRemoteObject *object), (override));
    MOCK_METHOD(IRemoteInvoker *, GetActiveInvoker, (), (override));
    MOCK_METHOD(IRemoteInvoker *, GetDefaultInvoker, (), (override));
};

static void *g_interface = nullptr;

IPCSkeletonInterfaceMock::IPCSkeletonInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCSkeletonInterfaceMock::~IPCSkeletonInterfaceMock()
{
    g_interface = nullptr;
}

static IPCSkeletonInterface *GetIPCSkeletonInterface()
{
    return reinterpret_cast<IPCSkeletonInterface *>(g_interface);
}

extern "C" {
IRemoteInvoker *IPCThreadSkeleton::GetProxyInvoker(IRemoteObject *object)
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCSkeletonInterface()->GetProxyInvoker(object);
}

IRemoteInvoker *IPCThreadSkeleton::GetActiveInvoker()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCSkeletonInterface()->GetActiveInvoker();
}

IRemoteInvoker *IPCThreadSkeleton::GetDefaultInvoker()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCSkeletonInterface()->GetDefaultInvoker();
}
}

void FlushCommandsFuzzTest(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    int handle = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> object =
        new (std::nothrow) IPCObjectProxy(handle, descriptor16, IRemoteObject::IF_PROT_BINDER);
    if (object == nullptr) {
        return;
    }
    DBinderDatabusInvoker *invoker = new (std::nothrow) DBinderDatabusInvoker();
    if (invoker == nullptr) {
        return;
    }
    NiceMock<IPCSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetProxyInvoker(object.GetRefPtr())).WillRepeatedly(Return(invoker));
    IPCSkeleton::FlushCommands(object.GetRefPtr());
    delete invoker;
}

void SetCallingIdentityFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<BinderInvoker> invoker = std::make_shared<BinderInvoker>();
    if (invoker == nullptr) {
        return;
    }
    NiceMock<IPCSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetActiveInvoker()).WillRepeatedly(Return(invoker.get()));
    std::string identity = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    bool flag = provider.ConsumeBool();
    IPCSkeleton::SetCallingIdentity(identity, flag);
}

void EnableIPCThreadReclaimFuzzTest(FuzzedDataProvider &provider)
{
    NiceMock<IPCSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(Return(nullptr));
    bool enable = provider.ConsumeBool();
    IPCSkeleton::EnableIPCThreadReclaim(enable);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FlushCommandsFuzzTest(provider);
    OHOS::SetCallingIdentityFuzzTest(provider);
    OHOS::EnableIPCThreadReclaimFuzzTest(provider);
    return 0;
}
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

#include "ipcthreadskeletonmock_fuzzer.h"

#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_thread_skeleton.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static constexpr size_t MAX_STR_LEN = 100;

class IPCThreadSkeletonInterface {
public:
    IPCThreadSkeletonInterface() {};
    virtual ~IPCThreadSkeletonInterface() {};

    virtual IPCThreadSkeleton *GetCurrent() = 0;
};

class IPCThreadSkeletonInterfaceMock : public IPCThreadSkeletonInterface {
public:
    IPCThreadSkeletonInterfaceMock();
    ~IPCThreadSkeletonInterfaceMock() override;

    MOCK_METHOD0(GetCurrent, IPCThreadSkeleton *());
};

static void *g_interface = nullptr;

IPCThreadSkeletonInterfaceMock::IPCThreadSkeletonInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCThreadSkeletonInterfaceMock::~IPCThreadSkeletonInterfaceMock()
{
    g_interface = nullptr;
}

static IPCThreadSkeletonInterface *GetIPCThreadSkeletonInterface()
{
    return reinterpret_cast<IPCThreadSkeletonInterface *>(g_interface);
}

extern "C" {
IPCThreadSkeleton *IPCThreadSkeleton::GetCurrent()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCThreadSkeletonInterface()->GetCurrent();
}
}

void SetThreadTypeFuzzTest(FuzzedDataProvider &provider)
{
    NiceMock<IPCThreadSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(nullptr));
    bool type = provider.ConsumeBool();
    ThreadType threadType = type ? ThreadType::IPC_THREAD : ThreadType::NORMAL_THREAD;
    IPCThreadSkeleton::SetThreadType(threadType);
}

void UpdateSendRequestCountFuzzTest(FuzzedDataProvider &provider)
{
    NiceMock<IPCThreadSkeletonInterfaceMock> mock;
    int delta = provider.ConsumeIntegral<int>();
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(nullptr));
    IPCThreadSkeleton::UpdateSendRequestCount(delta);
}

void GetProxyInvokerFuzzTest(FuzzedDataProvider &provider)
{
    int handle = provider.ConsumeIntegral<int>();
    sptr<IPCObjectProxy> proxy = sptr<IPCObjectProxy>::MakeSptr(handle);
    IPCThreadSkeleton::GetProxyInvoker(proxy);
    sptr<IPCObjectStub> stub = sptr<IPCObjectStub>::MakeSptr();
    IPCThreadSkeleton::GetProxyInvoker(stub);
}

void SaveThreadNameFuzzTest(FuzzedDataProvider &provider)
{
    NiceMock<IPCThreadSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(nullptr));
    std::string name = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    IPCThreadSkeleton::SaveThreadName(name);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SetThreadTypeFuzzTest(provider);
    OHOS::UpdateSendRequestCountFuzzTest(provider);
    OHOS::GetProxyInvokerFuzzTest(provider);
    OHOS::SaveThreadNameFuzzTest(provider);
    return 0;
}

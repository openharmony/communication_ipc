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
class IPCSkeletonInterface {
public:
    IPCSkeletonInterface() {};
    virtual ~IPCSkeletonInterface() {};

    virtual IPCProcessSkeleton *GetCurrent() = 0;
};

class IPCSkeletonInterfaceMock : public IPCSkeletonInterface {
public:
    IPCSkeletonInterfaceMock();
    ~IPCSkeletonInterfaceMock() override;

    MOCK_METHOD(IPCProcessSkeleton *, GetCurrent, (), (override));
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
IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCSkeletonInterface()->GetCurrent();
}
}

void SetContextObjectFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IRemoteObject> object;
    NiceMock<IPCSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(nullptr));
    IPCSkeleton::SetContextObject(object);
}

void SetMaxWorkThreadNumFuzzTest(FuzzedDataProvider &provider)
{
    int maxThreadNum = provider.ConsumeIntegral<int>();
    NiceMock<IPCSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(nullptr));
    IPCSkeleton::SetMaxWorkThreadNum(maxThreadNum);
}

void SetIPCProxyLimitFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t num = provider.ConsumeIntegral<uint64_t>();
    NiceMock<IPCSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(nullptr));
    IPCDfx::IPCProxyLimitCallback callback;
    IPCDfx::SetIPCProxyLimit(num, callback);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SetContextObjectFuzzTest(provider);
    OHOS::SetMaxWorkThreadNumFuzzTest(provider);
    OHOS::SetIPCProxyLimitFuzzTest(provider);
    return 0;
}
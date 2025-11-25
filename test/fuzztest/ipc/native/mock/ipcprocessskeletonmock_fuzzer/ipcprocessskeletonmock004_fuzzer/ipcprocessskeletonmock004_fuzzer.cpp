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

    virtual int32_t StartServerListener(const std::string &ownName) = 0;
};

class IPCProcessSkeletonInterfaceMock : public IPCProcessSkeletonInterface {
public:
    IPCProcessSkeletonInterfaceMock();
    ~IPCProcessSkeletonInterfaceMock() override;

    MOCK_METHOD(int32_t, StartServerListener, (const std::string &ownName), (override));
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
int32_t DatabusSocketListener::StartServerListener(const std::string &ownName)
{
    if (g_interface == nullptr) {
        return -1;
    }
    return GetIPCProcessSkeletonInterface()->StartServerListener(ownName);
}
}

void AddSendThreadInWaitFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint64_t seqNumber = provider.ConsumeIntegral<uint64_t>();
    int userWaitTime = provider.ConsumeIntegral<int>();
    current->AddSendThreadInWait(seqNumber, nullptr, userWaitTime);
}

void QueryStubByIndexFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    current->stubObjects_.insert(std::pair<uint64_t, IRemoteObject *>(stubIndex, nullptr));
    current->QueryStubByIndex(stubIndex);
}

void CreateSoftbusServerFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    std::string serverName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    current->sessionName_ = serverName;
    current->listenSocketId_ = 1;
    current->CreateSoftbusServer(serverName);

    current->listenSocketId_ = -1;
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, StartServerListener(serverName)).WillRepeatedly(Return(1));
    current->sessionName_ = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    current->CreateSoftbusServer(serverName);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AddSendThreadInWaitFuzzTest(provider);
    OHOS::QueryStubByIndexFuzzTest(provider);
    OHOS::CreateSoftbusServerFuzzTest(provider);
    return 0;
}

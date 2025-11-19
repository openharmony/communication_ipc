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

    virtual bool IsSameRemoteObject(IRemoteObject *stub, int pid, int uid, uint32_t tokenId,
        const std::string &deviceId, const std::shared_ptr<CommAuthInfo> &auth) = 0;
};

class IPCProcessSkeletonInterfaceMock : public IPCProcessSkeletonInterface {
public:
    IPCProcessSkeletonInterfaceMock();
    ~IPCProcessSkeletonInterfaceMock() override;

    MOCK_METHOD(bool, IsSameRemoteObject, (IRemoteObject * stub, int pid, int uid, uint32_t tokenId,
        const std::string &deviceId, const std::shared_ptr<CommAuthInfo> &auth), (override));
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
bool IPCProcessSkeleton::IsSameRemoteObject(IRemoteObject *stub, int pid, int uid, uint32_t tokenId,
    const std::string &deviceId, const std::shared_ptr<CommAuthInfo> &auth)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetIPCProcessSkeletonInterface()->IsSameRemoteObject(stub, pid, uid, tokenId, deviceId, auth);
}
}

void AddDataThreadInWaitFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    std::thread t([current] {
        std::thread::id threadId = std::this_thread::get_id();
        current->AddDataThreadInWait(threadId);
    });

    auto startTime = std::chrono::steady_clock::now();
    auto timeoutDuration = std::chrono::seconds(TIMEOUT_SECOND);
    std::thread::id threadId = t.get_id();
    std::shared_ptr<SocketThreadLockInfo> threadLockInfo = current->QueryThreadLockInfo(threadId);
    while (threadLockInfo == nullptr) {
        threadLockInfo = current->QueryThreadLockInfo(threadId);
        auto currentTime = std::chrono::steady_clock::now();
        if (currentTime - startTime >= timeoutDuration) {
            break;
        }
    }
    current->WakeUpDataThread(threadId);
    t.join();
}

void AttachCommAuthInfoFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int pid = provider.ConsumeIntegral<int>();
    int uid = provider.ConsumeIntegral<int>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::string deviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    sptr<IPCObjectStub> stubObject = sptr<IPCObjectStub>::MakeSptr();
    if (stubObject == nullptr) {
        return;
    }
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, IsSameRemoteObject(_, _, _, _, _, _)).WillOnce(Return(true));
    // call twice
    current->AttachCommAuthInfo(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);
    current->AttachCommAuthInfo(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);
}

void StubDetachDBinderSessionFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    uint32_t tokenId;
    current->dbinderSessionObjects_.insert(std::make_pair(handle, nullptr));
    current->StubDetachDBinderSession(handle, tokenId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AddDataThreadInWaitFuzzTest(provider);
    OHOS::AttachCommAuthInfoFuzzTest(provider);
    OHOS::StubDetachDBinderSessionFuzzTest(provider);
    return 0;
}

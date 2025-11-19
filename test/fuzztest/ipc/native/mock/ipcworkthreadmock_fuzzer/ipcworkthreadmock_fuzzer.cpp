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

#include "ipcworkthreadmock_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "binder_invoker.h"
#include "ipc_thread_skeleton.h"
#include "ipc_workthread.h"
#include "iremote_invoker.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static constexpr size_t MAX_STR_LEN = 100;

using threadPolicy = decltype(IPCWorkThread::SPAWN_PASSIVE);
static const std::vector<threadPolicy> policyList = {
    IPCWorkThread::SPAWN_PASSIVE,
    IPCWorkThread::SPAWN_ACTIVE,
    IPCWorkThread::PROCESS_PASSIVE,
    IPCWorkThread::PROCESS_ACTIVE
};

class IPCWorkThreadInterface {
public:
    IPCWorkThreadInterface() {};
    virtual ~IPCWorkThreadInterface() {};

    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
};

class IPCWorkThreadInterfaceMock : public IPCWorkThreadInterface {
public:
    IPCWorkThreadInterfaceMock();
    ~IPCWorkThreadInterfaceMock() override;

    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
};

static void *g_interface = nullptr;

IPCWorkThreadInterfaceMock::IPCWorkThreadInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCWorkThreadInterfaceMock::~IPCWorkThreadInterfaceMock()
{
    g_interface = nullptr;
}

static IPCWorkThreadInterface *GetIPCWorkThreadInterface()
{
    return reinterpret_cast<IPCWorkThreadInterface *>(g_interface);
}

extern "C" {
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (GetIPCWorkThreadInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCWorkThreadInterface()->GetRemoteInvoker(proto);
    }
}

void ThreadHandlerFuzzTest(FuzzedDataProvider &provider)
{
    std::string threadName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    IPCWorkThread ipcWorkThread(threadName);
    ipcWorkThread.ThreadHandler(nullptr);
}

void JoinThreadFuzzTest(FuzzedDataProvider &provider)
{
    int proto = provider.ConsumeIntegral<int>();
    int policy = provider.ConsumeIntegral<int>();
    std::string threadName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    NiceMock<IPCWorkThreadInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(testing::Return(nullptr));
    IPCWorkThread ipcWorkThread(threadName);
    ipcWorkThread.JoinThread(proto, policy);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ThreadHandlerFuzzTest(provider);
    OHOS::JoinThreadFuzzTest(provider);
    return 0;
}

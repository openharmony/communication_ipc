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
};

class DBinderDataBusInvokerInterfaceMock : public DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterfaceMock();
    ~DBinderDataBusInvokerInterfaceMock() override;

    MOCK_METHOD(IPCProcessSkeleton *, GetCurrent, (), (override));
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
}

void QueryServerSessionObjectFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.QueryServerSessionObject(handle);
}

void OnReceiveNewConnectionFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    int peerPid = provider.ConsumeIntegral<int>();
    int peerUid = provider.ConsumeIntegral<int>();
    std::string peerName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string networkId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, networkId);
}

void OnRawDataAvailableFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    uint64_t seqNumber = provider.ConsumeIntegral<uint64_t>();
    std::vector<char> data;
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.OnRawDataAvailable(socketId, seqNumber, data.data(), data.size());

    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr) {
        return;
    }
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    invoker.OnRawDataAvailable(socketId, seqNumber, data.data(), data.size());

    size_t size = sizeof(dbinder_transaction_data);
    data.resize(size + size, 'a');
    invoker.OnRawDataAvailable(socketId, seqNumber, data.data(), data.size());
    delete current;
}

void OnMessageAvailableFuzzTest(FuzzedDataProvider &provider)
{
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    dbinder_transaction_data data;
    ssize_t len = static_cast<ssize_t>(sizeof(dbinder_transaction_data));
    DBinderDatabusInvoker invoker;
    invoker.OnMessageAvailable(socketId, reinterpret_cast<const char *>(&data), len);
}

void OnSendMessageFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = CreateDBinderSessionObject(provider);
    if (sessionOfPeer == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    sessionOfPeer->SetSocketId(socketId);
    DBinderDatabusInvoker invoker;
    invoker.OnSendMessage(sessionOfPeer);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::QueryServerSessionObjectFuzzTest(provider);
    OHOS::OnReceiveNewConnectionFuzzTest(provider);
    OHOS::OnRawDataAvailableFuzzTest(provider);
    OHOS::OnMessageAvailableFuzzTest(provider);
    OHOS::OnSendMessageFuzzTest(provider);
    return 0;
}
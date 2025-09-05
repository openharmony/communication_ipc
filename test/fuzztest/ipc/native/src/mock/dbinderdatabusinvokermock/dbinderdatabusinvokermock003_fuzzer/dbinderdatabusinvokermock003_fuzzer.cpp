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
    virtual int32_t SendBytes(int32_t socket, const void *data, uint32_t len) = 0;
    virtual void UpdateSendBuffer(uint32_t userDataSize) = 0;
};

class DBinderDataBusInvokerInterfaceMock : public DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterfaceMock();
    ~DBinderDataBusInvokerInterfaceMock() override;

    MOCK_METHOD(IPCProcessSkeleton *, GetCurrent, (), (override));
    MOCK_METHOD(int32_t, SendBytes, (int32_t socket, const void *data, uint32_t len), (override));
    MOCK_METHOD(void, UpdateSendBuffer, (uint32_t userDataSize), (override));
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

int32_t DBinderSoftbusClient::SendBytes(int32_t socket, const void *data, uint32_t len)
{
    if (g_interface == nullptr) {
        return 0;
    }
    return GetDBinderDataBusInvokerInterfaceMock()->SendBytes(socket, data, len);
}

void BufferObject::UpdateSendBuffer(uint32_t userDataSize)
{
    if (g_interface == nullptr) {
        return;
    }
    GetDBinderDataBusInvokerInterfaceMock()->UpdateSendBuffer(userDataSize);
}
}

void SendDataFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<BufferObject> buffer = std::make_shared<BufferObject>();
    if (buffer == nullptr) {
        return;
    }

    ssize_t writeCursor = provider.ConsumeIntegral<ssize_t>();
    ssize_t readCursor = provider.ConsumeIntegral<ssize_t>();
    ssize_t sendBuffSize = provider.ConsumeIntegral<ssize_t>();
    buffer->SetSendBufferWriteCursor(writeCursor);
    buffer->SetSendBufferReadCursor(readCursor);
    buffer->sendBuffSize_ = sendBuffSize;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, UpdateSendBuffer(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SendBytes(_, _, _)).WillRepeatedly(Return(-1));
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SendData(buffer, socketId);
}

void OnSendRawDataFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    session->SetSocketId(socketId);
    DBinderDatabusInvoker invoker;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, SendBytes(_, _, _)).WillRepeatedly(Return(0));
    invoker.OnSendRawData(session, nullptr, 0);

    EXPECT_CALL(mock, SendBytes(_, _, _)).WillRepeatedly(Return(-1));
    invoker.OnSendRawData(session, nullptr, 0);
}

void JoinProcessThreadFuzzTest(FuzzedDataProvider &provider)
{
    bool initiative = provider.ConsumeBool();
    DBinderDatabusInvoker invoker;
    invoker.JoinThread(initiative);

    invoker.StopWorkThread();
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    invoker.JoinProcessThread(initiative);

    IPCProcessSkeleton *current = new (std::nothrow) IPCProcessSkeleton();
    if (current == nullptr) {
        return;
    }
    current->exitFlag_ = true;
    EXPECT_CALL(mock, GetCurrent()).WillRepeatedly(Return(current));
    invoker.JoinProcessThread(initiative);
    delete current;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SendDataFuzzTest(provider);
    OHOS::OnSendRawDataFuzzTest(provider);
    OHOS::JoinProcessThreadFuzzTest(provider);
    return 0;
}
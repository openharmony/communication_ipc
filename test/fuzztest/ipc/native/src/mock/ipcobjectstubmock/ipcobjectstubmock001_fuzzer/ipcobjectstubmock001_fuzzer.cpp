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

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "ipcobjectstubmock_fuzzer.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "message_parcel.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class IPCObjectStubInterface {
public:
    IPCObjectStubInterface() {};
    virtual ~IPCObjectStubInterface() {};

    virtual bool WriteInt32(int32_t value) = 0;
    virtual bool WriteString16(const std::u16string &value) = 0;
    virtual bool IsLocalCalling() = 0;
};

class IPCObjectStubInterfaceMock : public IPCObjectStubInterface {
public:
    IPCObjectStubInterfaceMock();
    ~IPCObjectStubInterfaceMock() override;
    MOCK_METHOD1(WriteInt32, bool(int32_t value));
    MOCK_METHOD1(WriteString16, bool(const std::u16string &value));
    MOCK_METHOD0(IsLocalCalling, bool());
};

static void *g_interface = nullptr;

IPCObjectStubInterfaceMock::IPCObjectStubInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCObjectStubInterfaceMock::~IPCObjectStubInterfaceMock()
{
    g_interface = nullptr;
}

static IPCObjectStubInterface *GetIPCObjectStubInterface()
{
    return reinterpret_cast<IPCObjectStubInterfaceMock *>(g_interface);
}

extern "C" {
    bool Parcel::WriteInt32(int32_t value)
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteInt32(value);
    }

    bool Parcel::WriteString16(const std::u16string &value)
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteString16(value);
    }

    bool IPCSkeleton::IsLocalCalling()
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->IsLocalCalling();
    }
}

static void DBinderPingTransactionFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    reply.WriteBuffer(bytes.data(), bytes.size());
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, WriteInt32).WillRepeatedly(Return(0));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderPingTransaction(code, data, reply, option);
}

static void DBinderSearchDescriptorFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    reply.WriteBuffer(bytes.data(), bytes.size());
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, WriteString16).WillRepeatedly(Return(0));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderSearchDescriptor(code, data, reply, option);
}

static void DBinderDumpTransactionFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillRepeatedly(Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderDumpTransaction(code, data, reply, option);
}

static void DBinderInvokeListenThreadFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillRepeatedly(Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderInvokeListenThread(code, data, reply, option);
}

static void DBinderIncRefsTransactionFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillRepeatedly(Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderIncRefsTransaction(code, data, reply, option);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DBinderPingTransactionFuzzTest(provider);
    OHOS::DBinderSearchDescriptorFuzzTest(provider);
    OHOS::DBinderDumpTransactionFuzzTest(provider);
    OHOS::DBinderInvokeListenThreadFuzzTest(provider);
    OHOS::DBinderIncRefsTransactionFuzzTest(provider);
    return 0;
}

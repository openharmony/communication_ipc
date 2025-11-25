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
    virtual bool WriteString(const std::string &value) = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual std::string CreateSessionName(int uid, int pid) = 0;
};

class IPCObjectStubInterfaceMock : public IPCObjectStubInterface {
public:
    IPCObjectStubInterfaceMock();
    ~IPCObjectStubInterfaceMock() override;
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD1(WriteUint32, bool(uint32_t value));
    MOCK_METHOD2(CreateSessionName, std::string(int uid, int pid));
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
    bool Parcel::WriteString(const std::string &value)
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteString(value);
    }

    bool Parcel::WriteUint32(uint32_t value)
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteUint32(value);
    }

    std::string IPCObjectStub::CreateSessionName(int uid, int pid)
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return "";
        }
        return interface->CreateSessionName(uid, pid);
    }
}

static void GetSessionNameForPidUidFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, CreateSessionName).WillRepeatedly(testing::Return("sessionName"));
    EXPECT_CALL(mockClient, WriteUint32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mockClient, WriteString).WillRepeatedly(testing::Return(true));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.GetSessionNameForPidUid(code, data, reply, option);
}

static void GetSessionNameForPidUidFuzzTest002(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, CreateSessionName).WillRepeatedly(testing::Return("sessionName"));
    EXPECT_CALL(mockClient, WriteUint32).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(mockClient, WriteString).WillRepeatedly(testing::Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.GetSessionNameForPidUid(code, data, reply, option);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetSessionNameForPidUidFuzzTest001(provider);
    OHOS::GetSessionNameForPidUidFuzzTest002(provider);
    return 0;
}

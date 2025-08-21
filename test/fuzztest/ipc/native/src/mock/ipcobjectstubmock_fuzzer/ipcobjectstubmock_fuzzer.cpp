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
using Transaction = decltype(FIRST_CALL_TRANSACTION);
static const std::vector<Transaction> codeList = {
    FIRST_CALL_TRANSACTION,
    LAST_CALL_TRANSACTION,
    PING_TRANSACTION,
    DUMP_TRANSACTION,
    SHELL_COMMAND_TRANSACTION,
    INTERFACE_TRANSACTION,
    SYSPROPS_TRANSACTION,
    SYNCHRONIZE_REFERENCE,
    INVOKE_LISTEN_THREAD,
    GET_PID_UID,
    GET_PROTO_INFO,
    GET_SESSION_NAME,
    GET_SESSION_NAME_PID_UID,
    GET_GRANTED_SESSION_NAME,
    REMOVE_SESSION_NAME,
    CLEAR_DBINDER_SERVICE_STATE,
    DBINDER_OBITUARY_TRANSACTION,
    DBINDER_INCREFS_TRANSACTION,
    DBINDER_DECREFS_TRANSACTION,
    DBINDER_ADD_COMMAUTH,
    TRANS_SYNC,
    TRANS_ASYNC,
};

class IPCObjectStubInterface {
public:
    IPCObjectStubInterface() {};
    virtual ~IPCObjectStubInterface() {};

    virtual bool WriteInt32(int32_t value) = 0;
    virtual bool WriteString16(const std::u16string &value) = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual bool IsLocalCalling() = 0;
    virtual bool IsSamgrCall() = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual std::string CreateSessionName(int uid, int pid) = 0;
    virtual std::string GetSessionName() = 0;
};

class IPCObjectStubInterfaceMock : public IPCObjectStubInterface {
public:
    IPCObjectStubInterfaceMock();
    ~IPCObjectStubInterfaceMock() override;
    MOCK_METHOD1(WriteInt32, bool(int32_t value));
    MOCK_METHOD1(WriteString16, bool(const std::u16string &value));
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD0(IsLocalCalling, bool());
    MOCK_METHOD0(IsSamgrCall, bool());
    MOCK_METHOD1(WriteUint32, bool(uint32_t value));
    MOCK_METHOD2(CreateSessionName, std::string(int uid, int pid));
    MOCK_METHOD0(GetSessionName, std::string());
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

    bool Parcel::WriteString(const std::string &value)
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteString(value);
    }

    bool IPCSkeleton::IsLocalCalling()
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->IsLocalCalling();
    }

    bool IPCObjectStub::IsSamgrCall()
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->IsSamgrCall();
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

    std::string IPCObjectStub::GetSessionName()
    {
        IPCObjectStubInterface* interface = GetIPCObjectStubInterface();
        if (interface == nullptr) {
            return "";
        }
        return interface->GetSessionName();
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
    EXPECT_CALL(mockClient, WriteInt32).WillOnce(Return(0));
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
    EXPECT_CALL(mockClient, WriteString16).WillOnce(Return(0));
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
    EXPECT_CALL(mockClient, IsLocalCalling).WillOnce(Return(false));
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
    EXPECT_CALL(mockClient, IsLocalCalling).WillOnce(Return(false));
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
    EXPECT_CALL(mockClient, IsLocalCalling).WillOnce(Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderIncRefsTransaction(code, data, reply, option);
}

static void DBinderDecRefsTransactionFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillOnce(Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderDecRefsTransaction(code, data, reply, option);
}

static void DBinderAddCommAuthFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillOnce(Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderAddCommAuth(code, data, reply, option);
}

static void DBinderGetSessionNameFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillOnce(Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderGetSessionName(code, data, reply, option);
}

static void DBinderGetSessionNameFuzzTest002(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillOnce(Return(true));
    EXPECT_CALL(mockClient, GetSessionName).WillOnce(Return(""));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderGetSessionName(code, data, reply, option);
}

static void DBinderGetSessionNameFuzzTest003(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillOnce(Return(true));
    EXPECT_CALL(mockClient, GetSessionName).WillOnce(Return("sessionname"));
    EXPECT_CALL(mockClient, WriteString).WillOnce(Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderGetSessionName(code, data, reply, option);
}

static void DBinderGetGrantedSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mockClient, IsSamgrCall).WillRepeatedly(testing::Return(true));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderGetGrantedSessionName(code, data, reply, option);
}

static void DBinderGetSessionNameForPidUidFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mockClient, IsSamgrCall).WillRepeatedly(testing::Return(true));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderGetSessionNameForPidUid(code, data, reply, option);
}

static void DBinderGetPidUidFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mockClient, IsSamgrCall).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mockClient, WriteUint32).WillRepeatedly(testing::Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderGetPidUid(code, data, reply, option);
}

static void DBinderGetPidUidFuzzTest002(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mockClient, IsSamgrCall).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mockClient, WriteUint32).WillRepeatedly(testing::Return(true));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderGetPidUid(code, data, reply, option);
}

static void DBinderRemoveSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, IsLocalCalling).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mockClient, IsSamgrCall).WillRepeatedly(testing::Return(true));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.DBinderRemoveSessionName(code, data, reply, option);
}

static void SendRequestFuzzTest001(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    size_t dataBytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> dataBytes = provider.ConsumeBytes<uint8_t>(dataBytesSize);
    data.WriteBuffer(dataBytes.data(), dataBytes.size());
    MessageParcel reply;
    size_t replyBytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> replyBytes = provider.ConsumeBytes<uint8_t>(replyBytesSize);
    reply.WriteBuffer(replyBytes.data(), replyBytes.size());
    MessageOption option;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.SendRequest(code, data, reply, option);
}

static void SendRequestFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel data;
    size_t dataBytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> dataBytes = provider.ConsumeBytes<uint8_t>(dataBytesSize);
    data.WriteBuffer(dataBytes.data(), dataBytes.size());
    MessageParcel reply;
    size_t replyBytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> replyBytes = provider.ConsumeBytes<uint8_t>(replyBytesSize);
    reply.WriteBuffer(replyBytes.data(), replyBytes.size());
    MessageOption option;
    uint32_t code = 0;
    IPCObjectStub ipcObjectStub;
    for (int i = 0; i < codeList.size(); i++) {
        code = codeList[i];
        ipcObjectStub.SendRequest(code, data, reply, option);
    }
}

static void ProcessProtoFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<IPCObjectStubInterfaceMock> mockClient;
    EXPECT_CALL(mockClient, WriteUint32).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(mockClient, WriteString16).WillRepeatedly(testing::Return(false));
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.ProcessProto(code, data, reply, option);
}

static void GetGrantedSessionNameFuzzTest001(FuzzedDataProvider &provider)
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
    ipcObjectStub.GetGrantedSessionName(code, data, reply, option);
}

static void GetGrantedSessionNameFuzzTest002(FuzzedDataProvider &provider)
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
    ipcObjectStub.GetGrantedSessionName(code, data, reply, option);
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
    OHOS::DBinderPingTransactionFuzzTest(provider);
    OHOS::DBinderSearchDescriptorFuzzTest(provider);
    OHOS::DBinderDumpTransactionFuzzTest(provider);
    OHOS::DBinderInvokeListenThreadFuzzTest(provider);
    OHOS::DBinderIncRefsTransactionFuzzTest(provider);
    OHOS::DBinderDecRefsTransactionFuzzTest(provider);
    OHOS::DBinderAddCommAuthFuzzTest(provider);
    OHOS::DBinderGetSessionNameFuzzTest001(provider);
    OHOS::DBinderGetSessionNameFuzzTest002(provider);
    OHOS::DBinderGetSessionNameFuzzTest003(provider);
    OHOS::DBinderGetGrantedSessionNameFuzzTest(provider);
    OHOS::DBinderGetSessionNameForPidUidFuzzTest(provider);
    OHOS::DBinderGetPidUidFuzzTest001(provider);
    OHOS::DBinderGetPidUidFuzzTest002(provider);
    OHOS::DBinderRemoveSessionNameFuzzTest(provider);
    OHOS::SendRequestFuzzTest001(provider);
    OHOS::SendRequestFuzzTest002(provider);
    OHOS::ProcessProtoFuzzTest(provider);
    OHOS::GetGrantedSessionNameFuzzTest001(provider);
    OHOS::GetGrantedSessionNameFuzzTest002(provider);
    OHOS::GetSessionNameForPidUidFuzzTest001(provider);
    OHOS::GetSessionNameForPidUidFuzzTest002(provider);
    return 0;
}

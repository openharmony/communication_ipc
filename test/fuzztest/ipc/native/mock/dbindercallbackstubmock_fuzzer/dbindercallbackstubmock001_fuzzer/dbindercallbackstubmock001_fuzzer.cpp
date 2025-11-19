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

#include "dbindercallbackstubmock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class DBinderCallbackStubInterface {
public:
    DBinderCallbackStubInterface() {};
    virtual ~DBinderCallbackStubInterface() {};

    virtual int GetCallingUid() = 0;
    virtual sptr<IRemoteObject> GetSAMgrObject() = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual int SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) = 0;
};

class DBinderCallbackStubInterfaceMock : public DBinderCallbackStubInterface {
public:
    DBinderCallbackStubInterfaceMock();
    ~DBinderCallbackStubInterfaceMock() override;

    MOCK_METHOD(int, GetCallingUid, (), (override));
    MOCK_METHOD(sptr<IRemoteObject>, GetSAMgrObject, (), (override));
    MOCK_METHOD(bool, WriteUint32, (uint32_t value), (override));
    MOCK_METHOD(IRemoteInvoker *, GetRemoteInvoker, (int proto), (override));
    MOCK_METHOD(int, SendRequest, (int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option), (override));
};

static void *g_interface = nullptr;

DBinderCallbackStubInterfaceMock::DBinderCallbackStubInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DBinderCallbackStubInterfaceMock::~DBinderCallbackStubInterfaceMock()
{
    g_interface = nullptr;
}

static DBinderCallbackStubInterface *GetDBinderCallbackStubInterface()
{
    return reinterpret_cast<DBinderCallbackStubInterface *>(g_interface);
}

extern "C" {
int IPCSkeleton::GetCallingUid()
{
    if (g_interface == nullptr) {
        return -1;
    }
    return GetDBinderCallbackStubInterface()->GetCallingUid();
}

sptr<IRemoteObject> IPCProcessSkeleton::GetSAMgrObject()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetDBinderCallbackStubInterface()->GetSAMgrObject();
}

bool Parcel::WriteUint32(uint32_t value)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetDBinderCallbackStubInterface()->WriteUint32(value);
}

IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetDBinderCallbackStubInterface()->GetRemoteInvoker(proto);
}

int BinderInvoker::SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (g_interface == nullptr) {
        return -1;
    }
    return GetDBinderCallbackStubInterface()->SendRequest(handle, code, data, reply, option);
}
}

void ProcessProtoFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    EXPECT_CALL(mock, GetCallingUid()).WillRepeatedly(Return(-1));
    stub->ProcessProto(code, data, reply, option);

    EXPECT_CALL(mock, GetCallingUid()).WillRepeatedly(Return(0));
    EXPECT_CALL(mock, GetSAMgrObject()).WillRepeatedly(Return(nullptr));
    stub->ProcessProto(code, data, reply, option);
}

void ProcessDataFuzzTest001(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    int uid = provider.ConsumeIntegral<int>();
    int pid = provider.ConsumeIntegral<int>();
    std::string sessionName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    MessageParcel data;
    MessageParcel reply;
    stub->ProcessData(uid, pid, sessionName, data, reply);

    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    EXPECT_CALL(mock, WriteUint32(pid)).WillRepeatedly(Return(false));
    stub->ProcessData(uid, pid, sessionName, data, reply);
}

void ProcessDataFuzzTest002(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    std::string sessionName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    MessageParcel data;
    MessageParcel reply;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    EXPECT_CALL(mock, WriteUint32(_)).WillRepeatedly(Return(true));
    IRemoteInvoker *dbinderInvoker = new (std::nothrow) BinderInvoker();
    if (dbinderInvoker == nullptr) {
        return;
    }
    EXPECT_CALL(mock, GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS)).WillRepeatedly(Return(dbinderInvoker));
    EXPECT_CALL(mock, SendRequest(_, _, _, _, _)).WillRepeatedly(Return(ERR_NONE));
    int uid = provider.ConsumeIntegral<int>();
    int pid = provider.ConsumeIntegral<int>();
    stub->ProcessData(uid, pid, sessionName, data, reply);
    delete dbinderInvoker;
}

void OnRemoteRequestFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    stub->OnRemoteRequest(code, data, reply, option);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ProcessProtoFuzzTest(provider);
    OHOS::ProcessDataFuzzTest001(provider);
    OHOS::ProcessDataFuzzTest002(provider);
    OHOS::OnRemoteRequestFuzzTest(provider);
    return 0;
}

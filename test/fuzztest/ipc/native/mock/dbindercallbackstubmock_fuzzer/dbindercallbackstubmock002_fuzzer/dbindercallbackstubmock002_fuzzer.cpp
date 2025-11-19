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

    virtual bool WriteUint32(uint32_t value) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual int SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) = 0;
};

class DBinderCallbackStubInterfaceMock : public DBinderCallbackStubInterface {
public:
    DBinderCallbackStubInterfaceMock();
    ~DBinderCallbackStubInterfaceMock() override;

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

void MarshallingFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    MessageParcel parcel;
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    IRemoteInvoker *dbinderInvoker = new (std::nothrow) BinderInvoker();
    if (dbinderInvoker == nullptr) {
        return;
    }
    EXPECT_CALL(mock, GetRemoteInvoker(_)).WillRepeatedly(Return(dbinderInvoker));
    stub->Marshalling(parcel);
    stub->dbinderData_ = nullptr;
    stub->Marshalling(parcel);
    delete dbinderInvoker;
}

void AddDBinderCommAuthFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    pid_t pid = provider.ConsumeIntegral<pid_t>();
    uid_t uid = provider.ConsumeIntegral<uid_t>();
    std::string sessionName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    NiceMock<DBinderCallbackStubInterfaceMock> mock;
    EXPECT_CALL(mock, WriteUint32(_)).WillRepeatedly(Return(false));
    stub->AddDBinderCommAuth(pid, uid, sessionName);

    EXPECT_CALL(mock, WriteUint32(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRemoteInvoker(_)).WillRepeatedly(Return(nullptr));
    stub->AddDBinderCommAuth(pid, uid, sessionName);

    IRemoteInvoker *dbinderInvoker = new (std::nothrow) BinderInvoker();
    if (dbinderInvoker == nullptr) {
        return;
    }
    EXPECT_CALL(mock, GetRemoteInvoker(_)).WillRepeatedly(Return(dbinderInvoker));
    EXPECT_CALL(mock, SendRequest(_, _, _, _, _)).WillRepeatedly(Return(ERR_NONE));
    stub->AddDBinderCommAuth(pid, uid, sessionName);
    delete dbinderInvoker;
}

void GetAndSaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderCallbackStub> stub = CreateDBinderCallbackStub(provider);
    if (stub == nullptr) {
        return;
    }
    pid_t pid = provider.ConsumeIntegral<pid_t>();
    uid_t uid = provider.ConsumeIntegral<uid_t>();
    stub->GetAndSaveDBinderData(pid, uid);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::MarshallingFuzzTest(provider);
    OHOS::AddDBinderCommAuthFuzzTest(provider);
    OHOS::GetAndSaveDBinderDataFuzzTest(provider);
    return 0;
}

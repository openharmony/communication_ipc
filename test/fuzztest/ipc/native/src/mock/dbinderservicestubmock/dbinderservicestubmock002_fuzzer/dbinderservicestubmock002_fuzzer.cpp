/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dbinderservicestubmock_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "iremote_invoker.h"
#include "iremote_object.h"
#include "string_ex.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static constexpr uint32_t DBINDER_HANDLE_BASE = 100000 * 6872;
const static size_t MAX_STRING_PARAM_LEN = 100;

class DbinderServiceStub {
public:
    DbinderServiceStub() {};
    virtual ~DbinderServiceStub() {};

    virtual sptr<DBinderService> GetInstance() = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual bool FlattenObject(Parcel &parcel, const IRemoteObject *object) = 0;
    virtual bool FlattenDBinderData(Parcel &parcel, const dbinder_negotiation_data *&dbinderData) = 0;
    virtual sptr<IRemoteObject> ReadRemoteObject() = 0;
};

class DbinderServiceStubMock : public DbinderServiceStub {
public:
    DbinderServiceStubMock();
    ~DbinderServiceStubMock() override;
    
    MOCK_METHOD0(GetInstance, sptr<DBinderService>());
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
    MOCK_METHOD2(FlattenObject, bool(Parcel &parcel, const IRemoteObject *object));
    MOCK_METHOD2(FlattenDBinderData, bool(Parcel &parcel, const dbinder_negotiation_data *&dbinderData));
    MOCK_METHOD0(ReadRemoteObject, sptr<IRemoteObject>());
};

static void *g_interface = nullptr;

DbinderServiceStubMock::DbinderServiceStubMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DbinderServiceStubMock::~DbinderServiceStubMock()
{
    g_interface = nullptr;
}

static DbinderServiceStubMock *GetDbinderServiceStubMock()
{
    return reinterpret_cast<DbinderServiceStubMock *>(g_interface);
}

extern "C" {
    sptr<DBinderService> DBinderService::GetInstance()
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->GetInstance();
    }

    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->GetRemoteInvoker(proto);
    }

    bool BinderInvoker::FlattenObject(Parcel &parcel, const IRemoteObject *object) const
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->FlattenObject(parcel, object);
    }

    bool ProcessSkeleton::FlattenDBinderData(Parcel &parcel, const dbinder_negotiation_data *&dbinderData)
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->FlattenDBinderData(parcel, dbinderData);
    }

    sptr<IRemoteObject> MessageParcel::ReadRemoteObject()
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->ReadRemoteObject();
    }
}

void MarshallingFuzzTest001(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    Parcel parcel;
    dBinderServiceStub.Marshalling(parcel, nullptr);

    NiceMock<DbinderServiceStubMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker).WillOnce(Return(nullptr));
    dBinderServiceStub.Marshalling(parcel);

    dBinderServiceStub.dbinderData_ = nullptr;
    dBinderServiceStub.Marshalling(parcel);
}

void MarshallingFuzzTest002(FuzzedDataProvider &provider)
{
    Parcel parcel;
    NiceMock<DbinderServiceStubMock> mock;
    BinderInvoker* invoker = new (std::nothrow) BinderInvoker();
    if (invoker == nullptr) {
        return;
    }
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(mock, FlattenDBinderData).WillOnce(Return(false));
    dBinderServiceStub.Marshalling(parcel);

    EXPECT_CALL(mock, FlattenDBinderData).WillOnce(Return(true));
    EXPECT_CALL(mock, FlattenObject).WillOnce(Return(false));
    dBinderServiceStub.Marshalling(parcel);
    delete invoker;
}

void RemoveDbinderDeathRecipientFuzzTest(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint32_t handle = provider.ConsumeIntegralInRange<uint32_t>(1, DBINDER_HANDLE_BASE);
    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(handle, Str8ToStr16(descriptor));
    if (callbackProxy == nullptr) {
        return;
    }
    callbackProxy->SetObjectDied(false);
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    MessageParcel dataOne;
    NiceMock<DbinderServiceStubMock> mock;
    EXPECT_CALL(mock, ReadRemoteObject).WillRepeatedly(testing::Return(callbackProxy));
    EXPECT_CALL(mock, GetInstance).WillOnce(Return(nullptr));
    dBinderServiceStub.RemoveDbinderDeathRecipient(dataOne);
}

void AddDbinderDeathRecipientFuzzTest(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    uint32_t handle = provider.ConsumeIntegralInRange<uint32_t>(1, DBINDER_HANDLE_BASE);
    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(handle, Str8ToStr16(descriptor));
    if (callbackProxy == nullptr) {
        return;
    }
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    MessageParcel dataOne;
    NiceMock<DbinderServiceStubMock> mock;
    callbackProxy->SetObjectDied(true);
    EXPECT_CALL(mock, ReadRemoteObject).WillOnce(Return(callbackProxy));
    dBinderServiceStub.AddDbinderDeathRecipient(dataOne);

    callbackProxy->SetObjectDied(false);
    EXPECT_CALL(mock, ReadRemoteObject).WillOnce(Return(callbackProxy));
    EXPECT_CALL(mock, GetInstance).WillOnce(Return(nullptr));
    dBinderServiceStub.AddDbinderDeathRecipient(dataOne);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::MarshallingFuzzTest001(provider);
    OHOS::MarshallingFuzzTest002(provider);
    OHOS::RemoveDbinderDeathRecipientFuzzTest(provider);
    OHOS::AddDbinderDeathRecipientFuzzTest(provider);

    return 0;
}

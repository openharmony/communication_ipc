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

    virtual bool IsLocalCalling() = 0;
    virtual sptr<DBinderService> GetInstance() = 0;
    virtual pid_t GetCallingPid() = 0;
    virtual pid_t GetCallingUid() = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual bool WriteUint64(uint64_t value) = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual bool WriteString16(const std::u16string &value) = 0;
    virtual std::string CreateDatabusName(int uid, int pid) = 0;
    virtual bool CheckSessionObjectValidity() = 0;
};

class DbinderServiceStubMock : public DbinderServiceStub {
public:
    DbinderServiceStubMock();
    ~DbinderServiceStubMock() override;
    
    MOCK_METHOD0(IsLocalCalling, bool());
    MOCK_METHOD0(GetInstance, sptr<DBinderService>());
    MOCK_METHOD0(GetCallingPid, pid_t());
    MOCK_METHOD0(GetCallingUid, pid_t());
    MOCK_METHOD1(WriteUint32, bool(uint32_t value));
    MOCK_METHOD1(WriteUint64, bool(uint64_t value));
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD1(WriteString16, bool(const std::u16string &value));
    MOCK_METHOD2(CreateDatabusName, std::string(int uid, int pid));
    MOCK_METHOD0(CheckSessionObjectValidity, bool());
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
    bool IPCSkeleton::IsLocalCalling()
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->IsLocalCalling();
    }

    sptr<DBinderService> DBinderService::GetInstance()
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->GetInstance();
    }

    pid_t IPCSkeleton::GetCallingUid()
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return -1;
        }
        return interface->GetCallingUid();
    }

    pid_t IPCSkeleton::GetCallingPid()
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return -1;
        }
        return interface->GetCallingPid();
    }

    bool Parcel::WriteUint32(uint32_t value)
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteUint32(value);
    }
    bool Parcel::WriteUint64(uint64_t value)
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteUint64(value);
    }
    bool Parcel::WriteString(const std::string &value)
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteString(value);
    }
    bool Parcel::WriteString16(const std::u16string &value)
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteString16(value);
    }

    std::string DBinderService::CreateDatabusName(int uid, int pid)
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return "";
        }
        return interface->CreateDatabusName(uid, pid);
    }

    bool DBinderServiceStub::CheckSessionObjectValidity()
    {
        DbinderServiceStubMock* interface = GetDbinderServiceStubMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->CheckSessionObjectValidity();
    }
}

void DBinderClearServiceStateFuzzTest(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DbinderServiceStubMock> mock;
    EXPECT_CALL(mock, IsLocalCalling).WillOnce(Return(false));
    dBinderServiceStub.DBinderClearServiceState(code, data, reply, option);
}

void GetAndSaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = new (std::nothrow) DBinderService();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    pid_t uid = provider.ConsumeIntegralInRange<uint32_t>(1, DBINDER_HANDLE_BASE);
    uid_t pid = provider.ConsumeIntegralInRange<uint32_t>(1, DBINDER_HANDLE_BASE);
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);
    NiceMock<DbinderServiceStubMock> mock;
    EXPECT_CALL(mock, CheckSessionObjectValidity).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, GetInstance).WillOnce(Return(nullptr));
    dBinderServiceStub.GetAndSaveDBinderData(pid, uid);

    EXPECT_CALL(mock, GetInstance).WillRepeatedly(testing::Return(dBinderService));
    EXPECT_CALL(mock, CreateDatabusName).WillOnce(Return(""));
    dBinderServiceStub.GetAndSaveDBinderData(pid, uid);

    EXPECT_CALL(mock, CreateDatabusName).WillOnce(Return("DatabusName"));
    dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
}

void SaveDBinderDataFuzzTest(FuzzedDataProvider &provider)
{
    std::string localBusName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    NiceMock<DbinderServiceStubMock> mock;
    EXPECT_CALL(mock, GetInstance).WillOnce(Return(nullptr));
    dBinderServiceStub.SaveDBinderData(localBusName);

    sptr<DBinderService> dBinderService = new (std::nothrow) DBinderService();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    sessionInfo->type = provider.ConsumeIntegral<uint32_t>();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);
    EXPECT_CALL(mock, GetInstance).WillOnce(Return(dBinderService));
    dBinderServiceStub.dbinderData_ = nullptr;
    dBinderServiceStub.SaveDBinderData(localBusName);
}

void ProcessProtoFuzzTest001(FuzzedDataProvider &provider)
{
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DbinderServiceStubMock> mock;
    EXPECT_CALL(mock, GetInstance).WillOnce(Return(nullptr));
    dBinderServiceStub.ProcessProto(code, data, reply, option);

    sptr<DBinderService> dBinderService = new (std::nothrow) DBinderService();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    sessionInfo->type = provider.ConsumeIntegral<uint32_t>();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);
    EXPECT_CALL(mock, GetInstance).WillOnce(Return(dBinderService));
    EXPECT_CALL(mock, GetCallingUid).WillOnce(Return(-1));
    EXPECT_CALL(mock, GetCallingPid).WillOnce(Return(-1));
    dBinderServiceStub.ProcessProto(code, data, reply, option);

    EXPECT_CALL(mock, GetInstance).WillOnce(Return(dBinderService));
    EXPECT_CALL(mock, GetCallingUid).WillOnce(Return(1));
    EXPECT_CALL(mock, GetCallingPid).WillOnce(Return(1));
    EXPECT_CALL(mock, CreateDatabusName).WillOnce(Return("DatabusName"));
    dBinderServiceStub.ProcessProto(code, data, reply, option);
}

void ProcessProtoFuzzTest002(FuzzedDataProvider &provider)
{
    sptr<DBinderService> dBinderService = new (std::nothrow) DBinderService();
    if (dBinderService == nullptr) {
        return;
    }
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    if (sessionInfo == nullptr) {
        return;
    }
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    const std::string service = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    const std::string device = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    binder_uintptr_t object = provider.ConsumeIntegral<uint64_t>();
    DBinderServiceStub dBinderServiceStub(Str8ToStr16(service), device, object);
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DbinderServiceStubMock> mock;
    EXPECT_CALL(mock, GetInstance).WillRepeatedly(testing::Return(dBinderService));
    EXPECT_CALL(mock, GetCallingUid).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, GetCallingPid).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, CreateDatabusName).WillRepeatedly(testing::Return("DatabusName"));
    EXPECT_CALL(mock, WriteUint32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteUint64).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteString).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteString16).WillOnce(Return(false));
    dBinderServiceStub.ProcessProto(code, data, reply, option);

    EXPECT_CALL(mock, WriteString16).WillOnce(Return(true));
    dBinderServiceStub.ProcessProto(code, data, reply, option);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DBinderClearServiceStateFuzzTest(provider);
    OHOS::GetAndSaveDBinderDataFuzzTest(provider);
    OHOS::SaveDBinderDataFuzzTest(provider);
    OHOS::ProcessProtoFuzzTest001(provider);
    OHOS::ProcessProtoFuzzTest002(provider);
    return 0;
}

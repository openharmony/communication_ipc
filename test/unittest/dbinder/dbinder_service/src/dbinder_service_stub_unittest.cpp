/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "iremote_object.h"
#include "mock_iremote_invoker.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

namespace {
    constexpr binder_uintptr_t BINDER_OBJECT = 11;
    constexpr uint32_t PROCESS_PROTO_CODE = 11;
    constexpr uint32_t SESSION_TYPE_UNKNOWN = 99;
    constexpr int32_t UNKNOWN_TRANSACTION_CODE = 999;
    const std::u16string SERVICE_TEST = u"serviceTest";
    const std::string DEVICE_TEST = "deviceTest";
    const std::string LOCAL_BUS_NAME_TEST = "localBusNameTest";
    const std::u16string DESCRIPTOR_TEST = u"localBusNameTest";
    const pid_t VALID_PID_TEST = 1234;
    const uid_t VALID_UID_TEST = 1001;
    const pid_t INVALID_PID_TEST = -1;
    const uid_t INVALID_UID_TEST = -1;
    const uint32_t TEST_SEQ_NUM = 1;
}

class DBinderServiceStubInterface {
public:
    DBinderServiceStubInterface() {};
    virtual ~DBinderServiceStubInterface() {};

    virtual std::string CreateDatabusName(int uid, int pid) = 0;
    virtual bool WriteUint32(uint32_t value) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual bool FlattenDBinderData(Parcel &parcel, const dbinder_negotiation_data *&dbinderData) = 0;
    virtual pid_t GetCallingPid() = 0;
    virtual pid_t GetCallingUid() = 0;
    virtual bool WriteUint64(uint64_t value) = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual bool WriteString16(const std::u16string &value) = 0;
};
class DBinderServiceStubInterfaceMock : public DBinderServiceStubInterface {
public:
    DBinderServiceStubInterfaceMock();
    ~DBinderServiceStubInterfaceMock() override;

    MOCK_METHOD2(CreateDatabusName, std::string(int uid, int pid));
    MOCK_METHOD1(WriteUint32, bool(uint32_t value));
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
    MOCK_METHOD2(FlattenDBinderData, bool(Parcel &parcel, const dbinder_negotiation_data *&dbinderData));
    MOCK_METHOD0(GetCallingPid, pid_t());
    MOCK_METHOD0(GetCallingUid, pid_t());
    MOCK_METHOD1(WriteUint64, bool(uint64_t value));
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD1(WriteString16, bool(const std::u16string &value));
};

static void *g_interface = nullptr;

DBinderServiceStubInterfaceMock::DBinderServiceStubInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DBinderServiceStubInterfaceMock::~DBinderServiceStubInterfaceMock()
{
    g_interface = nullptr;
}

static DBinderServiceStubInterface *GetDBinderServiceStubInterface()
{
    return reinterpret_cast<DBinderServiceStubInterfaceMock *>(g_interface);
}

extern "C" {
    std::string DBinderService::CreateDatabusName(int uid, int pid)
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return "";
        }
        return GetDBinderServiceStubInterface()->CreateDatabusName(uid, pid);
    }
    bool Parcel::WriteUint32(uint32_t value)
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return false;
        }
        return GetDBinderServiceStubInterface()->WriteUint32(value);
    }
    bool Parcel::WriteUint64(uint64_t value)
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return false;
        }
        return GetDBinderServiceStubInterface()->WriteUint64(value);
    }
    bool Parcel::WriteString(const std::string &value)
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return false;
        }
        return GetDBinderServiceStubInterface()->WriteString(value);
    }
    bool Parcel::WriteString16(const std::u16string &value)
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return false;
        }
        return GetDBinderServiceStubInterface()->WriteString16(value);
    }
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return nullptr;
        }
        return GetDBinderServiceStubInterface()->GetRemoteInvoker(proto);
    }
    bool ProcessSkeleton::FlattenDBinderData(Parcel &parcel, const dbinder_negotiation_data *&dbinderData)
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return false;
        }
        return GetDBinderServiceStubInterface()->FlattenDBinderData(parcel, dbinderData);
    }
    pid_t IPCSkeleton::GetCallingUid()
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return 0;
        }
        return GetDBinderServiceStubInterface()->GetCallingUid();
    }
    pid_t IPCSkeleton::GetCallingPid()
    {
        if (GetDBinderServiceStubInterface() == nullptr) {
            return 0;
        }
        return GetDBinderServiceStubInterface()->GetCallingPid();
    }
}

class DBinderServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DBinderServiceStubTest::SetUpTestCase()
{
}

void DBinderServiceStubTest::TearDownTestCase()
{
}

void DBinderServiceStubTest::SetUp()
{
}

void DBinderServiceStubTest::TearDown()
{
}

/**
 * @tc.name: DBinderServiceStubTest001
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, DBinderServiceStubTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    int32_t num = dBinderServiceStub.GetObjectRefCount();
    EXPECT_NE(num, 0);
}

/**
 * @tc.name: DBinderServiceStubTest002
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, DBinderServiceStubTest002, TestSize.Level1)
{
    const std::u16string service = u"";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    int32_t num = dBinderServiceStub.GetObjectRefCount();
    EXPECT_NE(num, 0);
}

/**
 * @tc.name: DBinderServiceStubTest003
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, DBinderServiceStubTest003, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    int32_t num = dBinderServiceStub.GetObjectRefCount();
    EXPECT_NE(num, 0);
}

/**
 * @tc.name: DBinderServiceStubTest004
 * @tc.desc: Verify the DBinderServiceStub function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, DBinderServiceStubTest004, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = UINT_MAX;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    int32_t num = dBinderServiceStub.GetObjectRefCount();
    EXPECT_NE(num, 0);
}


/**
 * @tc.name: GetServiceNameTest001
 * @tc.desc: Verify the GetServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetServiceNameTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::u16string ret = dBinderServiceStub.GetServiceName();
    EXPECT_EQ(ret, u"serviceTest");
}

/**
 * @tc.name: GetServiceNameTest002
 * @tc.desc: Verify the GetServiceName function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetServiceNameTest002, TestSize.Level1)
{
    const std::u16string service;
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::u16string ret = dBinderServiceStub.GetServiceName();
    EXPECT_EQ(ret, u"");
}

/**
 * @tc.name: GetDeviceIDTest001
 * @tc.desc: Verify the GetDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetDeviceIDTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::string ret = dBinderServiceStub.GetDeviceID();
    EXPECT_EQ(ret, "deviceTest");
}

/**
 * @tc.name: GetDeviceIDTest002
 * @tc.desc: Verify the GetDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetDeviceIDTest002, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device;
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    std::string ret = dBinderServiceStub.GetDeviceID();
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: GetBinderObject001
 * @tc.desc: Verify the GetBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetBinderObject001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    binder_uintptr_t ret = dBinderServiceStub.GetBinderObject();
    EXPECT_EQ(ret, BINDER_OBJECT);
}

/**
 * @tc.name: GetBinderObject002
 * @tc.desc: Verify the GetBinderObject function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetBinderObject002, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = UINT_MAX;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    binder_uintptr_t ret = dBinderServiceStub.GetBinderObject();
    EXPECT_EQ(ret, UINT_MAX);
}

/**
 * @tc.name: ProcessProtoTest001
 * @tc.desc: Verify the ProcessProto function when QuerySessionObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest001, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    dBinderService->sessionObject_.clear();

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest002
 * @tc.desc: Verify the ProcessProto function when GetCallingUid function return -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest002, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(INVALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest003
 * @tc.desc: Verify the ProcessProto function when GetCallingPid function return -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest003, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(INVALID_PID_TEST));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest004
 * @tc.desc: Verify the ProcessProto function when CreateDatabusName function return empty
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest004, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(""));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest005
 * @tc.desc: Verify the ProcessProto function when sessionInfo->type is IRemoteObject::IF_PROT_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest005, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::IF_PROT_ERROR;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(LOCAL_BUS_NAME_TEST));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest006
 * @tc.desc: Verify the ProcessProto function when WriteUint32 function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest006, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(LOCAL_BUS_NAME_TEST));
    EXPECT_CALL(mockServiceStub, WriteUint32).WillRepeatedly(Return(false));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest007
 * @tc.desc: Verify the ProcessProto function when WriteUint64 function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest007, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(LOCAL_BUS_NAME_TEST));
    EXPECT_CALL(mockServiceStub, WriteUint32).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteUint64).WillRepeatedly(Return(false));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest008
 * @tc.desc: Verify the ProcessProto function when WriteString function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest008, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(LOCAL_BUS_NAME_TEST));
    EXPECT_CALL(mockServiceStub, WriteUint32).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteUint64).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteString).WillRepeatedly(Return(false));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest09
 * @tc.desc: Verify the ProcessProto function when WriteString16 function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest09, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(LOCAL_BUS_NAME_TEST));
    EXPECT_CALL(mockServiceStub, WriteUint32).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteUint64).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteString).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteString16).WillRepeatedly(Return(false));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest010
 * @tc.desc: Verify the ProcessProto function when WriteString16 function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest010, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(LOCAL_BUS_NAME_TEST));
    EXPECT_CALL(mockServiceStub, WriteUint32).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteUint64).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteString).WillRepeatedly(Return(true));
    EXPECT_CALL(mockServiceStub, WriteString16).WillRepeatedly(Return(true));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: ProcessProtoTest011
 * @tc.desc: Verify the ProcessProto function when code is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest011, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    uint32_t code = UINT_MAX;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.ProcessProto(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: OnRemoteRequestTest001
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, OnRemoteRequestTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    uint32_t code = GET_PROTO_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: OnRemoteRequestTest002
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, OnRemoteRequestTest002, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    uint32_t code = DBINDER_OBITUARY_TRANSACTION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnRemoteRequestTest003
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, OnRemoteRequestTest003, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    uint32_t code = PROCESS_PROTO_CODE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = dBinderServiceStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: ProcessDeathRecipientTest001
 * @tc.desc: Verify the ProcessDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessDeathRecipientTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    data.WriteInt32(IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT);
    int32_t ret = dBinderServiceStub.ProcessDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: ProcessDeathRecipientTest002
 * @tc.desc: Verify the ProcessDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessDeathRecipientTest002, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    data.WriteInt32(IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT);
    int32_t ret = dBinderServiceStub.ProcessDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: ProcessDeathRecipientTest003
 * @tc.desc: Verify the ProcessDeathRecipient function with unknown type
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessDeathRecipientTest003, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    data.WriteInt32(UNKNOWN_TRANSACTION_CODE);

    int32_t ret = dBinderServiceStub.ProcessDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: ProcessDeathRecipientTest004
 * @tc.desc: Verify the ProcessDeathRecipient function with unknown type
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessDeathRecipientTest004, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    data.WriteString("");

    int32_t ret = dBinderServiceStub.ProcessDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest001
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, AddDbinderDeathRecipientTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);
    MessageParcel data;
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_INVALID_DATA_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest002
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, AddDbinderDeathRecipientTest002, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    data.WriteString("");
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_ADD_DEATH_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest003
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, AddDbinderDeathRecipientTest003, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    data.WriteString("test");
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_ADD_DEATH_ERR);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest004
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, AddDbinderDeathRecipientTest004, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    data.WriteString("test");
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest005
 * @tc.desc: Verify the AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, AddDbinderDeathRecipientTest005, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    data.WriteString("");
    int32_t ret = dBinderServiceStub.AddDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_ADD_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest001
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, RemoveDbinderDeathRecipientTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    MessageParcel data;
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest002
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, RemoveDbinderDeathRecipientTest002, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    data.WriteString("test");
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest003
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, RemoveDbinderDeathRecipientTest003, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectProxy> callbackProxy = new (std::nothrow) IPCObjectProxy(0);
    EXPECT_TRUE(callbackProxy != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackProxy);
    data.WriteString("");
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest004
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, RemoveDbinderDeathRecipientTest004, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    data.WriteString("test");
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest005
 * @tc.desc: Verify the RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, RemoveDbinderDeathRecipientTest005, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"testStub");
    EXPECT_TRUE(callbackStub != nullptr);
    MessageParcel data;
    data.WriteRemoteObject(callbackStub);
    data.WriteString("");
    int32_t ret = dBinderServiceStub.RemoveDbinderDeathRecipient(data);
    EXPECT_EQ(ret, DBINDER_SERVICE_REMOVE_DEATH_ERR);
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Verify the Marshalling function when dbinderData_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, MarshallingTest001, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dBinderServiceStub.dbinderData_ = nullptr;

    Parcel parcel;
    bool result = dBinderServiceStub.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Verify the Marshalling function when GetRemoteInvoker function nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, MarshallingTest002, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dBinderServiceStub.dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    Parcel parcel;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;

    EXPECT_CALL(mockServiceStub, GetRemoteInvoker).WillOnce(testing::Return(nullptr));
    
    bool result = dBinderServiceStub.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest003
 * @tc.desc: Verify the Marshalling function when function FlattenDBinderData return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, MarshallingTest003, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dBinderServiceStub.dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    Parcel parcel;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    
    EXPECT_CALL(mockServiceStub, GetRemoteInvoker).WillOnce(testing::Return(invoker));
    EXPECT_CALL(mockServiceStub, FlattenDBinderData).WillRepeatedly(testing::Return(false));

    bool result = dBinderServiceStub.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest004
 * @tc.desc: Verify the Marshalling function when FlattenObject function return false
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, MarshallingTest004, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dBinderServiceStub.dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    Parcel parcel;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mockServiceStub, GetRemoteInvoker).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(mockServiceStub, FlattenDBinderData).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*invoker, FlattenObject).WillRepeatedly(testing::Return(false));

    bool result = dBinderServiceStub.Marshalling(parcel);
    EXPECT_FALSE(result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest005
 * @tc.desc: Verify the Marshalling function when dbinderData_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, MarshallingTest005, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dBinderServiceStub.dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    Parcel parcel;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mockServiceStub, GetRemoteInvoker).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(mockServiceStub, FlattenDBinderData).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*invoker, FlattenObject).WillRepeatedly(testing::Return(true));

    bool result = dBinderServiceStub.Marshalling(parcel);
    EXPECT_TRUE(result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: MarshallingTest006
 * @tc.desc: Verify the Marshalling function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, MarshallingTest006, TestSize.Level1)
{
    sptr<IRemoteObject> nullObject = nullptr;
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    Parcel parcel;
    bool result = dBinderServiceStub.Marshalling(parcel, nullObject);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingTest007
 * @tc.desc: Verify the Marshalling function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, MarshallingTest007, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    const std::u16string service2 = u"serviceTest2";
    const std::string device2 = "deviceTest2";
    sptr<IRemoteObject> stubObject = new DBinderServiceStub(service2, device2, object);
    EXPECT_TRUE(stubObject != nullptr);
    Parcel parcel;
    bool result = dBinderServiceStub.Marshalling(parcel, stubObject);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MarshallingTest008
 * @tc.desc: Verify the Marshalling function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, MarshallingTest008, TestSize.Level1)
{
    const std::u16string service1 = u"serviceTest1";
    const std::string device1 = "deviceTest1";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub1(service1, device1, object);

    const std::u16string service2 = u"serviceTest2";
    const std::string device2 = "deviceTest2";
    DBinderServiceStub* dBinderServiceStub2 =  new DBinderServiceStub(service2, device2, object);
    dBinderServiceStub2->dbinderData_ = nullptr;
    sptr<IRemoteObject> stubObject = dBinderServiceStub2;

    Parcel parcel;
    bool result = dBinderServiceStub1.Marshalling(parcel, stubObject);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SaveDBinderDataTest001
 * @tc.desc: Verify the SaveDBinderData function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, SaveDBinderDataTest001, TestSize.Level1)
{
    DBinderService::GetInstance()->instance_ = nullptr;
    const std::u16string service1 = u"serviceTest1";
    const std::string device1 = "deviceTest1";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dbinderServiceStub(service1, device1, object);
    std::string localBusName = "localBusName";
    int ret = dbinderServiceStub.SaveDBinderData(localBusName);
    ASSERT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: SaveDBinderDataTest002
 * @tc.desc: Verify the SaveDBinderData function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, SaveDBinderDataTest002, TestSize.Level1)
{
    const std::u16string service1 = u"serviceTest1";
    const std::string device1 = "deviceTest1";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dbinderServiceStub(service1, device1, object);
    std::string localBusName = "localBusName";
    dbinderServiceStub.dbinderData_ = std::make_unique<uint8_t[]>(sizeof(DBinderNegotiationData));
    ASSERT_NE(dbinderServiceStub.dbinderData_, nullptr);
    int ret = dbinderServiceStub.SaveDBinderData(localBusName);
    ASSERT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: SaveDBinderDataTest003
 * @tc.desc: Verify the SaveDBinderData function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, SaveDBinderDataTest003, TestSize.Level1)
{
    const std::u16string service1 = u"serviceTest1";
    const std::string device1 = "deviceTest1";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dbinderServiceStub(service1, device1, object);
    binder_uintptr_t objectAddress = reinterpret_cast<binder_uintptr_t>(&dbinderServiceStub);
    std::string localBusName = "localBusName";
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<SessionInfo> sessionInfo = std::make_shared<SessionInfo>();
    EXPECT_TRUE(sessionInfo != nullptr);
    sessionInfo->type = SESSION_TYPE_UNKNOWN;
    bool isInitialized = dBinderService->AttachSessionObject(sessionInfo, objectAddress);
    ASSERT_TRUE(isInitialized);
    dbinderServiceStub.dbinderData_ = nullptr;
    int ret = dbinderServiceStub.SaveDBinderData(localBusName);
    ASSERT_EQ(ret, DBINDER_SERVICE_MALLOC_ERR);
    bool result = dBinderService->DetachSessionObject(objectAddress);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: SaveDBinderDataTest004
 * @tc.desc: Verify the SaveDBinderData function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, SaveDBinderDataTest004, TestSize.Level1)
{
    const std::u16string service1 = u"serviceTest1";
    const std::string device1 = "deviceTest1";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dbinderServiceStub(service1, device1, object);
    std::string localBusName = "localBusName";
    dbinderServiceStub.dbinderData_ = std::make_unique<uint8_t[]>(sizeof(DBinderNegotiationData));
    ASSERT_NE(dbinderServiceStub.dbinderData_, nullptr);
    DBinderNegotiationData data;
    data.stubIndex = 1;
    data.peerTokenId = 1;
    data.peerServiceName = "target_name";
    data.peerDeviceId = "target_device";
    data.localDeviceId = "local_device";
    data.localServiceName = "local_name";
    memcpy_s(dbinderServiceStub.dbinderData_.get(), sizeof(DBinderNegotiationData),
        &data, sizeof(DBinderNegotiationData));
    int ret = dbinderServiceStub.SaveDBinderData(localBusName);
    ASSERT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: SaveDBinderDataTest005
 * @tc.desc: Verify the SaveDBinderData function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, SaveDBinderDataTest005, TestSize.Level1)
{
    const std::u16string service1 = u"serviceTest1";
    const std::string device1 = "deviceTest1";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dbinderServiceStub(service1, device1, object);
    binder_uintptr_t objectAddress = reinterpret_cast<binder_uintptr_t>(&dbinderServiceStub);
    std::string localBusName = "localBusName";
    dbinderServiceStub.dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    ASSERT_NE(dbinderServiceStub.dbinderData_, nullptr);
    dbinder_negotiation_data *dbinderData = reinterpret_cast<dbinder_negotiation_data *>(
        dbinderServiceStub.dbinderData_.get());
    dbinderData->stub_index = 1;
    dbinderData->tokenid = 1;
    auto ret = strcpy_s(dbinderData->target_name, SESSION_NAME_LENGTH, "target_name");
    ret += strcpy_s(dbinderData->target_device, OHOS::DEVICEID_LENGTH, "target_device");
    ret += strcpy_s(dbinderData->local_device, OHOS::DEVICEID_LENGTH, "local_device");
    ret += strcpy_s(dbinderData->local_name, SESSION_NAME_LENGTH, "local_name");
    ASSERT_EQ(ret, EOK);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    std::shared_ptr<SessionInfo> sessionInfo = std::make_shared<SessionInfo>();
    EXPECT_TRUE(sessionInfo != nullptr);
    sessionInfo->type = SESSION_TYPE_UNKNOWN;
    bool isInitialized = dBinderService->AttachSessionObject(sessionInfo, objectAddress);
    ASSERT_TRUE(isInitialized);
    ret = dbinderServiceStub.SaveDBinderData(localBusName);
    ASSERT_EQ(ret, ERR_NONE);
    bool result = dBinderService->DetachSessionObject(objectAddress);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: CheckSessionObjectValidityTest001
 * @tc.desc: Verify the CheckSessionObjectValidity function when GetInstance function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, CheckSessionObjectValidityTest001, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    dBinderService->sessionObject_.clear();

    bool result = dBinderServiceStub.CheckSessionObjectValidity();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckSessionObjectValidityTest002
 * @tc.desc: Verify the CheckSessionObjectValidity function when QuerySessionObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, CheckSessionObjectValidityTest002, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::IF_PROT_ERROR;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    bool result = dBinderServiceStub.CheckSessionObjectValidity();
    EXPECT_FALSE(result);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: CheckSessionObjectValidityTest003
 * @tc.desc: Verify the CheckSessionObjectValidity function when sessionInfo->type is IRemoteObject::IF_PROT_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, CheckSessionObjectValidityTest003, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    bool result = dBinderServiceStub.CheckSessionObjectValidity();
    EXPECT_TRUE(result);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest001
 * @tc.desc: Verify the GetAndSaveDBinderData function pid is -1 and uid is -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderDataTest001, TestSize.Level1)
{
    const std::u16string service = u"serviceTest";
    const std::string device = "deviceTest";
    binder_uintptr_t object = BINDER_OBJECT;
    DBinderServiceStub dBinderServiceStub(service, device, object);

    pid_t pid = INVALID_PID_TEST;
    uid_t uid = INVALID_UID_TEST;

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest002
 * @tc.desc: Verify the GetAndSaveDBinderData function when pid is -1 and uid is 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderDataTest002, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = INVALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest003
 * @tc.desc: Verify the GetAndSaveDBinderData function when pid is 1 and uid is -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderDataTest003, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = VALID_PID_TEST;
    uid_t uid = INVALID_UID_TEST;

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest004
 * @tc.desc: Verify the GetAndSaveDBinderData function when pid and uid are valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderDataTest004, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = VALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    dBinderService->sessionObject_.clear();

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest005
 * @tc.desc: Verify the GetAndSaveDBinderData function when CreateDatabusName function return ""
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderDataTest005, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = VALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(testing::Return(""));

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest006
 * @tc.desc: Verify the GetAndSaveDBinderData function when return DBINDER_SERVICE_MALLOC_ERR
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderDataTest006, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dBinderServiceStub.dbinderData_ = nullptr;
    pid_t pid = VALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(testing::Return(LOCAL_BUS_NAME_TEST));

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_MALLOC_ERR);
    dBinderService->DetachSessionObject(stub);
}

/**
 * @tc.name: GetAndSaveDBinderDataTest007
 * @tc.desc: Verify the GetAndSaveDBinderData function when return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderDataTest007, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dBinderServiceStub.dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
    pid_t pid = VALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    binder_uintptr_t stub = reinterpret_cast<binder_uintptr_t>(&dBinderServiceStub);
    dBinderService->AttachSessionObject(sessionInfo, stub);

    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(testing::Return(LOCAL_BUS_NAME_TEST));

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, ERR_NONE);
    dBinderService->DetachSessionObject(stub);
    dBinderServiceStub.dbinderData_ = nullptr;;
}

/**
 * @tc.name: GetPeerPidTest001
 * @tc.desc: Verify the GetPeerPid function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetPeerPidTest001, TestSize.Level1)
{
    DBinderServiceStub dbinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    EXPECT_EQ(dbinderServiceStub.GetPeerPid(), 0);

    DBinderServiceStub dbinderServiceStub2(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT, VALID_PID_TEST, VALID_UID_TEST);
    EXPECT_EQ(dbinderServiceStub2.GetPeerPid(), VALID_PID_TEST);
}

/**
 * @tc.name: GetPeerUidTest001
 * @tc.desc: Verify the GetPeerUid function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetPeerUidTest001, TestSize.Level1)
{
    DBinderServiceStub dbinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    EXPECT_EQ(dbinderServiceStub.GetPeerUid(), 0);

    DBinderServiceStub dbinderServiceStub2(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT, VALID_PID_TEST, VALID_UID_TEST);
    EXPECT_EQ(dbinderServiceStub2.GetPeerUid(), VALID_UID_TEST);
}

/**
 * @tc.name: SetSeqNumberTest001
 * @tc.desc: Verify the SetSeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, SetSeqNumberTest001, TestSize.Level1)
{
    DBinderServiceStub dbinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dbinderServiceStub.SetSeqNumber(TEST_SEQ_NUM);
    EXPECT_EQ(dbinderServiceStub.GetSeqNumber(), TEST_SEQ_NUM);
}

/**
 * @tc.name: SetNegoStatusAndTimeTest001
 * @tc.desc: Verify the SetNegoStatusAndTime function
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, SetNegoStatusAndTimeTest001, TestSize.Level1)
{
    DBinderServiceStub dbinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    dbinderServiceStub.SetNegoStatusAndTime(NegotiationStatus::NEGO_DOING, 1);

    NegotiationStatus status = NegotiationStatus::NEGO_INIT;
    uint64_t time = 0;
    dbinderServiceStub.GetNegoStatusAndTime(status, time);
    EXPECT_EQ(status, NegotiationStatus::NEGO_DOING);
    EXPECT_EQ(time, 1);
}
} // namespace OHOS
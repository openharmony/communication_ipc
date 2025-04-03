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
    const std::string SERVICE_TEST = "serviceTest";
    const std::string DEVICE_TEST = "deviceTest";
    const std::string LOCAL_BUS_NAME_TEST = "localBusNameTest";
    const std::u16string DESCRIPTOR_TEST = u"localBusNameTest";
    const pid_t VALID_PID_TEST = 1234;
    const uid_t VALID_UID_TEST = 1001;
    const pid_t INVALID_PID_TEST = -1;
    const uid_t INVALID_UID_TEST = -1;
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

class MockDBinderService : public DBinderService {
public:
    MOCK_METHOD1(QuerySessionObject, std::shared_ptr<struct SessionInfo>(binder_uintptr_t stub));
    MOCK_METHOD0(GetInstance, sptr<DBinderService>());
};

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
 * @tc.name: ProcessProtoTest001
 * @tc.desc: Verify the ProcessProto function when GetInstance function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest001, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<MockDBinderService> mockService;

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(testing::Return(nullptr));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest002
 * @tc.desc: Verify the ProcessProto function when QuerySessionObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest002, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<MockDBinderService> mockService;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(Return(nullptr));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest003
 * @tc.desc: Verify the ProcessProto function when GetCallingUid function return -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest003, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    NiceMock<MockDBinderService> mockService;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(Return(sessionInfo));
    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(INVALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest004
 * @tc.desc: Verify the ProcessProto function when GetCallingPid function return -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest004, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    NiceMock<MockDBinderService> mockService;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(Return(sessionInfo));
    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(INVALID_PID_TEST));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest005
 * @tc.desc: Verify the ProcessProto function when CreateDatabusName function return empty
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest005, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    NiceMock<MockDBinderService> mockService;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::IF_PROT_ERROR;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(Return(sessionInfo));
    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(""));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest006
 * @tc.desc: Verify the ProcessProto function when sessionInfo->type is IRemoteObject::IF_PROT_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest006, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    NiceMock<MockDBinderService> mockService;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::IF_PROT_ERROR;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(Return(sessionInfo));
    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(LOCAL_BUS_NAME_TEST));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
}

/**
 * @tc.name: ProcessProtoTest007
 * @tc.desc: Verify the ProcessProto function when return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, ProcessProtoTest007, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    NiceMock<MockDBinderService> mockService;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(Return(sessionInfo));
    EXPECT_CALL(mockServiceStub, GetCallingUid).WillRepeatedly(Return(VALID_UID_TEST));
    EXPECT_CALL(mockServiceStub, GetCallingPid).WillRepeatedly(Return(VALID_PID_TEST));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(Return(LOCAL_BUS_NAME_TEST));
    EXPECT_CALL(mockServiceStub, WriteUint32).WillRepeatedly(Return(false));

    int32_t ret = dBinderServiceStub.ProcessProto(PROCESS_PROTO_CODE, data, reply, option);
    EXPECT_EQ(ret, DBINDER_SERVICE_PROCESS_PROTO_ERR);
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
 * @tc.name: CheckSessionObjectValidityTest001
 * @tc.desc: Verify the CheckSessionObjectValidity function when GetInstance function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, CheckSessionObjectValidityTest001, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MockDBinderService mockService;

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(testing::Return(nullptr));

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
    MockDBinderService mockService;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    dBinderService->sessionObject_.clear();

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(testing::Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(testing::Return(nullptr));

    bool result = dBinderServiceStub.CheckSessionObjectValidity();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckSessionObjectValidityTest003
 * @tc.desc: Verify the CheckSessionObjectValidity function when sessionInfo->type is IRemoteObject::IF_PROT_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, CheckSessionObjectValidityTest003, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    MockDBinderService mockService;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::IF_PROT_ERROR;
    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    dBinderService->sessionObject_.clear();

    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(testing::Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(testing::Return(sessionInfo));

    bool result = dBinderServiceStub.CheckSessionObjectValidity();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetAndSaveDBinderData001
 * @tc.desc: Verify the GetAndSaveDBinderData function when pid is -1 and uid is 1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderData001, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = INVALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderData002
 * @tc.desc: Verify the GetAndSaveDBinderData function when pid is 1 and uid is -1
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderData002, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = VALID_PID_TEST;
    uid_t uid = INVALID_UID_TEST;

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderData003
 * @tc.desc: Verify the GetAndSaveDBinderData function when pid and uid are valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderData003, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = VALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;
    MockDBinderService mockService;

    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(testing::Return(nullptr));

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderData004
 * @tc.desc: Verify the GetAndSaveDBinderData function when GetInstance function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderData004, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = VALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;
    MockDBinderService mockService;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(testing::Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(testing::Return(sessionInfo));
    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(testing::Return(nullptr));

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderData005
 * @tc.desc: Verify the GetAndSaveDBinderData function when CreateDatabusName function return ""
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderData005, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = VALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;
    MockDBinderService mockService;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(testing::Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(testing::Return(sessionInfo));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(testing::Return(""));

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}

/**
 * @tc.name: GetAndSaveDBinderData006
 * @tc.desc: Verify the GetAndSaveDBinderData function when CreateDatabusName function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(DBinderServiceStubTest, GetAndSaveDBinderData006, TestSize.Level1)
{
    DBinderServiceStub dBinderServiceStub(SERVICE_TEST, DEVICE_TEST, BINDER_OBJECT);
    pid_t pid = VALID_PID_TEST;
    uid_t uid = VALID_UID_TEST;
    MockDBinderService mockService;
    NiceMock<DBinderServiceStubInterfaceMock> mockServiceStub;
    std::shared_ptr<struct SessionInfo> sessionInfo = std::make_shared<struct SessionInfo>();
    sessionInfo->type = IRemoteObject::DATABUS_TYPE;

    sptr<DBinderService> dBinderService = DBinderService::GetInstance();
    EXPECT_CALL(mockService, GetInstance).WillRepeatedly(testing::Return(dBinderService));
    EXPECT_CALL(mockService, QuerySessionObject).WillRepeatedly(testing::Return(sessionInfo));
    EXPECT_CALL(mockServiceStub, CreateDatabusName).WillRepeatedly(testing::Return(LOCAL_BUS_NAME_TEST));

    int ret = dBinderServiceStub.GetAndSaveDBinderData(pid, uid);
    EXPECT_EQ(ret, DBINDER_SERVICE_FILL_DATA_ERR);
}
} // namespace OHOS
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

#include <algorithm>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <pthread.h>

#include "ipc_skeleton.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

namespace {
const std::string DEVICEID_TEST = "testRemoteDeviceId";
constexpr uint32_t CODE_TEST = 0;
constexpr uint32_t REMOTEPID_TEST = 1;
constexpr uint32_t REMOTEUID_TEST = 1;
constexpr uint32_t STUBINDEX_TEST = 1;
constexpr uint32_t REMOTEFEATURE_TEST = 1;
constexpr int UID_TEST = 123;
constexpr int PID_TEST = 456;
}

class IPCObjectStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCObjectStubTest::SetUpTestCase()
{
}

void IPCObjectStubTest::TearDownTestCase()
{
}

void IPCObjectStubTest::SetUp()
{
}

void IPCObjectStubTest::TearDown()
{
}

class IpcObjectStubInterface {
public:
    IpcObjectStubInterface() {};
    virtual ~IpcObjectStubInterface() {};
    virtual bool ReadString16Vector(std::vector<std::u16string> *val) = 0;
    virtual bool WriteInt32(int32_t value) = 0;
    virtual bool WriteString16(const std::u16string &value) = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual IPCProcessSkeleton *GetCurrent() = 0;
    virtual pid_t GetCallingUid() = 0;
    virtual pid_t GetCallingPid() = 0;
    virtual bool IsLocalCalling() = 0;
    virtual std::string CreateSessionName(int uid, int pid) = 0;
};

class IpcObjectStubInterfaceMock : public IpcObjectStubInterface {
public:
    IpcObjectStubInterfaceMock();
    ~IpcObjectStubInterfaceMock() override;
    MOCK_METHOD1(ReadString16Vector, bool(std::vector<std::u16string> *val));
    MOCK_METHOD1(WriteInt32, bool(int32_t value));
    MOCK_METHOD1(WriteString16, bool(const std::u16string &value));
    MOCK_METHOD1(WriteString, bool(const std::string &value));
    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton *());
    MOCK_METHOD0(GetCallingUid, pid_t());
    MOCK_METHOD0(GetCallingPid, pid_t());
    MOCK_METHOD0(IsLocalCalling, bool());
    MOCK_METHOD2(CreateSessionName, std::string(int uid, int pid));
};

static void *g_interface = nullptr;

IpcObjectStubInterfaceMock::IpcObjectStubInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IpcObjectStubInterfaceMock::~IpcObjectStubInterfaceMock()
{
    g_interface = nullptr;
}

static IpcObjectStubInterface *GetIpcObjectStubInterface()
{
    return reinterpret_cast<IpcObjectStubInterface *>(g_interface);
}
extern "C" {
    bool Parcel::ReadString16Vector(std::vector<std::u16string> *val)
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->ReadString16Vector(val);
    }
    bool Parcel::WriteInt32(int32_t value)
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteInt32(value);
    }
    bool Parcel::WriteString16(const std::u16string &value)
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteString16(value);
    }
    bool Parcel::WriteString(const std::string &value)
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteString(value);
    }
    IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->GetCurrent();
    }
    pid_t IPCSkeleton::GetCallingPid()
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return -1;
        }
        return interface->GetCallingPid();
    }
    pid_t IPCSkeleton::GetCallingUid()
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return -1;
        }
        return interface->GetCallingUid();
    }
    bool IPCSkeleton::IsLocalCalling()
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->IsLocalCalling();
    }
    std::string IPCObjectStub::CreateSessionName(int uid, int pid)
    {
        IpcObjectStubInterface* interface = GetIpcObjectStubInterface();
        if (interface == nullptr) {
            return "";
        }
        return interface->CreateSessionName(uid, pid);
    }
}

/**
 * @tc.name: OnRemoteDumpTest001
 * @tc.desc: Verify the OnRemoteDump function return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, OnRemoteDumpTest001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    IPCObjectStub stub;
    int fd = 1;
    data.WriteFileDescriptor(fd);
    NiceMock<IpcObjectStubInterfaceMock> mock;
    EXPECT_CALL(mock, ReadString16Vector).WillOnce(Return(true));
    int result = stub.OnRemoteDump(CODE_TEST, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: OnRemoteDumpTest002
 * @tc.desc: Verify the OnRemoteDump function return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, OnRemoteDumpTest002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    IPCObjectStub stub;
    int fd = 1;
    data.WriteFileDescriptor(fd);
    NiceMock<IpcObjectStubInterfaceMock> mock;
    EXPECT_CALL(mock, ReadString16Vector).WillOnce(Return(false));
    int result = stub.OnRemoteDump(CODE_TEST, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: DBinderPingTransactionTest001
 * @tc.desc: Verify the DBinderPingTransaction function return IPC_STUB_WRITE_PARCEL_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, DBinderPingTransactionTest001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    IPCObjectStub stub;
    NiceMock<IpcObjectStubInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillOnce(Return(false));
    int result = stub.DBinderPingTransaction(CODE_TEST, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_WRITE_PARCEL_ERR);
}

/**
 * @tc.name: DBinderSearchDescriptorTest001
 * @tc.desc: Verify the DBinderSearchDescriptor function return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, DBinderSearchDescriptorTest001, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_CALL(mock, WriteString16).WillOnce(Return(true));
    int result = stub.DBinderSearchDescriptor(CODE_TEST, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: DBinderSearchDescriptorTest002
 * @tc.desc: Verify the DBinderSearchDescriptor function return IPC_STUB_WRITE_PARCEL_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, DBinderSearchDescriptorTest002, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_CALL(mock, WriteString16).WillOnce(Return(false));
    int result = stub.DBinderSearchDescriptor(CODE_TEST, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_WRITE_PARCEL_ERR);
}

/**
 * @tc.name: DBinderDumpTransactionTest001
 * @tc.desc: Verify the DBinderDumpTransaction function return IPC_STUB_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, DBinderDumpTransactionTest001, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_CALL(mock, IsLocalCalling).WillOnce(Return(true));
    int result = stub.DBinderDumpTransaction(CODE_TEST, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnFirstStrongRefTest001
 * @tc.desc: Verify the OnFirstStrongRef function return void
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, OnFirstStrongRefTest001, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    const void* objectId = nullptr;
    IPCObjectStub stub;
    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(nullptr));
    ASSERT_NO_FATAL_FAILURE(stub.OnFirstStrongRef(objectId));
}

/**
 * @tc.name: NoticeServiceDieTest001
 * @tc.desc: Verify the NoticeServiceDie function return IPC_STUB_CURRENT_NULL_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, NoticeServiceDieTest001, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub stub;
    MessageParcel data, reply;
    MessageOption option;
    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(nullptr));
    int32_t result = stub.NoticeServiceDie(data, reply, option);
    EXPECT_EQ(result, IPC_STUB_CURRENT_NULL_ERR);
}

/**
 * @tc.name: NoticeServiceDieTest002
 * @tc.desc: Verify the NoticeServiceDie function return IPC_STUB_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, NoticeServiceDieTest002, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub stub;
    MessageParcel data, reply;
    MessageOption option;
    IPCProcessSkeleton realObject;
    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(&realObject));
    int32_t result = stub.NoticeServiceDie(data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: IsDeviceIdIllegalTest001
 * @tc.desc: Verify the IsDeviceIdIllegal function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, IsDeviceIdIllegalTest001, TestSize.Level1)
{
    IPCObjectStub stub;
    std::string remoteDeviceId = DEVICEID_TEST;
    int32_t ret = stub.IsDeviceIdIllegal(remoteDeviceId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetSessionName001
 * @tc.desc: Verify the GetSessionName function return ""
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, GetSessionNameTest001, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub stub;
    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(nullptr));
    auto ret = stub.GetSessionName();
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: GetGrantedSessionNameTest001
 * @tc.desc: Verify the GetGrantedSessionName function return ERR_NONE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, GetGrantedSessionNameTest001, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub Stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int uid = UID_TEST;
    int pid = PID_TEST;
    std::string sessionName = DBINDER_SOCKET_NAME_PREFIX + std::to_string(uid) + std::string("_") + std::to_string(pid);
    EXPECT_CALL(mock, CreateSessionName).WillOnce(Return(sessionName));
    EXPECT_CALL(mock, WriteString).WillOnce(Return(true));
    int result = Stub.GetGrantedSessionName(CODE_TEST, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: GetGrantedSessionNameTest002
 * @tc.desc: Verify the GetGrantedSessionName function return IPC_STUB_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, GetGrantedSessionNameTest002, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub Stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int uid = UID_TEST;
    int pid = PID_TEST;
    std::string sessionName = DBINDER_SOCKET_NAME_PREFIX + std::to_string(uid) + std::string("_") + std::to_string(pid);
    EXPECT_CALL(mock, CreateSessionName).WillOnce(Return(sessionName));
    EXPECT_CALL(mock, WriteString).WillOnce(Return(false));
    int result = Stub.GetGrantedSessionName(CODE_TEST, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: AddAuthInfoTest001
 * @tc.desc: Verify the AddAuthInfo function return BINDER_CALLBACK_STUBINDEX_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, AddAuthInfoTest001, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub stub;
    MessageParcel data;
    uint32_t remotePid = REMOTEPID_TEST;
    data.WriteUint32(remotePid);
    uint32_t remoteUid = REMOTEUID_TEST;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = DEVICEID_TEST;
    data.WriteString(remoteDeviceId);
    uint32_t remoteFeature = REMOTEFEATURE_TEST;
    data.WriteUint32(remoteFeature);
    uint64_t stubIndex = STUBINDEX_TEST;
    data.WriteUint64(stubIndex);
    MessageParcel reply;
    IPCProcessSkeleton current;
    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(&current));
    int32_t ret = stub.AddAuthInfo(data, reply, CODE_TEST);
    EXPECT_EQ(ret, BINDER_CALLBACK_STUBINDEX_ERR);
}

/**
 * @tc.name: AddAuthInfoeTest002
 * @tc.desc: Verify the AddAuthInfoe function return IPC_STUB_CURRENT_NULL_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectStubTest, AddAuthInfoTest002, TestSize.Level1)
{
    NiceMock<IpcObjectStubInterfaceMock> mock;
    IPCObjectStub stub;
    MessageParcel data;
    uint32_t remotePid = REMOTEPID_TEST;
    data.WriteUint32(remotePid);
    uint32_t remoteUid = REMOTEUID_TEST;
    data.WriteUint32(remoteUid);
    std::string remoteDeviceId = DEVICEID_TEST;
    data.WriteString(remoteDeviceId);
    uint32_t remoteFeature = REMOTEFEATURE_TEST;
    data.WriteUint32(remoteFeature);
    uint64_t stubIndex = STUBINDEX_TEST;
    data.WriteUint64(stubIndex);
    MessageParcel reply;
    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(nullptr));
    int32_t ret = stub.AddAuthInfo(data, reply, CODE_TEST);
    EXPECT_EQ(ret, IPC_STUB_CURRENT_NULL_ERR);
}
}
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
#include <iostream>

#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "log_tags.h"
#include "mock_iremote_invoker.h"
#include "mock_iremote_object.h"
#include "sys_binder.h"

#define private public
#include "buffer_object.h"
#include "dbinder_databus_invoker.h"
#include "dbinder_session_object.h"
#undef private

using namespace std;
using namespace testing::ext;
using namespace OHOS;

namespace {
const std::string DEVICE_ID_TEST = "deviceidTest";
const std::string SESSION_NAME_TEST = "sessionNameTest";
const std::string PEER_SESSION_NAME_TEST = "peerSessionNameTest";
const std::string SERVICE_NAME_TEST = "serviceNameTest";
const uint32_t DEVICEID_LENGTH_TEST = 64;
const int ACCESS_TOKEN_MAX_LEN = 10;
}

namespace OHOS {
class MockDBinderSessionObject : public DBinderSessionObject {
public:
    MockDBinderSessionObject();

    MOCK_METHOD0(GetSessionBuff, std::shared_ptr<BufferObject>());
    MOCK_CONST_METHOD0(GetSocketId, int32_t());
};

MockDBinderSessionObject::MockDBinderSessionObject()
    : DBinderSessionObject("serviceNameTest", "deviceidTest", 1, nullptr, 1)
{
}

class MockIPCProcessSkeleton : public IPCProcessSkeleton {
public:
    MockIPCProcessSkeleton() {}

    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton* ());
    MOCK_METHOD2(FindOrNewObject, sptr<IRemoteObject>(
        int handle, const dbinder_negotiation_data *data));
};

class MockBufferObject : public BufferObject {
public:
    MOCK_METHOD1(GetSendBufferAndLock, char *(uint32_t size));
    MOCK_CONST_METHOD0(GetSendBufferWriteCursor, ssize_t());
    MOCK_CONST_METHOD0(GetSendBufferReadCursor, ssize_t());
};
} // namespace OHOS

class DbinderDataBusInvokerTest : public testing::Test {
public:
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IPCUnitTest" };
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DbinderDataBusInvokerTest::SetUpTestCase()
{
}

void DbinderDataBusInvokerTest::TearDownTestCase()
{
}

void DbinderDataBusInvokerTest::SetUp()
{
}

void DbinderDataBusInvokerTest::TearDown()
{
}

/**
 * @tc.name: AcquireHandle001
 * @tc.desc: Verify the AcquireHandle function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AcquireHandle001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t handle = 0;
    bool res = testInvoker.AcquireHandle(handle);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: ReleaseHandle001
 * @tc.desc: Verify the ReleaseHandle function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, ReleaseHandle001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t handle = 0;
    bool res = testInvoker.ReleaseHandle(handle);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: StopWorkThreadTest001
 * @tc.desc: Verify the StopWorkThread function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, StopWorkThreadTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    testInvoker.StopWorkThread();
    EXPECT_TRUE(testInvoker.stopWorkThread_);
}

/**
 * @tc.name: FlattenObjectTest001
 * @tc.desc: Verify the FlattenObject function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlattenObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    MessageParcel data;
    IRemoteObject *object = nullptr;
    bool ret = testInvoker.FlattenObject(data, object);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: UnflattenObjectTest001
 * @tc.desc: Verify the UnflattenObject function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, UnflattenObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    MessageParcel data;
    sptr<IRemoteObject> object = testInvoker.UnflattenObject(data);
    EXPECT_EQ(object, nullptr);
}

/**
 * @tc.name: ReadFileDescriptorTest001
 * @tc.desc: Verify the ReadFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, ReadFileDescriptorTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    MessageParcel data;
    int ret = testInvoker.ReadFileDescriptor(data);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: WriteFileDescriptorTest001
 * @tc.desc: Verify the WriteFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, WriteFileDescriptorTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    MessageParcel data;
    int fd = -1;
    bool ret = testInvoker.WriteFileDescriptor(data, fd, true);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetCallerPidTest001
 * @tc.desc: Verify the GetCallerPid function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetCallerPidTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    pid_t pid = 1;
    testInvoker.callerPid_ = pid;
    pid_t ret = testInvoker.GetCallerPid();
    EXPECT_EQ(ret, pid);
}

/**
 * @tc.name: GetCallerTokenIDTest001
 * @tc.desc: Verify the GetCallerTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetCallerTokenIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint64_t tokenId = 1;
    testInvoker.callerTokenID_ = tokenId;
    uint32_t ret = testInvoker.GetCallerTokenID();
    EXPECT_EQ(ret, tokenId);
}

/**
 * @tc.name: GetFirstCallerTokenIDTest001
 * @tc.desc: Verify the GetFirstCallerTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetFirstCallerTokenIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint64_t tokenId = 1;
    testInvoker.firstTokenID_ = tokenId;
    uint32_t ret = testInvoker.GetFirstCallerTokenID();
    EXPECT_EQ(ret, tokenId);
}

/**
 * @tc.name: GetStatusTest001
 * @tc.desc: Verify the GetStatus function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetStatusTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t status = 1;
    testInvoker.SetStatus(status);
    uint32_t ret = testInvoker.GetStatus();
    EXPECT_EQ(ret, status);
}

/**
 * @tc.name: IsLocalCallingTest001
 * @tc.desc: Verify the IsLocalCalling function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, IsLocalCallingTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    bool ret = testInvoker.IsLocalCalling();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetLocalDeviceIDTest001
 * @tc.desc: Verify the GetLocalDeviceID function
 * when deviceID is empty
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetLocalDeviceIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string deviceId = testInvoker.GetLocalDeviceID();
    EXPECT_TRUE(deviceId.empty());
}

/**
 * @tc.name: GetCallerDeviceIDTest001
 * @tc.desc: Verify the GetCallerDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetCallerDeviceIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string src = "test device id";
    testInvoker.callerDeviceID_ = src;
    std::string deviceId = testInvoker.GetCallerDeviceID();
    EXPECT_TRUE(src == testInvoker.callerDeviceID_);
}

/**
 * @tc.name: NewSessionOfBinderProxy001
 * @tc.desc: Verify the NewSessionOfBinderProxy function
 * when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy001, TestSize.Level1)
{
    uint32_t handle = 0;

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.NewSessionOfBinderProxy(handle, nullptr);
    EXPECT_TRUE(res == nullptr);
}

/**
 * @tc.name: NewSessionOfBinderProxy002
 * @tc.desc: Verify the NewSessionOfBinderProxy function
 * when session is valid
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy002, TestSize.Level1)
{
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (remoteSession != nullptr);
}

/**
 * @tc.name: NewSessionOfBinderProxy003
 * @tc.desc: Verify the NewSessionOfBinderProxy function
 * when current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy003, TestSize.Level1)
{
    uint32_t handle = REGISTRY_HANDLE;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    ASSERT_NE(invoker, nullptr);

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (ret == nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: NewSessionOfBinderProxy004
 * @tc.desc: Verify the NewSessionOfBinderProxy function
 * when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy004, TestSize.Level1)
{
    uint32_t handle = REGISTRY_HANDLE;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (ret == nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: NewSessionOfBinderProxy005
 * @tc.desc: Verify the NewSessionOfBinderProxy function
 * when FindOrNewObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy005, TestSize.Level1)
{
    uint32_t handle = REGISTRY_HANDLE;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, FindOrNewObject(handle, nullptr))
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (ret == nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: NewSessionOfBinderProxy006
 * @tc.desc: Verify the NewSessionOfBinderProxy function
 * when GetProto function return IRemoteObject::IF_PROT_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, NewSessionOfBinderProxy006, TestSize.Level1)
{
    uint32_t handle = REGISTRY_HANDLE;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();
    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();

    EXPECT_CALL(*instance, FindOrNewObject(handle, nullptr))
        .WillRepeatedly(testing::Return(proxy));

    EXPECT_CALL(*proxy, GetProto())
        .WillRepeatedly(testing::Return(IRemoteObject::IF_PROT_ERROR));

    current->instance_ = instance;
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (ret == nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: GetSessionForProxy001
 * @tc.desc: Verify the GetSessionForProxy function
 * when sessionName is empty
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetSessionForProxy001, TestSize.Level1)
{
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();
    std::string sessionName;

    EXPECT_CALL(*proxy, GetSessionName())
        .WillRepeatedly(testing::Return(sessionName));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, "local_device_id");
    EXPECT_TRUE (ret == nullptr);
}

/**
 * @tc.name: GetSessionForProxy002
 * @tc.desc: Verify the GetSessionForProxy function
 * when InvokeListenThread function return 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, GetSessionForProxy002, TestSize.Level1)
{
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    sptr<MockIPCObjectProxy> proxy = sptr<MockIPCObjectProxy>::MakeSptr();
    EXPECT_CALL(*proxy, GetSessionName())
        .WillRepeatedly(testing::Return("session_name"));

    EXPECT_CALL(*proxy, InvokeListenThread(testing::_, testing::_))
        .WillRepeatedly(testing::Return(0));

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.GetSessionForProxy(
        proxy, remoteSession, "local_device_id");
    EXPECT_TRUE (ret == nullptr);
}

/**
 * @tc.name: AuthSession2Proxy001
 * @tc.desc: Verify the AuthSession2Proxy function
 * when session is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AuthSession2Proxy001, TestSize.Level1)
{
    uint32_t handle = 0;
    DBinderDatabusInvoker testInvoker;
    bool res = testInvoker.AuthSession2Proxy(handle, nullptr);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: AuthSession2Proxy002
 * @tc.desc: Verify the AuthSession2Proxy function
 * when IPCObjectProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, AuthSession2Proxy002, TestSize.Level1)
{
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    DBinderDatabusInvoker testInvoker;
    bool res = testInvoker.AuthSession2Proxy(handle, remoteSession);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: QuerySessionOfBinderProxy001
 * @tc.desc: Verify the QuerySessionOfBinderProxy function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QuerySessionOfBinderProxy001, TestSize.Level1)
{
    uint32_t handle = 0;
    std::string serverName = "serverName";
    std::string deviceId = "7001005458323933328a519c2fa83800";
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(serverName, deviceId, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.QuerySessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE(res == nullptr);
}

/**
 * @tc.name: QueryClientSessionObjectTest001
 * @tc.desc: Verify the QueryClientSessionObject function when handle is 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryClientSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryClientSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryClientSessionObjectTest002
 * @tc.desc: Verify the QueryClientSessionObject function valid
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryClientSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);
    bool ret = current->StubAttachDBinderSession(handle, remoteSession);
    EXPECT_TRUE(ret);

    std::shared_ptr<DBinderSessionObject> session = testInvoker.QueryClientSessionObject(handle);
    EXPECT_TRUE(session != nullptr);
}

/**
 * @tc.name: QueryClientSessionObjectTest003
 * @tc.desc: Verify the QueryClientSessionObject function
 * when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryClientSessionObjectTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryClientSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: QueryServerSessionObjectTest001
 * @tc.desc: Verify the QueryServerSessionObject function handle is 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryServerSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryServerSessionObjectTest002
 * @tc.desc: Verify the QueryServerSessionObject function valid
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryServerSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);
    bool ret = current->ProxyAttachDBinderSession(handle, remoteSession);
    EXPECT_TRUE(ret);

    std::shared_ptr<DBinderSessionObject> session = testInvoker.QueryServerSessionObject(handle);
    EXPECT_TRUE(session != nullptr);
}

/**
 * @tc.name: QueryServerSessionObjectTest003
 * @tc.desc: Verify the QueryServerSessionObject function
 * when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, QueryServerSessionObjectTest003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryServerSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: CreateProcessThreadTest001
 * @tc.desc: Verify the CreateProcessThread function return false
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateProcessThreadTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->threadPool_ = nullptr;
    bool ret = testInvoker.CreateProcessThread();
    EXPECT_FALSE(ret);
    ret = testInvoker.CreateProcessThread();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CreateProcessThreadTest002
 * @tc.desc: Verify the CreateProcessThread function return true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateProcessThreadTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    int maxThreadNum = 3;
    EXPECT_TRUE(current->SetMaxWorkThread(maxThreadNum));
    bool ret = testInvoker.CreateProcessThread();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CreateServerSessionObjectTest001
 * @tc.desc: Verify the CreateServerSessionObject function when binder is 0
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    binder_uintptr_t binder = 0;
    std::shared_ptr<DBinderSessionObject> sessionObject = nullptr;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.CreateServerSessionObject(binder, sessionObject);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: CreateServerSessionObjectTest002
 * @tc.desc: Verify the CreateServerSessionObject function when binder is valid value
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, CreateServerSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCObjectStub *temp = new (std::nothrow) IPCObjectStub();
    binder_uintptr_t binder = reinterpret_cast<binder_uintptr_t>(temp);
    std::shared_ptr<DBinderSessionObject> sessionObject = nullptr;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.CreateServerSessionObject(binder, sessionObject);
    EXPECT_EQ(ret, nullptr);
    delete temp;
}

/**
 * @tc.name: MakeDefaultServerSessionObjectTest001
 * @tc.desc: Verify the MakeDefaultServerSessionObject function when proxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, MakeDefaultServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    auto object = std::make_shared<DBinderSessionObject>(serviceName, serverDeviceId, 1, nullptr, 1);
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.MakeDefaultServerSessionObject(1, object);
    EXPECT_EQ(ret, nullptr);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->sessionName_ = SERVICE_NAME_TEST;
    ret = testInvoker.MakeDefaultServerSessionObject(1, object);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: FlushCommandsTest001
 * @tc.desc: Verify the FlushCommands function when object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, FlushCommandsTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IRemoteObject *object = nullptr;
    int ret = testInvoker.FlushCommands(object);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnReceiveNewConnectionTest001
 * @tc.desc: Verify the OnReceiveNewConnection function
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnReceiveNewConnectionTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    auto handle = 1;

    IPCObjectProxy *ipcProxy = new IPCObjectProxy(handle, u"testproxy");
    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, ipcProxy, 1);
    current->dbinderSessionObjects_[handle] = sessionObject;

    int32_t socketId = 1;
    int peerPid = 1;
    int peerUid = 1;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid,
        peerName, networkId);
    EXPECT_FALSE(ret);
    current->dbinderSessionObjects_.clear();
    sessionObject->proxy_ = nullptr;
    delete ipcProxy;
}

/**
 * @tc.name: OnReceiveNewConnectionTest002
 * @tc.desc: Verify the OnReceiveNewConnection function
 * when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, OnReceiveNewConnectionTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();

    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));

    current->instance_ = instance;
    int32_t socketId = 1;
    int peerPid = 1;
    int peerUid = 1;
    std::string peerName = SERVICE_NAME_TEST;
    std::string networkId = DEVICE_ID_TEST;
    bool ret = testInvoker.OnReceiveNewConnection(socketId, peerPid, peerUid,
        peerName, networkId);
    EXPECT_FALSE(ret);
    delete instance;
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: ResetCallingIdentityTest001
 * @tc.desc: Verify the ResetCallingIdentity and SetCallingIdentity function
 * when token is empty
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, ResetCallingIdentityTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string token = testInvoker.ResetCallingIdentity();
    EXPECT_FALSE(token.empty());
    bool ret = testInvoker.SetCallingIdentity(token, false);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetCallingIdentityTest001
 * @tc.desc: Verify the SetCallingIdentity function return true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SetCallingIdentityTest001, TestSize.Level1)
{
    uint64_t tokenId = 1;
    uint64_t pid = 1;
    char buf[ACCESS_TOKEN_MAX_LEN + 1] = {0};
    std::string deviceId;

    int ret = sprintf_s(buf, ACCESS_TOKEN_MAX_LEN + 1, "%010u", tokenId);
    EXPECT_FALSE(ret < 0);
    std::string accessToken(buf);
    for (int i = 0; i < DEVICEID_LENGTH_TEST; i++) {
        deviceId += "A";
    }
    std::string token = std::to_string(static_cast<uint64_t>(pid));
    std::string identity = accessToken + deviceId + token;

    DBinderDatabusInvoker testInvoker;
    bool result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SetCallingIdentityTest002
 * @tc.desc: Verify the SetCallingIdentity function return true
 * @tc.type: FUNC
 */
HWTEST_F(DbinderDataBusInvokerTest, SetCallingIdentityTest002, TestSize.Level1)
{
    uint64_t testCallerTokenID = 1;
    std::string testCallerDeviceID(DEVICEID_LENGTH_TEST, 'a');
    pid_t testCallerPid = getpid();
    pid_t testCallerUid = getuid();

    std::stringstream ss;
    ss << std::setw(DBinderDatabusInvoker::ACCESS_TOKEN_MAX_LEN) << std::setfill('0') << testCallerTokenID;
    ss << testCallerDeviceID;
    ss << std::to_string((static_cast<uint64_t>(testCallerUid) << PID_LEN) | static_cast<uint64_t>(testCallerPid));
    std::string identity = ss.str();
    std::cout << "identity=" << identity << std::endl;

    DBinderDatabusInvoker testInvoker;
    bool result = testInvoker.SetCallingIdentity(identity, false);
    EXPECT_TRUE(result);

    EXPECT_EQ(testInvoker.callerTokenID_, testCallerTokenID);
    EXPECT_EQ(testInvoker.callerDeviceID_, testCallerDeviceID);
    EXPECT_EQ(testInvoker.callerPid_, testCallerPid);
    EXPECT_EQ(testInvoker.callerUid_, testCallerUid);
}
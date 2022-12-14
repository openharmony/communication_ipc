/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "ipc_test_helper.h"
#include "log_tags.h"
#include "access_token_adapter.h"
#include "sys_binder.h"

#define private public
#include "dbinder_databus_invoker.h"
#undef private
#include "mock_session_impl.h"
#include "mock_iremote_invoker.h"
#include "dbinder_session_object.h"

using namespace testing::ext;
using namespace OHOS;

namespace {
const std::string DEVICE_ID_TEST = "deviceidTest";
const std::string SESSION_NAME_TEST = "sessionNameTest";
const std::string PEER_SESSION_NAME_TEST = "peerSessionNameTest";
const std::string SERVICE_NAME_TEST = "serviceNameTest";
const uint32_t ID_LENGTH = 64;
}

class IPCDbinderDataBusInvokerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_IPC, "IPCUnitTest" };

private:
    static inline IPCTestHelper *g_globalHelper = { nullptr };
};

void IPCDbinderDataBusInvokerTest::SetUpTestCase()
{
    if (g_globalHelper == nullptr) {
        g_globalHelper = new IPCTestHelper();
        bool res = g_globalHelper->PrepareTestSuite();
        ASSERT_TRUE(res);
    }
}

void IPCDbinderDataBusInvokerTest::TearDownTestCase()
{
    if (g_globalHelper != nullptr) {
        bool res = g_globalHelper->TearDownTestSuite();
        ASSERT_TRUE(res);
        delete g_globalHelper;
        g_globalHelper = nullptr;
    }
}

/**
 * @tc.name: AcquireHandle001
 * @tc.desc: AcquireHandle
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, AcquireHandle001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t handle = 0;
    bool res = testInvoker.AcquireHandle(handle);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: ReleaseHandle001
 * @tc.desc: ReleaseHandle
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, ReleaseHandle001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    int32_t handle = 0;
    bool res = testInvoker.ReleaseHandle(handle);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: FlattenObjectTest001
 * @tc.desc: StopWorkThread
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, StopWorkThreadTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    testInvoker.StopWorkThread();
    EXPECT_TRUE(testInvoker.stopWorkThread_);
}

/**
 * @tc.name: FlattenObjectTest005
 * @tc.desc: FlattenObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, FlattenObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    MessageParcel data;
    IRemoteObject *object = nullptr;
    bool ret = testInvoker.FlattenObject(data, object);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: UnflattenObjectTest001
 * @tc.desc: UnflattenObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, UnflattenObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    MessageParcel data;
    sptr<IRemoteObject> object = testInvoker.UnflattenObject(data);
    EXPECT_EQ(object, nullptr);
}

/**
 * @tc.name: ReadFileDescriptorTest001
 * @tc.desc: ReadFileDescriptor
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, ReadFileDescriptorTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    MessageParcel data;
    int ret = testInvoker.ReadFileDescriptor(data);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: WriteFileDescriptorTest001
 * @tc.desc: WriteFileDescriptor
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, WriteFileDescriptorTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    MessageParcel data;
    int fd = -1;
    bool ret = testInvoker.WriteFileDescriptor(data, fd, true);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetCallerPidTest001
 * @tc.desc: GetCallerPid
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetCallerPidTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    pid_t pid = 1;
    testInvoker.callerPid_ = pid;
    pid_t ret = testInvoker.GetCallerPid();
    EXPECT_EQ(ret, pid);
}

/**
 * @tc.name: GetCallerTokenIDTest001
 * @tc.desc: GetCallerTokenID
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetCallerTokenIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint64_t tokenId = 1;
    testInvoker.callerTokenID_ = tokenId;
    uint32_t ret = testInvoker.GetCallerTokenID();
    EXPECT_EQ(ret, tokenId);
}

/**
 * @tc.name: GetFirstCallerTokenIDTest001
 * @tc.desc: GetFirstCallerTokenID
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetFirstCallerTokenIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint64_t tokenId = 1;
    testInvoker.firstTokenID_ = tokenId;
    uint32_t ret = testInvoker.GetFirstCallerTokenID();
    EXPECT_EQ(ret, tokenId);
}

/**
 * @tc.name: GetStatusTest001
 * @tc.desc: GetStatus
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetStatusTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t status = 1;
    testInvoker.SetStatus(status);
    uint32_t ret = testInvoker.GetStatus();
    EXPECT_EQ(ret, status);
}

/**
 * @tc.name: IsLocalCallingTest001
 * @tc.desc: IsLocalCalling
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, IsLocalCallingTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    bool ret = testInvoker.IsLocalCalling();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetLocalDeviceIDTest001
 * @tc.desc: GetLocalDeviceID
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetLocalDeviceIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string deviceId = testInvoker.GetLocalDeviceID();
    EXPECT_TRUE(deviceId.empty());
}

/**
 * @tc.name: GetCallerDeviceIDTest001
 * @tc.desc: GetCallerDeviceID
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetCallerDeviceIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string src = "test device id";
    testInvoker.callerDeviceID_ = src;
    std::string deviceId = testInvoker.GetCallerDeviceID();
    EXPECT_TRUE(src == testInvoker.callerDeviceID_);
}

/**
 * @tc.name: NewSessionOfBinderProxy001
 * @tc.desc: NewSessionOfBinderProxy
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, NewSessionOfBinderProxy001, TestSize.Level1)
{
    uint32_t handle = 0;

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.NewSessionOfBinderProxy(handle, nullptr);
    EXPECT_TRUE(res == nullptr);
}

/**
 * @tc.name: NewSessionOfBinderProxy002
 * @tc.desc: NewSessionOfBinderProxy
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, NewSessionOfBinderProxy002, TestSize.Level1)
{
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (remoteSession != nullptr);
}

/**
 * @tc.name: NewSessionOfBinderProxy003
 * @tc.desc: NewSessionOfBinderProxy
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, NewSessionOfBinderProxy003, TestSize.Level1)
{
    uint32_t handle = REGISTRY_HANDLE;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;

    IRemoteInvoker *invoker = IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DEFAULT);
    ASSERT_TRUE(invoker == nullptr);
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.NewSessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE (ret == nullptr);
    current->invokers_.clear();
}

/**
 * @tc.name: AuthSession2Proxy001
 * @tc.desc: AuthSession2Proxy
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, AuthSession2Proxy001, TestSize.Level1)
{
    uint32_t handle = 0;
    DBinderDatabusInvoker testInvoker;
    bool res = testInvoker.AuthSession2Proxy(handle, nullptr);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: AuthSession2Proxy002
 * @tc.desc: AuthSession2Proxy
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, AuthSession2Proxy002, TestSize.Level1)
{
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    DBinderDatabusInvoker testInvoker;
    bool res = testInvoker.AuthSession2Proxy(handle, remoteSession);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: AuthSession2Proxy003
 * @tc.desc: AuthSession2Proxy
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, AuthSession2Proxy003, TestSize.Level1)
{
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    remoteSession->SetBusSession(nullptr);
    EXPECT_TRUE(remoteSession->GetBusSession() == nullptr);

    DBinderDatabusInvoker testInvoker;
    bool res = testInvoker.AuthSession2Proxy(handle, remoteSession);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: QuerySessionOfBinderProxy001
 * @tc.desc: QuerySessionOfBinderProxy
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, QuerySessionOfBinderProxy001, TestSize.Level1)
{
    uint32_t handle = 0;
    std::string serverName = "serverName";
    std::string deviceId = "7001005458323933328a519c2fa83800";
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(nullptr, serverName, deviceId, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);

    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> res = testInvoker.QuerySessionOfBinderProxy(handle, remoteSession);
    EXPECT_TRUE(res == nullptr);
}

/**
 * @tc.name: QueryClientSessionObjectTest001
 * @tc.desc: QueryClientSessionObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, QueryClientSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryClientSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryClientSessionObjectTest002
 * @tc.desc: QueryClientSessionObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, QueryClientSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);
    bool ret = current->StubAttachDBinderSession(handle, remoteSession);
    EXPECT_TRUE(ret);
    
    std::shared_ptr<DBinderSessionObject> session = testInvoker.QueryClientSessionObject(handle);
    EXPECT_TRUE(session != nullptr);
}

/**
 * @tc.name: QueryServerSessionObjectTest001
 * @tc.desc: QueryServerSessionObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, QueryServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 0;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.QueryServerSessionObject(handle);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryServerSessionObjectTest002
 * @tc.desc: QueryServerSessionObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, QueryServerSessionObjectTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    EXPECT_TRUE (current != nullptr);

    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(sessionMock, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    EXPECT_TRUE (remoteSession != nullptr);
    bool ret = current->ProxyAttachDBinderSession(handle, remoteSession);
    EXPECT_TRUE(ret);
    
    std::shared_ptr<DBinderSessionObject> session = testInvoker.QueryServerSessionObject(handle);
    EXPECT_TRUE(session != nullptr);
}

/**
 * @tc.name: CreateProcessThreadTest001
 * @tc.desc: CreateProcessThread
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CreateProcessThreadTest001, TestSize.Level1)
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
 * @tc.desc: CreateProcessThread
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CreateProcessThreadTest002, TestSize.Level1)
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
 * @tc.desc: CreateServerSessionObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CreateServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    binder_uintptr_t binder = 0;
    std::shared_ptr<DBinderSessionObject> sessionObject = nullptr;
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.CreateServerSessionObject(binder, sessionObject);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: CreateServerSessionObjectTest002
 * @tc.desc: CreateServerSessionObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CreateServerSessionObjectTest002, TestSize.Level1)
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
 * @tc.desc: MakeDefaultServerSessionObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, MakeDefaultServerSessionObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    auto object = std::make_shared<DBinderSessionObject>(nullptr, serviceName, serverDeviceId, 1, nullptr, 1);
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.MakeDefaultServerSessionObject(1, object);
    EXPECT_EQ(ret, nullptr);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->sessionName_ = SERVICE_NAME_TEST;
    ret = testInvoker.MakeDefaultServerSessionObject(1, object);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: FlushCommandsTest001
 * @tc.desc: FlushCommands
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, FlushCommandsTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IRemoteObject *object = nullptr;
    int ret = testInvoker.FlushCommands(object);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnDatabusSessionClosedTest001
 * @tc.desc: OnDatabusSessionClosed
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnDatabusSessionClosedTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<Session> session = nullptr;
    bool ret = testInvoker.OnDatabusSessionClosed(session);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnDatabusSessionClosedTest002
 * @tc.desc: OnDatabusSessionClosed
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnDatabusSessionClosedTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();

    EXPECT_CALL(*sessionMock, GetMySessionName())
        .WillRepeatedly(testing::ReturnRef(SESSION_NAME_TEST));

    EXPECT_CALL(*sessionMock, GetPeerSessionName())
        .WillRepeatedly(testing::ReturnRef(PEER_SESSION_NAME_TEST));

    EXPECT_CALL(*sessionMock, GetChannelId())
        .WillRepeatedly(testing::Return(0X0000000000FFFFFFULL));

    bool ret = testInvoker.OnDatabusSessionClosed(sessionMock);
    EXPECT_FALSE(ret);
    ret = testInvoker.OnDatabusSessionClosed(sessionMock);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnReceiveNewConnectionTest001
 * @tc.desc: OnReceiveNewConnection
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnReceiveNewConnectionTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();

    EXPECT_CALL(*sessionMock, GetChannelId())
        .WillRepeatedly(testing::Return(0X0000000000FFFFFFULL));

    EXPECT_CALL(*sessionMock, GetPeerPid())
        .WillRepeatedly(testing::Return(1));

    EXPECT_CALL(*sessionMock, GetPeerUid())
        .WillRepeatedly(testing::Return(1));

    EXPECT_CALL(*sessionMock, GetPeerSessionName())
        .WillRepeatedly(testing::ReturnRef(PEER_SESSION_NAME_TEST));

    EXPECT_CALL(*sessionMock, GetPeerDeviceId())
        .WillRepeatedly(testing::ReturnRef(DEVICE_ID_TEST));

    bool ret = testInvoker.OnReceiveNewConnection(sessionMock);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ResetCallingIdentityTest001
 * @tc.desc: ResetCallingIdentity
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, ResetCallingIdentityTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string token = testInvoker.ResetCallingIdentity();
    EXPECT_FALSE(token.empty());
    bool ret = testInvoker.SetCallingIdentity(token);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetCallingIdentityTest001
 * @tc.desc: SetCallingIdentity
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, SetCallingIdentityTest001, TestSize.Level1)
{
    #define DEVICEID_LENGTH_TEST 64
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
    bool result = testInvoker.SetCallingIdentity(identity);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TranslateIRemoteObjectTest001
 * @tc.desc: TranslateIRemoteObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, TranslateIRemoteObjectTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t cmd = 0;
    int ret = testInvoker.TranslateIRemoteObject(cmd, nullptr);
    EXPECT_EQ(ret, -IPC_INVOKER_TRANSLATE_ERR);
}

/**
 * @tc.name: OnMessageAvailable001
 * @tc.desc: OnMessageAvailable
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnMessageAvailable001, TestSize.Level1)
{
    std::shared_ptr<Session> session = nullptr;
    DBinderDatabusInvoker testInvoker;;
    testInvoker.OnMessageAvailable(session, nullptr, 0);
    EXPECT_TRUE(session == nullptr);
}

/**
 * @tc.name: OnMessageAvailable002
 * @tc.desc: OnMessageAvailable return at first branch
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnMessageAvailable002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    const char *data = nullptr;
    testInvoker.OnMessageAvailable(sessionMock, data, 0);
    EXPECT_TRUE(data == nullptr);

    uint32_t size = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;
    dbinder_transaction_data *tmp = (dbinder_transaction_data *)malloc(size);
    EXPECT_TRUE(tmp != nullptr);

    data = reinterpret_cast<const char *>(tmp);
    ssize_t len = 0;
    testInvoker.OnMessageAvailable(sessionMock, data, len);
    EXPECT_TRUE(len < static_cast<ssize_t>(sizeof(dbinder_transaction_data)));

    len = static_cast<ssize_t>(MAX_RAWDATA_SIZE) + 1;
    testInvoker.OnMessageAvailable(sessionMock, data, len);
    EXPECT_TRUE(len > static_cast<ssize_t>(MAX_RAWDATA_SIZE));
    free(tmp);
}

/**
 * @tc.name: OnMessageAvailable003
 * @tc.desc: OnMessageAvailable return tr->sizeOfSelf in HasRawDataPackage
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnMessageAvailable003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    uint32_t size = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;
    dbinder_transaction_data *tmp = (dbinder_transaction_data *)malloc(size);
    EXPECT_TRUE(tmp != nullptr);

    tmp->magic = DBINDER_MAGICWORD;
    tmp->cmd = BC_SEND_RAWDATA;
    tmp->sizeOfSelf = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;;
    
    const char *data = reinterpret_cast<const char *>(tmp);
    ssize_t len = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;
    EXPECT_CALL(*sessionMock, GetChannelId())
        .WillOnce(testing::Return(0X0000000000FFFFFFULL))
        .WillRepeatedly(testing::Return(0));

    testInvoker.OnMessageAvailable(sessionMock, data, len);
    EXPECT_TRUE(tmp->sizeOfSelf == static_cast<uint32_t>(len));
    free(tmp);
}

/**
 * @tc.name: OnMessageAvailable004
 * @tc.desc: OnMessageAvailable return 0 in HasRawDataPackage
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnMessageAvailable004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    uint32_t size = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;
    dbinder_transaction_data *tmp = (dbinder_transaction_data *)malloc(size);
    EXPECT_TRUE(tmp != nullptr);

    EXPECT_CALL(*sessionMock, GetChannelId())
        .WillOnce(testing::Return(0X0000000000FFFFFFULL))
        .WillRepeatedly(testing::Return(0));

    tmp->magic = 0;
    const char *data = reinterpret_cast<const char *>(tmp);
    ssize_t len = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;

    testInvoker.OnMessageAvailable(sessionMock, data, len);
    EXPECT_FALSE(tmp->magic == DBINDER_MAGICWORD);

    tmp->magic = DBINDER_MAGICWORD;
    testInvoker.OnMessageAvailable(sessionMock, data, len);
    EXPECT_FALSE(tmp->cmd == BC_SEND_RAWDATA);

    tmp->cmd = BC_SEND_RAWDATA;
    testInvoker.OnMessageAvailable(sessionMock, data, len);
    EXPECT_FALSE(tmp->sizeOfSelf == static_cast<uint32_t>(len));
    free(tmp);
}

/**
 * @tc.name: OnRawDataAvailable001
 * @tc.desc: OnRawDataAvailable
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnRawDataAvailable001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    uint32_t size = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;
    dbinder_transaction_data *tmp = (dbinder_transaction_data *)malloc(size);
    EXPECT_TRUE(tmp != nullptr);

    tmp->magic = DBINDER_MAGICWORD;
    tmp->cmd = BC_SEND_RAWDATA;
    tmp->sizeOfSelf = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;
    const char *data = reinterpret_cast<const char *>(tmp);
    uint32_t dataSize = sizeof(dbinder_transaction_data);
    testInvoker.OnRawDataAvailable(sessionMock, data, dataSize);
    EXPECT_FALSE(dataSize - sizeof(dbinder_transaction_data) > 0);

    dataSize = MAX_RAWDATA_SIZE + 1;
    testInvoker.OnRawDataAvailable(sessionMock, data, dataSize);
    EXPECT_FALSE(dataSize <= MAX_RAWDATA_SIZE);

    dataSize = SOCKET_MAX_BUFF_SIZE;
    testInvoker.OnRawDataAvailable(sessionMock, data, dataSize);
    EXPECT_TRUE(dataSize > sizeof(dbinder_transaction_data) && dataSize <= MAX_RAWDATA_SIZE);
    free(tmp);
}

/**
 * @tc.name: HasCompletePackage001
 * @tc.desc: HasCompletePackage
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, HasCompletePackage001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    ssize_t size = sizeof(dbinder_transaction_data) + SOCKET_MAX_BUFF_SIZE;
    uint32_t readCursor = 0;

    dbinder_transaction_data *tmp = (dbinder_transaction_data *)malloc(size);
    EXPECT_TRUE(tmp != nullptr);
    const char *data = reinterpret_cast<const char *>(tmp);
    uint32_t res = testInvoker.HasCompletePackage(data, readCursor, size);
    EXPECT_EQ(res, readCursor);

    tmp->magic = DBINDER_MAGICWORD;
    data = reinterpret_cast<const char *>(tmp);
    res = testInvoker.HasCompletePackage(data, readCursor, size);
    EXPECT_EQ(res, readCursor);

    tmp->buffer_size = sizeof(binder_size_t);
    tmp->sizeOfSelf = sizeof(dbinder_transaction_data) + tmp->buffer_size;
    data = reinterpret_cast<const char *>(tmp);
    res = testInvoker.HasCompletePackage(data, readCursor, size);
    EXPECT_EQ(res, readCursor);

    tmp->offsets = tmp->buffer_size;
    tmp->flags = MessageOption::TF_STATUS_CODE;
    data = reinterpret_cast<const char *>(tmp);
    res = testInvoker.HasCompletePackage(data, readCursor, size);
    EXPECT_EQ(tmp->sizeOfSelf, res);
    free(tmp);
}

/**
 * @tc.name:CheckAndSetCallerInfo001
 * @tc.desc: Verify the CheckAndSetCallerInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CheckAndSetCallerInfo001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;
    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->StubAttachDBinderSession(handle, sessionObject);

    int ret = testInvoker.CheckAndSetCallerInfo(0, stubIndex);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);

    ret = testInvoker.CheckAndSetCallerInfo(handle, stubIndex);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name:CheckAndSetCallerInfo002
 * @tc.desc: Verify the CheckAndSetCallerInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CheckAndSetCallerInfo002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    sessionObject->session_ = sessionMock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->StubAttachDBinderSession(handle, sessionObject);

    int ret = testInvoker.CheckAndSetCallerInfo(handle, stubIndex);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: UpdateClientSession001
 * @tc.desc: UpdateClientSession return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, UpdateClientSession001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    bool ret = testInvoker.UpdateClientSession(sessionObject);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: OnSendMessage001
 * @tc.desc: OnSendMessage return -RPC_DATABUS_INVOKER_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnSendMessage001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = nullptr;
    int ret = testInvoker.OnSendMessage(sessionOfPeer);
    EXPECT_EQ(ret, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendMessage002
 * @tc.desc: OnSendMessage return RPC_DATABUS_INVOKER_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnSendMessage002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;

    std::shared_ptr<DBinderSessionObject> sessionOfPeer =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    int ret = testInvoker.OnSendMessage(sessionOfPeer);
    EXPECT_EQ(ret, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendMessage003
 * @tc.desc: OnSendMessage return RPC_DATABUS_INVOKER_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnSendMessage003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    std::shared_ptr<DBinderSessionObject> sessionOfPeer =
        std::make_shared<DBinderSessionObject>(sessionMock, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    int ret = testInvoker.OnSendMessage(sessionOfPeer);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
 * @tc.name: OnSendRawData001
 * @tc.desc: OnSendRawData return RPC_DATABUS_INVOKER_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnSendRawData001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> session = nullptr;
    size_t size = 0;
    int ret = testInvoker.OnSendRawData(session, nullptr, size);
    EXPECT_EQ(ret, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendRawData002
 * @tc.desc: OnSendRawData return RPC_DATABUS_INVOKER_INVALID_DATA_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnSendRawData002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> session =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    size_t size = 0;
    int ret = testInvoker.OnSendRawData(session, nullptr, size);
    EXPECT_EQ(ret, -RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
}

/**
 * @tc.name: OnSendRawData003
 * @tc.desc: OnSendRawData return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, OnSendRawData003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    std::shared_ptr<DBinderSessionObject> session =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    session->session_ = sessionMock;
    size_t size = 0;
    int ret = testInvoker.OnSendRawData(session, nullptr, size);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: SetCallerPid001
 * @tc.desc: SetCallerPid
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, SetCallerPid001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    pid_t pid = 1;

    testInvoker.SetCallerPid(pid);
    EXPECT_EQ(1, testInvoker.callerPid_);
}

/**
 * @tc.name: GetCallerUid001
 * @tc.desc: GetCallerUid
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetCallerUid001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    pid_t uid = 1;
    testInvoker.SetCallerUid(uid);

    uid_t test = testInvoker.GetCallerUid();
    EXPECT_EQ(test, testInvoker.callerUid_);
}

/**
 * @tc.name: SetCallerUid001
 * @tc.desc: SetCallerUid
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, SetCallerUid001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    pid_t uid = 1;
    testInvoker.SetCallerUid(uid);

    EXPECT_EQ(1, testInvoker.callerUid_);
}

/**
 * @tc.name: SetCallerDeviceID001
 * @tc.desc: SetCallerDeviceID
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, SetCallerDeviceID001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    const std::string deviceId = "test";
    testInvoker.SetCallerDeviceID(deviceId);

    EXPECT_EQ("test", testInvoker.callerDeviceID_);
}

/**
 * @tc.name: SetCallerTokenID001
 * @tc.desc: SetCallerTokenID
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, SetCallerTokenID001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    const uint32_t tokenId = 1;
    testInvoker.SetCallerTokenID(tokenId);
    uint64_t id = 1;
    EXPECT_EQ(id, testInvoker.callerTokenID_);
}

/**
 * @tc.name: ConnectRemoteObject2Session001
 * @tc.desc: ConnectRemoteObject2Session
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, ConnectRemoteObject2Session001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IRemoteObject* stubObject = nullptr;
    uint64_t stubIndex = 1;
    const std::shared_ptr<DBinderSessionObject> sessionObject = nullptr;
    bool test = testInvoker.ConnectRemoteObject2Session(stubObject, stubIndex, sessionObject);

    EXPECT_TRUE(sessionObject == nullptr);
    EXPECT_EQ(test, false);
}

/**
 * @tc.name: FlattenSession001
 * @tc.desc: FlattenSession return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, FlattenSession001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string serverDeviceId;
    std::shared_ptr<DBinderSessionObject> session =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, serverDeviceId, 1, nullptr, 1);
    FlatDBinderSession flatDBinderSession;
    char* sessionOffset = reinterpret_cast<char*>(&flatDBinderSession);
    uint64_t stubIndex = 0;
    uint32_t ret = testInvoker.FlattenSession(sessionOffset, session, stubIndex);
    EXPECT_EQ(ret, 0);
    serverDeviceId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    ret = testInvoker.FlattenSession(sessionOffset, session, stubIndex);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: FlattenSession002
 * @tc.desc: FlattenSession return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, FlattenSession002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::string serviceName;
    std::shared_ptr<DBinderSessionObject> session =
        std::make_shared<DBinderSessionObject>(nullptr, serviceName, DEVICE_ID_TEST, 1, nullptr, 1);
    FlatDBinderSession flatDBinderSession;
    char* sessionOffset = reinterpret_cast<char*>(&flatDBinderSession);
    uint64_t stubIndex = 0;
    uint32_t ret = testInvoker.FlattenSession(sessionOffset, session, stubIndex);
    EXPECT_EQ(ret, 0);
    serviceName = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    ret = testInvoker.FlattenSession(sessionOffset, session, stubIndex);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: FlattenSession003
 * @tc.desc: FlattenSession return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, FlattenSession003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> session =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    FlatDBinderSession flatDBinderSession;
    char* sessionOffset = reinterpret_cast<char*>(&flatDBinderSession);
    uint64_t stubIndex = 0;
    uint32_t ret = testInvoker.FlattenSession(sessionOffset, session, stubIndex);
    EXPECT_EQ(ret, 280);
}

/**
 * @tc.name: UnFlattenSession001
 * @tc.desc: UnFlattenSession return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, UnFlattenSession001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;

    uint64_t stubIndex = 0;
    FlatDBinderSession flatDBinderSession;
    flatDBinderSession.stubIndex = 0;
    char* sessionOffset = reinterpret_cast<char*>(&flatDBinderSession);
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.UnFlattenSession(sessionOffset, stubIndex);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: UnFlattenSession002
 * @tc.desc: UnFlattenSession return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, UnFlattenSession002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint64_t stubIndex = 0;
    FlatDBinderSession flatDBinderSession;
    int len = 65;
    strcpy_s(flatDBinderSession.serviceName, len, "testServiceName");
    strcpy_s(flatDBinderSession.deviceId, len, "testDeviceId");
    char* sessionOffset = reinterpret_cast<char*>(&flatDBinderSession);
    std::shared_ptr<DBinderSessionObject> ret = testInvoker.UnFlattenSession(sessionOffset, stubIndex);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryHandleBySession001
 * @tc.desc: QueryHandleBySession return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, QueryHandleBySession001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    std::shared_ptr<DBinderSessionObject> session =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    uint32_t ret = testInvoker.QueryHandleBySession(session);

    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: MakeStubIndexByRemoteObject001
 * @tc.desc: MakeStubIndexByRemoteObject return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, MakeStubIndexByRemoteObject001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    IPCObjectProxy *iPCObjectProxy = nullptr;
    uint32_t ret = testInvoker.MakeStubIndexByRemoteObject(iPCObjectProxy);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetSelfFirstCallerTokenIDTest001
 * @tc.desc: Verify the DBinderDatabusInvoker::GetSelfFirstCallerTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetSelfFirstCallerTokenIDTest001, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, GetSelfFirstCallerTokenID())
        .WillRepeatedly(testing::Return(111));

    auto ret = testInvoker.GetSelfFirstCallerTokenID();
    EXPECT_EQ(ret, 111);
    current->invokers_.clear();
    delete invoker;
}

/**
 * @tc.name: GetSelfFirstCallerTokenIDTest002
 * @tc.desc: Verify the DBinderDatabusInvoker::GetSelfFirstCallerTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, GetSelfFirstCallerTokenIDTest002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;

    auto ret = testInvoker.GetSelfFirstCallerTokenID();
    EXPECT_EQ(ret, 0);
    current->invokers_.clear();
}

/**
 * @tc.name:CheckAndSetCallerInfo003
 * @tc.desc: Verify the CheckAndSetCallerInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CheckAndSetCallerInfo003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    sessionObject->session_ = sessionMock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->dbinderSessionObjects_[handle] = sessionObject;
    EXPECT_CALL(*sessionMock, GetPeerUid())
        .WillRepeatedly(testing::Return(-1));

    std::string deviceId = "deviceId";
    EXPECT_CALL(*sessionMock, GetPeerDeviceId())
        .WillRepeatedly(testing::ReturnRef(deviceId));

    int ret = testInvoker.CheckAndSetCallerInfo(handle, stubIndex);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
    current->dbinderSessionObjects_.clear();
}

/**
 * @tc.name:CheckAndSetCallerInfo004
 * @tc.desc: Verify the CheckAndSetCallerInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CheckAndSetCallerInfo004, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    sessionObject->session_ = sessionMock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->dbinderSessionObjects_[handle] = sessionObject;
    EXPECT_CALL(*sessionMock, GetPeerUid())
        .WillRepeatedly(testing::Return(1));

    std::string deviceId('c', ID_LENGTH + 1);
    EXPECT_CALL(*sessionMock, GetPeerDeviceId())
        .WillRepeatedly(testing::ReturnRef(deviceId));

    int ret = testInvoker.CheckAndSetCallerInfo(handle, stubIndex);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_INVALID_DATA_ERR);
    current->dbinderSessionObjects_.clear();
}

/**
 * @tc.name:CheckAndSetCallerInfo005
 * @tc.desc: Verify the CheckAndSetCallerInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CheckAndSetCallerInfo005, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;
    uint32_t pid = 1;
    uint32_t uid = 1;
    uint32_t tokenId = 1;
    uint32_t listenFd = 1;

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    sessionObject->session_ = sessionMock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->dbinderSessionObjects_[handle] = sessionObject;
    EXPECT_CALL(*sessionMock, GetPeerUid())
        .WillRepeatedly(testing::Return(1));

    EXPECT_CALL(*sessionMock, GetPeerPid())
        .WillRepeatedly(testing::Return(1));

    std::string deviceId = "deviceId";
    EXPECT_CALL(*sessionMock, GetPeerDeviceId())
        .WillRepeatedly(testing::ReturnRef(deviceId));

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    skeleton->appInfoToStubIndex_.clear();

    std::string appInfo = deviceId + skeleton->UIntToString(pid) + skeleton->UIntToString(uid) +
        skeleton->UIntToString(tokenId);
    std::map<uint64_t, uint32_t> indexMap = {
        { stubIndex, listenFd }
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    int ret = testInvoker.CheckAndSetCallerInfo(handle, stubIndex);
    EXPECT_EQ(ret, ERR_NONE);
    current->dbinderSessionObjects_.clear();
}


/**
 * @tc.name:CheckAndSetCallerInfo006
 * @tc.desc: Verify the CheckAndSetCallerInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, CheckAndSetCallerInfo006, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;
    uint32_t pid = 1;
    uint32_t uid = 1;
    uint32_t tokenId = 1;
    uint32_t listenFd = 1;

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    sessionObject->session_ = sessionMock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->dbinderSessionObjects_[handle] = sessionObject;
    EXPECT_CALL(*sessionMock, GetPeerUid())
        .WillRepeatedly(testing::Return(2));

    EXPECT_CALL(*sessionMock, GetPeerPid())
        .WillRepeatedly(testing::Return(2));

    std::string deviceId = "deviceId";
    EXPECT_CALL(*sessionMock, GetPeerDeviceId())
        .WillRepeatedly(testing::ReturnRef(deviceId));

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    skeleton->appInfoToStubIndex_.clear();

    std::string appInfo = deviceId + skeleton->UIntToString(pid) + skeleton->UIntToString(uid) +
        skeleton->UIntToString(tokenId);
    std::map<uint64_t, uint32_t> indexMap = {
        { stubIndex, listenFd }
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    int ret = testInvoker.CheckAndSetCallerInfo(handle, stubIndex);
    EXPECT_EQ(ret, RPC_DATABUS_INVOKER_INVALID_STUB_INDEX);
    current->dbinderSessionObjects_.clear();
}

/**
 * @tc.name: ConnectRemoteObject2Session002
 * @tc.desc: ConnectRemoteObject2Session
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, ConnectRemoteObject2Session002, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;
    uint32_t pid = 1;
    uint32_t uid = 1;
    uint32_t tokenId = 1;
    uint32_t listenFd = 1;

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    sessionObject->session_ = sessionMock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->dbinderSessionObjects_[handle] = sessionObject;
    EXPECT_CALL(*sessionMock, GetPeerUid())
        .WillRepeatedly(testing::Return(1));

    EXPECT_CALL(*sessionMock, GetPeerPid())
        .WillRepeatedly(testing::Return(1));

    std::string deviceId = "deviceId";
    EXPECT_CALL(*sessionMock, GetPeerDeviceId())
        .WillRepeatedly(testing::ReturnRef(deviceId));

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    skeleton->appInfoToStubIndex_.clear();

    std::string appInfo = deviceId + skeleton->UIntToString(pid) + skeleton->UIntToString(uid) +
        skeleton->UIntToString(tokenId);
    std::map<uint64_t, uint32_t> indexMap = {
        { stubIndex, listenFd }
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    IPCObjectStub stub;
    auto ret = testInvoker.ConnectRemoteObject2Session(&stub, handle, sessionObject);
    ASSERT_TRUE(ret);
    current->dbinderSessionObjects_.clear();
    current->commAuth_.clear();
}

/**
 * @tc.name: ConnectRemoteObject2Session003
 * @tc.desc: ConnectRemoteObject2Session
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, ConnectRemoteObject2Session003, TestSize.Level1)
{
    DBinderDatabusInvoker testInvoker;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;
    uint32_t pid = 1;
    uint32_t uid = 1;
    uint32_t tokenId = 1;
    uint32_t listenFd = 1;

    std::shared_ptr<DBinderSessionObject> sessionObject =
        std::make_shared<DBinderSessionObject>(nullptr, SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    sessionObject->session_ = sessionMock;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->dbinderSessionObjects_[handle] = sessionObject;
    EXPECT_CALL(*sessionMock, GetPeerUid())
        .WillRepeatedly(testing::Return(2));

    EXPECT_CALL(*sessionMock, GetPeerPid())
        .WillRepeatedly(testing::Return(2));

    std::string deviceId = "deviceId";
    EXPECT_CALL(*sessionMock, GetPeerDeviceId())
        .WillRepeatedly(testing::ReturnRef(deviceId));

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    skeleton->appInfoToStubIndex_.clear();

    std::string appInfo = deviceId + skeleton->UIntToString(pid) + skeleton->UIntToString(uid) +
        skeleton->UIntToString(tokenId);
    std::map<uint64_t, uint32_t> indexMap = {
        { stubIndex, listenFd }
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    IPCObjectStub stub;
    auto ret = testInvoker.ConnectRemoteObject2Session(&stub, handle, sessionObject);
    ASSERT_TRUE(ret);
    current->dbinderSessionObjects_.clear();
    current->commAuth_.clear();
}

/**
 * @tc.name: HasRawDataPackage001
 * @tc.desc: HasRawDataPackage return tr->sizeOfSelf in HasRawDataPackage
 * @tc.type: FUNC
 */
HWTEST_F(IPCDbinderDataBusInvokerTest, HasRawDataPackage001, TestSize.Level1)
{
    constexpr size_t MAX_RAWDATA_SIZE = 128 * 1024 * 1024;
    DBinderDatabusInvoker testInvoker;

    ssize_t len = MAX_RAWDATA_SIZE + 1;
    dbinder_transaction_data *tr = new dbinder_transaction_data();
    tr->magic = DBINDER_MAGICWORD;
    tr->cmd = BC_SEND_RAWDATA;
    tr->sizeOfSelf = static_cast<uint32_t>(len);

    auto ret = testInvoker.HasRawDataPackage(reinterpret_cast<const char *>(tr), len);
    ASSERT_TRUE(ret == MAX_RAWDATA_SIZE);
    delete tr;
}

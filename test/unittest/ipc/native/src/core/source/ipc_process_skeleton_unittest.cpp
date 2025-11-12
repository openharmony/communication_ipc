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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "binder_invoker.h"
#include "dbinder_session_object.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "stub_refcount_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {
namespace {
    const std::u16string DESCRIPTOR_TEST = u"test_descriptor";
    const std::u16string DESCRIPTOR_INVALID_TEST = u"";
    const std::string SERVICE_NAME_TEST = "serviceNameTest";
    const std::string DEVICE_ID_TEST = "deviceidTest";
    const std::string DEVICE_ID_SECOND_TEST = "deviceidTest_second";
    constexpr int HANDLE_TEST = 1;
    constexpr int HANDLE_INVALID_TEST = 0;
    constexpr int POLICY_TEST = 1;
    constexpr int PROTO_TEST = 1;
    constexpr int MAX_THREAD_NUM_TEST = 1;
    constexpr uint64_t NUM_TEST = 10;
    constexpr int32_t SOCKET_ID_TEST = 1;
    constexpr int32_t SOCKET2_ID_TEST = 2;
    constexpr uint64_t STUB_INDEX_TEST = 123;
    constexpr uint32_t TOKEN_ID = 1;
    constexpr int PID_TEST = 1;
    constexpr int PID2_TEST = 11;
    constexpr int UID_TEST = 1;
}

class IPCProcessSkeletonInterface {
public:
    IPCProcessSkeletonInterface() {};
    virtual ~IPCProcessSkeletonInterface() {};

    virtual bool LockObjectMutex() = 0;
    virtual bool UnlockObjectMutex() = 0;
    virtual sptr<IRemoteObject> QueryObject(const std::u16string &descriptor, bool lockFlag) = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual sptr<IRemoteObject> GetRegistryObject() = 0;
    virtual bool PingService(int32_t handle) = 0;
    virtual bool SetRegistryObject(sptr<IRemoteObject> &object) = 0;
    virtual int32_t StartServerListener(const std::string &ownName) = 0;
};

class IPCProcessSkeletonInterfaceMock : public IPCProcessSkeletonInterface {
public:
    IPCProcessSkeletonInterfaceMock();
    ~IPCProcessSkeletonInterfaceMock() override;

    MOCK_METHOD0(LockObjectMutex, bool());
    MOCK_METHOD0(UnlockObjectMutex, bool());
    MOCK_METHOD2(QueryObject, sptr<IRemoteObject>(const std::u16string &descriptor, bool lockFlag));
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
    MOCK_METHOD0(GetRegistryObject, sptr<IRemoteObject>());
    MOCK_METHOD1(PingService, bool(int32_t));
    MOCK_METHOD1(SetRegistryObject, bool(sptr<IRemoteObject> &object));
    MOCK_METHOD1(StartServerListener, int32_t(const std::string &ownName));
};

static void *g_interface = nullptr;

IPCProcessSkeletonInterfaceMock::IPCProcessSkeletonInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCProcessSkeletonInterfaceMock::~IPCProcessSkeletonInterfaceMock()
{
    g_interface = nullptr;
}

static IPCProcessSkeletonInterface *GetIPCProcessSkeletonInterface()
{
    return reinterpret_cast<IPCProcessSkeletonInterface *>(g_interface);
}

extern "C" {
    bool ProcessSkeleton::LockObjectMutex()
    {
        if (GetIPCProcessSkeletonInterface() == nullptr) {
            return true;
        }
        return GetIPCProcessSkeletonInterface()->LockObjectMutex();
    }
    bool ProcessSkeleton::UnlockObjectMutex()
    {
        if (GetIPCProcessSkeletonInterface() == nullptr) {
            return true;
        }
        return GetIPCProcessSkeletonInterface()->UnlockObjectMutex();
    }
    sptr<IRemoteObject> ProcessSkeleton::QueryObject(const std::u16string &descriptor, bool lockFlag)
    {
        if (GetIPCProcessSkeletonInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCProcessSkeletonInterface()->QueryObject(descriptor, lockFlag);
    }
    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        if (GetIPCProcessSkeletonInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCProcessSkeletonInterface()->GetRemoteInvoker(proto);
    }
    sptr<IRemoteObject> ProcessSkeleton::GetRegistryObject()
    {
        if (GetIPCProcessSkeletonInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCProcessSkeletonInterface()->GetRegistryObject();
    }
    bool BinderInvoker::PingService(int32_t handle)
    {
        if (GetIPCProcessSkeletonInterface() == nullptr) {
            return false;
        }
        return GetIPCProcessSkeletonInterface()->PingService(handle);
    }
    bool BinderInvoker::SetRegistryObject(sptr<IRemoteObject> &object)
    {
        if (GetIPCProcessSkeletonInterface() == nullptr) {
            return false;
        }
        return GetIPCProcessSkeletonInterface()->SetRegistryObject(object);
    }
    int32_t DatabusSocketListener::StartServerListener(const std::string &ownName)
    {
        if (GetIPCProcessSkeletonInterface() == nullptr) {
            return false;
        }
        return GetIPCProcessSkeletonInterface()->StartServerListener(ownName);
    }
}

class IPCProcessSkeletonUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void IPCProcessSkeletonUnitTest::SetUpTestCase()
{
}

void IPCProcessSkeletonUnitTest::TearDownTestCase()
{
}

void IPCProcessSkeletonUnitTest::SetUp() {}

void IPCProcessSkeletonUnitTest::TearDown() {}

/**
 * @tc.name: IsContainsObjectTest001
 * @tc.desc: Verify the IsContainsObject function object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsContainsObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    
    EXPECT_FALSE(skeleton->IsContainsObject(nullptr));
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: IsContainsObjectTest002
 * @tc.desc: Verify the IsContainsObject function when ProcessSkeleton::GetInstance() return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsContainsObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    sptr<IRemoteObject> obj = new (std::nothrow) IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST);
    ASSERT_TRUE(obj != nullptr);
    bool ret = skeleton->IsContainsObject(obj);
    EXPECT_FALSE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: AttachObjectTest001
 * @tc.desc: Verify the AttachObject function object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    EXPECT_FALSE(skeleton->AttachObject(nullptr));
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: AttachObjectTest002
 * @tc.desc: Verify the AttachObject function lockFlag is false
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    EXPECT_TRUE(skeleton->AttachObject(object, false));
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: AttachObjectTest003
 * @tc.desc: Verify the AttachObject function current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachObjectTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    bool ret = skeleton->AttachObject(object, false);
    EXPECT_FALSE(ret);
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
    current->exitFlag_ = false;
}

/**
 * @tc.name: DetachObjectTest001
 * @tc.desc: Verify the DetachObject function object is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"");
    EXPECT_FALSE(skeleton->DetachObject(object));
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: DetachObjectTest002
 * @tc.desc: Verify the DetachObject function object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    EXPECT_FALSE(skeleton->DetachObject(nullptr));
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: DetachObjectTest003
 * @tc.desc: Verify the DetachObject function when ProcessSkeleton::GetInstance() is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachObjectTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);
    EXPECT_FALSE(skeleton->DetachObject(object));
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: DetachObjectTest004
 * @tc.desc: Verify the DetachObject function when ProcessSkeleton::GetInstance() is valid value
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachObjectTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);
    bool ret = skeleton->DetachObject(object);
    EXPECT_FALSE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryAppInfoToStubIndexTest001
 * @tc.desc: Verify the QueryAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryAppInfoToStubIndexTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->appInfoToStubIndex_.clear();
    uint32_t pid = 1;
    uint32_t uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "testDeviceId";
    uint64_t stubIndex = 1;
    int32_t listenFd = 1;
    std::string appInfo = deviceId + skeleton->UIntToString(pid) + skeleton->UIntToString(uid) +
        skeleton->UIntToString(tokenId);
    std::map<uint64_t, int32_t> indexMap = {{ stubIndex, listenFd }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;
    bool ret = skeleton->QueryAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    EXPECT_TRUE(ret);

    skeleton->appInfoToStubIndex_.clear();
    std::map<uint64_t, int32_t> indexNewMap = {{ 0, listenFd }};
    skeleton->appInfoToStubIndex_[appInfo] = indexNewMap;
    ret = skeleton->QueryAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    EXPECT_FALSE(ret);
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: CreateSoftbusServerTest001
 * @tc.desc: Verify the CreateSoftbusServer function name is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, CreateSoftbusServerTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::string name = "";
    auto ret = skeleton->CreateSoftbusServer(name);
    EXPECT_EQ(ret, false);
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: CreateSoftbusServerTest002
 * @tc.desc: Verify the CreateSoftbusServer function when StartServerListener function return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, CreateSoftbusServerTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, StartServerListener(testing::_)).WillRepeatedly(Return(0));

    std::string name = SERVICE_NAME_TEST;
    auto ret = skeleton->CreateSoftbusServer(name);
    EXPECT_FALSE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: CreateSoftbusServerTest003
 * @tc.desc: Verify the CreateSoftbusServer function when sessionName_ not equal to name
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, CreateSoftbusServerTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, StartServerListener(testing::_)).WillRepeatedly(Return(1));

    std::string name = SERVICE_NAME_TEST;
    auto ret = skeleton->CreateSoftbusServer(name);
    EXPECT_TRUE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: CreateSoftbusServerTest004
 * @tc.desc: Verify the CreateSoftbusServer function when sessionName_ equal name
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, CreateSoftbusServerTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, StartServerListener(testing::_)).WillRepeatedly(Return(1));

    std::string name = SERVICE_NAME_TEST;
    skeleton->sessionName_ = SERVICE_NAME_TEST;
    auto ret = skeleton->CreateSoftbusServer(name);
    EXPECT_TRUE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    skeleton->sessionName_ = "";
}

/**
 * @tc.name: GetRegistryObjectTest001
 * @tc.desc: Verify the GetRegistryObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetRegistryObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    sptr<IRemoteObject> obj = new (std::nothrow) IPCObjectProxy(1, DESCRIPTOR_TEST);
    ASSERT_TRUE(obj != nullptr);
    EXPECT_CALL(mock, GetRegistryObject()).WillOnce(Return(obj));

    sptr<IRemoteObject> object = skeleton->GetRegistryObject();
    EXPECT_NE(object, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: GetRegistryObjectTest002
 * @tc.desc: Verify the GetRegistryObject function when ProcessSkeleton::GetInstance() return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetRegistryObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    sptr<IRemoteObject> object = skeleton->GetRegistryObject();
    EXPECT_EQ(object, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: GetRegistryObjectTest003
 * @tc.desc: Verify the GetRegistryObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetRegistryObjectTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, GetRegistryObject()).WillOnce(Return(nullptr));

    sptr<IRemoteObject> object = skeleton->GetRegistryObject();
    EXPECT_EQ(object, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: GetProxyObjectTest001
 * @tc.desc: Verify the GetProxyObject function when ProcessSkeleton::GetInstance() return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetProxyObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    bool newFlag = false;
    int handle = HANDLE_TEST;

    sptr<IRemoteObject> object = skeleton->GetProxyObject(handle, newFlag);
    EXPECT_EQ(object, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: GetProxyObjectTest002
 * @tc.desc: Verify the GetProxyObject function when LockObjectMutex function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetProxyObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    bool newFlag = false;
    int handle = HANDLE_TEST;
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, LockObjectMutex()).WillOnce(Return(false));

    sptr<IRemoteObject> object = skeleton->GetProxyObject(handle, newFlag);
    EXPECT_EQ(object, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: GetProxyObjectTest003
 * @tc.desc: Verify the GetProxyObject function when QueryObject function return a valid value obj
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetProxyObjectTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool newFlag = false;
    int handle = HANDLE_TEST;
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    sptr<IRemoteObject> obj = new (std::nothrow) IPCObjectProxy(handle, DESCRIPTOR_TEST);
    ASSERT_TRUE(obj != nullptr);
    EXPECT_CALL(mock, LockObjectMutex()).WillOnce(Return(true));
    EXPECT_CALL(mock, QueryObject(testing::_, testing::_)).WillOnce(Return(obj));

    sptr<IRemoteObject> object = skeleton->GetProxyObject(handle, newFlag);
    EXPECT_CALL(mock, UnlockObjectMutex()).WillRepeatedly(Return(true));
    EXPECT_EQ(object, obj);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: GetProxyObjectTest004
 * @tc.desc: Verify the GetProxyObject function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetProxyObjectTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool newFlag = false;
    int handle = HANDLE_INVALID_TEST;
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, LockObjectMutex()).WillOnce(Return(true));
    EXPECT_CALL(mock, QueryObject(testing::_, testing::_)).WillOnce(Return(nullptr));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(mock, UnlockObjectMutex()).WillRepeatedly(Return(true));

    sptr<IRemoteObject> object = skeleton->GetProxyObject(handle, newFlag);
    EXPECT_EQ(object, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: GetProxyObjectTest005
 * @tc.desc: Verify the GetProxyObject function when PingService function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetProxyObjectTest005, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool newFlag = false;
    int handle = HANDLE_INVALID_TEST;
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    BinderInvoker *invoker = new BinderInvoker();
    ASSERT_TRUE(invoker != nullptr);

    EXPECT_CALL(mock, LockObjectMutex()).WillOnce(Return(true));
    EXPECT_CALL(mock, QueryObject(testing::_, testing::_)).WillOnce(Return(nullptr));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(mock, PingService(testing::_)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, UnlockObjectMutex()).WillRepeatedly(Return(true));

    sptr<IRemoteObject> object = skeleton->GetProxyObject(handle, newFlag);
    EXPECT_EQ(object, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: GetProxyObjectTest006
 * @tc.desc: Verify the GetProxyObject function when PingService function return true and handle is 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetProxyObjectTest006, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool newFlag = false;
    int handle = HANDLE_TEST;
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, LockObjectMutex()).WillOnce(Return(true));
    EXPECT_CALL(mock, QueryObject(testing::_, testing::_)).WillOnce(Return(nullptr));
    EXPECT_CALL(mock, UnlockObjectMutex()).WillRepeatedly(Return(true));

    sptr<IRemoteObject> object = skeleton->GetProxyObject(handle, newFlag);
    EXPECT_NE(object, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: SetRegistryObjectTest001
 * @tc.desc: Verify the SetRegistryObject function when object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetRegistryObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = nullptr;
    bool ret = skeleton->SetRegistryObject(object);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetRegistryObjectTest002
 * @tc.desc: Verify the SetRegistryObject function when ProcessSkeleton::GetInstance() return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetRegistryObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);

    bool ret = skeleton->SetRegistryObject(object);
    EXPECT_FALSE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: SetRegistryObjectTest003
 * @tc.desc: Verify the SetRegistryObject function when GetRemoteInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetRegistryObjectTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);

    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));

    bool ret = skeleton->SetRegistryObject(object);
    EXPECT_FALSE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: SetRegistryObjectTest004
 * @tc.desc: Verify the SetRegistryObject function when ProcessSkeleton::GetInstance() return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetRegistryObjectTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);

    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    BinderInvoker *invoker = new BinderInvoker();
    ASSERT_TRUE(invoker != nullptr);

    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(mock, SetRegistryObject(testing::_)).WillRepeatedly(Return(true));

    bool ret = skeleton->SetRegistryObject(object);
    EXPECT_TRUE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: SetRegistryObjectTest005
 * @tc.desc: Verify the SetRegistryObject function when ProcessSkeleton::GetInstance() return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetRegistryObjectTest005, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);

    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    BinderInvoker *invoker = new BinderInvoker();
    ASSERT_TRUE(invoker != nullptr);

    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(invoker));
    EXPECT_CALL(mock, SetRegistryObject(testing::_)).WillRepeatedly(Return(false));

    bool ret = skeleton->SetRegistryObject(object);
    EXPECT_FALSE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    if (invoker != nullptr) {
        delete invoker;
    }
}

/**
 * @tc.name: SpawnThreadTest001
 * @tc.desc: Verify the SpawnThread function when threadPool_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SpawnThreadTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    int policy = POLICY_TEST;
    int proto = PROTO_TEST;
    skeleton->threadPool_ = nullptr;
    bool ret = skeleton->SpawnThread(policy, proto);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SpawnThreadTest002
 * @tc.desc: Verify the SpawnThread function when threadPool_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SpawnThreadTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    int policy = POLICY_TEST;
    int proto = PROTO_TEST;
    int maxThreadNum = MAX_THREAD_NUM_TEST;
    IPCWorkThreadPool *ipcThreadPool = new (std::nothrow) IPCWorkThreadPool(maxThreadNum);
    ASSERT_TRUE(ipcThreadPool != nullptr);

    skeleton->threadPool_ = ipcThreadPool;
    bool ret = skeleton->SpawnThread(policy, proto);
    EXPECT_TRUE(ret);
    if (ipcThreadPool != nullptr) {
        delete ipcThreadPool;
    }
}

/**
 * @tc.name: QueryObjectTest001
 * @tc.desc: Verify the QueryObject function when descriptor is valid value
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string descriptor = DESCRIPTOR_TEST;
    auto ret = skeleton->QueryObject(descriptor, false);
    EXPECT_EQ(ret, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryObjectTest002
 * @tc.desc: Verify the QueryObject function when descriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string descriptor = DESCRIPTOR_INVALID_TEST;
    auto ret = skeleton->QueryObject(descriptor, false);
    EXPECT_EQ(ret, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryObjectTest003
 * @tc.desc: Verify the QueryObject function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryObjectTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    std::u16string descriptor = DESCRIPTOR_INVALID_TEST;
    auto ret = skeleton->QueryObject(descriptor, false);
    EXPECT_EQ(ret, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: SetIPCProxyLimitTest001
 * @tc.desc: Verify the SetIPCProxyLimit function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetIPCProxyLimitTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    std::function<void(uint64_t)> callback = [](uint64_t) {};
    auto ret = skeleton->SetIPCProxyLimit(NUM_TEST, callback);
    EXPECT_FALSE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: SetIPCProxyLimitTest002
 * @tc.desc: Verify the SetIPCProxyLimit function when current->instance_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetIPCProxyLimitTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::function<void(uint64_t)> callback = [](uint64_t) {};
    auto ret = skeleton->SetIPCProxyLimit(NUM_TEST, callback);
    EXPECT_TRUE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: GetSAMgrObjectTest001
 * @tc.desc: Verify the GetSAMgrObject function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetSAMgrObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(current != nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    auto ret = skeleton->GetSAMgrObject();
    EXPECT_EQ(ret, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: ProxyMoveDBinderSessionTest001
 * @tc.desc: Verify the ProxyMoveDBinderSession function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ProxyMoveDBinderSessionTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(0);
    ASSERT_TRUE(proxy != nullptr);
    auto ret = skeleton->ProxyMoveDBinderSession(HANDLE_TEST, proxy);
    EXPECT_FALSE(ret);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: ProxyMoveDBinderSessionTest002
 * @tc.desc: Verify the ProxyMoveDBinderSession function when current->instance_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ProxyMoveDBinderSessionTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->proxyToSession_[HANDLE_TEST] = nullptr;
    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(0);
    ASSERT_TRUE(proxy != nullptr);
    auto ret = skeleton->ProxyMoveDBinderSession(HANDLE_TEST, proxy);
    EXPECT_FALSE(ret);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: ProxyMoveDBinderSessionTest003
 * @tc.desc: Verify the ProxyMoveDBinderSession function when remoteSession is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ProxyMoveDBinderSessionTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    skeleton->proxyToSession_[HANDLE_TEST] = remoteSession;
    sptr<IPCObjectProxy> proxy = new (std::nothrow) IPCObjectProxy(0);
    ASSERT_TRUE(proxy != nullptr);
    auto ret = skeleton->ProxyMoveDBinderSession(HANDLE_TEST, proxy);
    EXPECT_TRUE(ret);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryProxyBySocketIdTest001
 * @tc.desc: Verify the QueryProxyBySocketId function when it->second is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryProxyBySocketIdTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->proxyToSession_[HANDLE_TEST] = nullptr;
    std::vector<uint32_t> proxyHandle;
    bool result = skeleton->QueryProxyBySocketId(SOCKET_ID_TEST, proxyHandle);
    EXPECT_FALSE(result);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryProxyBySocketIdTest002
 * @tc.desc: Verify the QueryProxyBySocketId function when socketId not equal GetSocketId()
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryProxyBySocketIdTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    skeleton->proxyToSession_[HANDLE_TEST] = remoteSession;
    remoteSession->SetSocketId(2);
    std::vector<uint32_t> proxyHandle;
    bool result = skeleton->QueryProxyBySocketId(SOCKET_ID_TEST, proxyHandle);
    EXPECT_TRUE(result);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryProxyBySocketIdTest003
 * @tc.desc: Verify the QueryProxyBySocketId function when socketId equal GetSocketId()
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryProxyBySocketIdTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    skeleton->proxyToSession_[HANDLE_TEST] = remoteSession;
    remoteSession->SetSocketId(SOCKET_ID_TEST);
    std::vector<uint32_t> proxyHandle;
    bool result = skeleton->QueryProxyBySocketId(SOCKET_ID_TEST, proxyHandle);
    EXPECT_TRUE(result);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryHandleByDatabusSessionTest001
 * @tc.desc: Verify the QueryHandleByDatabusSession function when it->second is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryHandleByDatabusSessionTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->proxyToSession_[HANDLE_TEST] = nullptr;
    uint32_t result = skeleton->QueryHandleByDatabusSession(SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX_TEST);
    EXPECT_EQ(result, 0);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryHandleByDatabusSessionTest002
 * @tc.desc: Verify the QueryHandleByDatabusSession function when proxyToSession_ not contain match object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryHandleByDatabusSessionTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, 1, nullptr, 1);
    skeleton->proxyToSession_[HANDLE_TEST] = remoteSession;
    uint32_t result = skeleton->QueryHandleByDatabusSession(SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX_TEST);
    EXPECT_EQ(result, 0);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryHandleByDatabusSessionTest003
 * @tc.desc: Verify the QueryHandleByDatabusSession function when proxyToSession_ contain match object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryHandleByDatabusSessionTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX_TEST, nullptr, 1);
    skeleton->proxyToSession_[HANDLE_TEST] = remoteSession;
    uint32_t result = skeleton->QueryHandleByDatabusSession(SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX_TEST);
    EXPECT_EQ(result, HANDLE_TEST);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QuerySessionByInfoTest001
 * @tc.desc: Verify the QuerySessionByInfo function when it->second is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QuerySessionByInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->proxyToSession_[HANDLE_TEST] = nullptr;
    auto result = skeleton->QuerySessionByInfo(SERVICE_NAME_TEST, DEVICE_ID_TEST);
    EXPECT_EQ(result, nullptr);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QuerySessionByInfoTest002
 * @tc.desc: Verify the QuerySessionByInfo function when proxyToSession_ not contain match object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QuerySessionByInfoTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_SECOND_TEST, STUB_INDEX_TEST, nullptr, TOKEN_ID);
    skeleton->proxyToSession_[HANDLE_TEST] = remoteSession;
    auto result = skeleton->QuerySessionByInfo(SERVICE_NAME_TEST, DEVICE_ID_TEST);
    EXPECT_EQ(result, nullptr);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QuerySessionByInfoTest003
 * @tc.desc: Verify the QuerySessionByInfo function when proxyToSession_ contain match object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QuerySessionByInfoTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX_TEST, nullptr, TOKEN_ID);
    skeleton->proxyToSession_[HANDLE_TEST] = remoteSession;
    auto result = skeleton->QuerySessionByInfo(SERVICE_NAME_TEST, DEVICE_ID_TEST);
    EXPECT_EQ(result, remoteSession);
    skeleton->proxyToSession_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: StubDetachDBinderSessionTest001
 * @tc.desc: Verify the StubDetachDBinderSession function when it->second is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, StubDetachDBinderSessionTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->dbinderSessionObjects_[HANDLE_TEST] = nullptr;
    uint32_t tokenId = TOKEN_ID;
    auto result = skeleton->StubDetachDBinderSession(HANDLE_TEST, tokenId);
    EXPECT_FALSE(result);
    skeleton->dbinderSessionObjects_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: StubDetachDBinderSessionTest002
 * @tc.desc: Verify the StubDetachDBinderSession function when proxyToSession_ not contain match HANDLE_TEST
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, StubDetachDBinderSessionTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint32_t tokenId = TOKEN_ID;
    skeleton->dbinderSessionObjects_.clear();
    auto result = skeleton->StubDetachDBinderSession(HANDLE_TEST, tokenId);
    EXPECT_FALSE(result);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: StubDetachDBinderSessionTest003
 * @tc.desc: Verify the StubDetachDBinderSession function when dbinderSessionObjects_ contain match object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, StubDetachDBinderSessionTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_TEST, STUB_INDEX_TEST, nullptr, TOKEN_ID);
    skeleton->dbinderSessionObjects_[HANDLE_TEST] = remoteSession;
    uint32_t tokenId = TOKEN_ID;
    auto result = skeleton->StubDetachDBinderSession(HANDLE_TEST, tokenId);
    EXPECT_TRUE(result);
    skeleton->dbinderSessionObjects_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: StubQueryDBinderSessionTest001
 * @tc.desc: Verify the StubQueryDBinderSession function when dbinderSessionObjects_ contain match HANDLE_TEST
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, StubQueryDBinderSessionTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<DBinderSessionObject> remoteSession = std::make_shared<DBinderSessionObject>(
        SERVICE_NAME_TEST, DEVICE_ID_SECOND_TEST, STUB_INDEX_TEST, nullptr, TOKEN_ID);
    skeleton->dbinderSessionObjects_[HANDLE_TEST] = remoteSession;
    auto result = skeleton->StubQueryDBinderSession(HANDLE_TEST);
    skeleton->dbinderSessionObjects_.clear();
    EXPECT_EQ(result, remoteSession);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: StubQueryDBinderSessionTest002
 * @tc.desc: Verify the StubQueryDBinderSession function when dbinderSessionObjects_ not contain match HANDLE_TEST
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, StubQueryDBinderSessionTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->dbinderSessionObjects_.clear();
    auto result = skeleton->StubQueryDBinderSession(HANDLE_TEST);
    EXPECT_EQ(result, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: AddSendThreadInWaitTest001
 * @tc.desc: Verify the AddSendThreadInWait function when messageInfo is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddSendThreadInWaitTest001, TestSize.Level1)
{
    uint64_t seqNumber = 1;
    int userWaitTime = 1;
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    auto messageInfo = nullptr;
    bool ret = skeleton->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddSendThreadInWaitTest002
 * @tc.desc: Verify the AddSendThreadInWait function AddThreadBySeqNumber function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddSendThreadInWaitTest002, TestSize.Level1)
{
    uint64_t seqNumber = 1;
    int userWaitTime = 1;
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumberToThread_.clear();
    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = 1;
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);

    bool ret = skeleton->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddSendThreadInWaitTest003
 * @tc.desc: Verify the AddSendThreadInWait function when messageInfo->ready is false
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddSendThreadInWaitTest003, TestSize.Level1)
{
    uint64_t seqNumber = 1;
    int userWaitTime = 1;
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumberToThread_.clear();
    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = 1;
    messageInfo->ready = false;

    bool ret = skeleton->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddSendThreadInWaitTest004
 * @tc.desc: Verify the AddSendThreadInWait function when messageInfo->ready is true
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddSendThreadInWaitTest004, TestSize.Level1)
{
    uint64_t seqNumber = 1;
    int userWaitTime = 1;
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumberToThread_.clear();
    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = 1;
    messageInfo->ready = true;

    bool ret = skeleton->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: QueryStubByIndexTest001
 * @tc.desc: Verify the QueryStubByIndex function when stubIndex is 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryStubByIndexTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t stubIndex = 0;
    auto ret = skeleton->QueryStubByIndex(stubIndex);
    EXPECT_EQ(ret, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryStubByIndexTest002
 * @tc.desc: Verify the QueryStubByIndex function when stubObjects_ not contain stubIndex
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryStubByIndexTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t stubIndex = 1;
    skeleton->stubObjects_.clear();
    auto ret = skeleton->QueryStubByIndex(stubIndex);
    EXPECT_EQ(ret, nullptr);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryStubByIndexTest003
 * @tc.desc: Verify the QueryStubByIndex function when stubObjects_ contain stubIndex
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryStubByIndexTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t stubIndex = 1;
    sptr<IRemoteObject> object = new (std::nothrow) IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);

    skeleton->stubObjects_.clear();
    skeleton->stubObjects_[1] = object;
    auto ret = skeleton->QueryStubByIndex(stubIndex);
    EXPECT_EQ(ret, object);
    skeleton->stubObjects_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: DetachCommAuthInfoTest001
 * @tc.desc: Verify the DetachCommAuthInfo function when commAuth_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachCommAuthInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->commAuth_.clear();
    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    auto ret = skeleton->DetachCommAuthInfo(stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST);
    EXPECT_EQ(ret, false);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: DetachCommAuthInfoTest002
 * @tc.desc: Verify the DetachCommAuthInfo function when commAuth_ is not empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachCommAuthInfoTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);
    auto ret = skeleton->DetachCommAuthInfo(stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST);
    EXPECT_EQ(ret, true);
    skeleton->commAuth_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryCommAuthInfoTest001
 * @tc.desc: Verify the QueryCommAuthInfo function when it != commAuth_.end()
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryCommAuthInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint32_t tokenId = TOKEN_ID;
    std::string deviceId = DEVICE_ID_TEST;
    skeleton->commAuth_.clear();
    auto ret = skeleton->QueryCommAuthInfo(PID_TEST, UID_TEST, tokenId, deviceId);
    EXPECT_EQ(ret, false);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: QueryCommAuthInfoTest002
 * @tc.desc: Verify the QueryCommAuthInfo function when it != commAuth_.end()
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryCommAuthInfoTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint32_t tokenId = TOKEN_ID;
    std::string deviceId = DEVICE_ID_TEST;
    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), PID_TEST, UID_TEST, tokenId, deviceId);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);
    auto ret = skeleton->QueryCommAuthInfo(PID_TEST, UID_TEST, tokenId, deviceId);
    EXPECT_EQ(ret, true);
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: UpdateCommAuthSocketInfoTest001
 * @tc.desc: Verify the UpdateCommAuthSocketInfo function when it != commAuth_.end()
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, UpdateCommAuthSocketInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint32_t tokenId = TOKEN_ID;
    std::string deviceId = DEVICE_ID_TEST;
    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), PID_TEST, UID_TEST, tokenId, deviceId);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);
    ASSERT_NO_FATAL_FAILURE(skeleton->UpdateCommAuthSocketInfo(PID_TEST, UID_TEST, tokenId, deviceId, SOCKET_ID_TEST));
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: AttachOrUpdateAppAuthInfoTest001
 * @tc.desc: Verify the AttachOrUpdateAppAuthInfo function
 * when appAuthInfo.stub equal nullptr and appInfoToStubIndex_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachOrUpdateAppAuthInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = nullptr;
    appAuthInfo.stubIndex = STUB_INDEX_TEST;

    skeleton->appInfoToStubIndex_.clear();
    auto result = skeleton->AttachOrUpdateAppAuthInfo(appAuthInfo);
    EXPECT_EQ(result, false);
    skeleton->appInfoToStubIndex_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: AttachOrUpdateAppAuthInfoTest002
 * @tc.desc: Verify the AttachOrUpdateAppAuthInfo function when appAuthInfo.stub equal nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachOrUpdateAppAuthInfoTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = nullptr;
    appAuthInfo.stubIndex = STUB_INDEX_TEST;

    std::string appInfo = appAuthInfo.deviceId + skeleton->UIntToString(appAuthInfo.pid) +
        skeleton->UIntToString(appAuthInfo.uid) + skeleton->UIntToString(appAuthInfo.tokenId);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, TOKEN_ID }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    auto result = skeleton->AttachOrUpdateAppAuthInfo(appAuthInfo);
    EXPECT_EQ(result, false);
    skeleton->appInfoToStubIndex_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: AttachOrUpdateAppAuthInfoTest003
 * @tc.desc: Verify the AttachOrUpdateAppAuthInfo function
 * when iter not equal to commAuth_.end() and appAuthInfo.socketId not equal to 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachOrUpdateAppAuthInfoTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = stubObject;
    appAuthInfo.stubIndex = HANDLE_INVALID_TEST;
    appAuthInfo.socketId = SOCKET_ID_TEST;

    std::string appInfo = appAuthInfo.deviceId + skeleton->UIntToString(appAuthInfo.pid) +
        skeleton->UIntToString(appAuthInfo.uid) + skeleton->UIntToString(appAuthInfo.tokenId);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, TOKEN_ID }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);

    auto result = skeleton->AttachOrUpdateAppAuthInfo(appAuthInfo);
    EXPECT_EQ(result, false);
    skeleton->appInfoToStubIndex_.clear();
    skeleton->commAuth_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: AttachOrUpdateAppAuthInfoTest004
 * @tc.desc: Verify the AttachOrUpdateAppAuthInfo function return true when appAuthInfo.socketId is 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachOrUpdateAppAuthInfoTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = stubObject;
    appAuthInfo.stubIndex = HANDLE_INVALID_TEST;
    appAuthInfo.socketId = HANDLE_INVALID_TEST;

    std::string appInfo = appAuthInfo.deviceId + skeleton->UIntToString(appAuthInfo.pid) +
        skeleton->UIntToString(appAuthInfo.uid) + skeleton->UIntToString(appAuthInfo.tokenId);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, TOKEN_ID }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    auto result = skeleton->AttachOrUpdateAppAuthInfo(appAuthInfo);
    EXPECT_EQ(result, true);
    skeleton->appInfoToStubIndex_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: DetachAppAuthInfoTest001
 * @tc.desc: Verify the DetachAppAuthInfo function return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppAuthInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = nullptr;
    appAuthInfo.stubIndex = STUB_INDEX_TEST;
    appAuthInfo.socketId = SOCKET_ID_TEST;

    std::string appInfo = appAuthInfo.deviceId + skeleton->UIntToString(appAuthInfo.pid) +
        skeleton->UIntToString(appAuthInfo.uid) + skeleton->UIntToString(appAuthInfo.tokenId);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, SOCKET_ID_TEST }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    auto result = skeleton->DetachAppAuthInfo(appAuthInfo);
    EXPECT_EQ(result, true);
    skeleton->appInfoToStubIndex_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: DetachAppAuthInfoTest002
 * @tc.desc: Verify the DetachAppAuthInfo function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppAuthInfoTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = nullptr;
    appAuthInfo.stubIndex = STUB_INDEX_TEST;
    appAuthInfo.socketId = SOCKET_ID_TEST;

    std::string appInfo = appAuthInfo.deviceId + skeleton->UIntToString(appAuthInfo.pid) +
        skeleton->UIntToString(appAuthInfo.uid) + skeleton->UIntToString(appAuthInfo.tokenId);
    std::map<uint64_t, int32_t> indexMap = {{ TOKEN_ID, SOCKET_ID_TEST }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    auto result = skeleton->DetachAppAuthInfo(appAuthInfo);
    EXPECT_EQ(result, false);
    skeleton->appInfoToStubIndex_.clear();
    skeleton->exitFlag_ = false;
    skeleton->instance_ = nullptr;
}

/**
 * @tc.name: DetachAppAuthInfoBySocketIdTest001
 * @tc.desc: Verify the DetachAppAuthInfoBySocketId function when auth->GetRemoteSocketId() == socketId
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppAuthInfoBySocketIdTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth = std::make_shared<CommAuthInfo>(
        stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST, SOCKET_ID_TEST);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);

    std::list<uint64_t> result = skeleton->DetachAppAuthInfoBySocketId(SOCKET_ID_TEST);
    EXPECT_EQ(result.size(), 0);
    skeleton->commAuth_.clear();
}

/**
 * @tc.name: DetachAppAuthInfoBySocketIdTest002
 * @tc.desc: Verify the DetachAppAuthInfoBySocketId function when it2->second == socketId
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppAuthInfoBySocketIdTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth = std::make_shared<CommAuthInfo>(
        stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST, SOCKET_ID_TEST);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);

    std::string appInfo = DEVICE_ID_TEST + skeleton->UIntToString(PID_TEST) + skeleton->UIntToString(UID_TEST) +
        skeleton->UIntToString(TOKEN_ID);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, SOCKET2_ID_TEST }};
    skeleton->appInfoToStubIndex_.clear();
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    std::list<uint64_t> result = skeleton->DetachAppAuthInfoBySocketId(SOCKET2_ID_TEST);
    EXPECT_GT(result.size(), 0);
    skeleton->commAuth_.clear();
    skeleton->appInfoToStubIndex_.clear();
}

/**
 * @tc.name: DetachAppAuthInfoBySocketIdTest003
 * @tc.desc: Verify the DetachAppAuthInfoBySocketId function when it2->second != socketId
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppAuthInfoBySocketIdTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth = std::make_shared<CommAuthInfo>(
        stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST, SOCKET_ID_TEST);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);

    std::string appInfo = DEVICE_ID_TEST + skeleton->UIntToString(PID_TEST) + skeleton->UIntToString(UID_TEST) +
        skeleton->UIntToString(TOKEN_ID);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, SOCKET2_ID_TEST }};
    skeleton->appInfoToStubIndex_.clear();
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    std::list<uint64_t> result = skeleton->DetachAppAuthInfoBySocketId(3);
    EXPECT_EQ(result.size(), 0);
    skeleton->commAuth_.clear();
    skeleton->appInfoToStubIndex_.clear();
}

/**
 * @tc.name: DetachAppAuthInfoBySocketIdTest004
 * @tc.desc: Verify the DetachAppAuthInfoBySocketId function when indexMap is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppAuthInfoBySocketIdTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth = std::make_shared<CommAuthInfo>(
        stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST, SOCKET_ID_TEST);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);

    std::string appInfo = DEVICE_ID_TEST + skeleton->UIntToString(PID_TEST) + skeleton->UIntToString(UID_TEST) +
        skeleton->UIntToString(TOKEN_ID);
    std::map<uint64_t, int32_t> indexMap = {};
    skeleton->appInfoToStubIndex_.clear();
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    std::list<uint64_t> result = skeleton->DetachAppAuthInfoBySocketId(3);
    EXPECT_EQ(result.size(), 0);
    skeleton->commAuth_.clear();
    skeleton->appInfoToStubIndex_.clear();
}

/**
 * @tc.name: QueryAppInfoToStubIndexTest002
 * @tc.desc: Verify the QueryAppInfoToStubIndex function when return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryAppInfoToStubIndexTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = nullptr;
    appAuthInfo.stubIndex = STUB_INDEX_TEST;
    appAuthInfo.socketId = SOCKET_ID_TEST;

    std::string appInfo = DEVICE_ID_TEST + skeleton->UIntToString(PID_TEST) + skeleton->UIntToString(UID_TEST) +
        skeleton->UIntToString(TOKEN_ID);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, 5 }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    auto result = skeleton->QueryAppInfoToStubIndex(appAuthInfo);
    EXPECT_EQ(result, false);
    skeleton->commAuth_.clear();
}

/**
 * @tc.name: QueryAppInfoToStubIndexTest003
 * @tc.desc: Verify the QueryAppInfoToStubIndex function when it2->second == 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryAppInfoToStubIndexTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = nullptr;
    appAuthInfo.stubIndex = STUB_INDEX_TEST;
    appAuthInfo.socketId = SOCKET_ID_TEST;

    std::string appInfo = DEVICE_ID_TEST + skeleton->UIntToString(PID_TEST) + skeleton->UIntToString(UID_TEST) +
        skeleton->UIntToString(TOKEN_ID);
    std::string appInfo2 = DEVICE_ID_TEST + skeleton->UIntToString(PID2_TEST) + skeleton->UIntToString(UID_TEST) +
        skeleton->UIntToString(TOKEN_ID);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, HANDLE_INVALID_TEST }, { NUM_TEST, PID_TEST }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;
    skeleton->appInfoToStubIndex_[appInfo2] = indexMap;

    auto result = skeleton->QueryAppInfoToStubIndex(appAuthInfo);
    EXPECT_EQ(result, true);
    skeleton->commAuth_.clear();
}

/**
 * @tc.name: QueryAppInfoToStubIndexTest004
 * @tc.desc: Verify the QueryAppInfoToStubIndex function when it2->second == appAuthInfo.socketId
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryAppInfoToStubIndexTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = nullptr;
    appAuthInfo.stubIndex = STUB_INDEX_TEST;
    appAuthInfo.socketId = SOCKET_ID_TEST;

    std::string appInfo = DEVICE_ID_TEST + skeleton->UIntToString(PID_TEST) + skeleton->UIntToString(UID_TEST) +
        skeleton->UIntToString(TOKEN_ID);
    std::string appInfo2 = DEVICE_ID_TEST + skeleton->UIntToString(PID2_TEST) + skeleton->UIntToString(UID_TEST) +
        skeleton->UIntToString(TOKEN_ID);
    std::map<uint64_t, int32_t> indexMap = {{ STUB_INDEX_TEST, SOCKET_ID_TEST }, { NUM_TEST, SOCKET_ID_TEST }};
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;
    skeleton->appInfoToStubIndex_[appInfo2] = indexMap;

    auto result = skeleton->QueryAppInfoToStubIndex(appAuthInfo);
    EXPECT_EQ(result, true);
    skeleton->commAuth_.clear();
}

/**
 * @tc.name: DetachCommAuthInfoByStubTest001
 * @tc.desc: Verify the DetachCommAuthInfoByStub function when auth->GetStubObject() == stubObject
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachCommAuthInfoByStubTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth = std::make_shared<CommAuthInfo>(
        stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST, SOCKET_ID_TEST);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);

    skeleton->DetachCommAuthInfoByStub(stubObject);
    EXPECT_EQ(auth->GetStubObject(), stubObject);
    skeleton->commAuth_.clear();
}

/**
 * @tc.name: QueryCommAuthInfoTest003
 * @tc.desc: Verify the QueryCommAuthInfo function when appAuthInfo.pid is PID_TEST or PID2_TEST
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryCommAuthInfoTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->exitFlag_ = false;

    sptr<IRemoteObject> stubObject = new IPCObjectStub(DESCRIPTOR_TEST);
    std::shared_ptr<CommAuthInfo> auth = std::make_shared<CommAuthInfo>(
        stubObject.GetRefPtr(), PID_TEST, UID_TEST, TOKEN_ID, DEVICE_ID_TEST, SOCKET_ID_TEST);
    skeleton->commAuth_.clear();
    skeleton->commAuth_.push_back(auth);

    AppAuthInfo appAuthInfo;
    appAuthInfo.deviceId = DEVICE_ID_TEST;
    appAuthInfo.pid = PID_TEST;
    appAuthInfo.uid = UID_TEST;
    appAuthInfo.tokenId = TOKEN_ID;
    appAuthInfo.stub = nullptr;
    appAuthInfo.stubIndex = STUB_INDEX_TEST;
    appAuthInfo.socketId = SOCKET_ID_TEST;

    auto result = skeleton->QueryCommAuthInfo(appAuthInfo);
    EXPECT_EQ(result, true);

    appAuthInfo.pid = PID2_TEST;
    result = skeleton->QueryCommAuthInfo(appAuthInfo);
    EXPECT_EQ(result, false);
    skeleton->commAuth_.clear();
}
} // namespace OHOS
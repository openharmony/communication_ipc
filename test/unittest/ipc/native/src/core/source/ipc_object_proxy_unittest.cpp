/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define private public
#include "dbinder_databus_invoker.h"
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "mock_iremote_invoker.h"
#include "mock_iremote_object.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {
class IPCObjectProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCObjectProxyTest::SetUpTestCase()
{
}

void IPCObjectProxyTest::TearDownTestCase()
{
}

void IPCObjectProxyTest::SetUp()
{
}

void IPCObjectProxyTest::TearDown()
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

class IpcObjectProxyInterface {
public:
    IpcObjectProxyInterface() {};
    virtual ~IpcObjectProxyInterface() {};
    virtual IPCProcessSkeleton *GetCurrent() = 0;
    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual bool CreateSoftbusServer(const std::string &name) = 0;
    virtual bool UpdateClientSession(std::shared_ptr<DBinderSessionObject> sessionObject) = 0;
    virtual bool ProxyAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object) = 0;
    virtual std::shared_ptr<DBinderSessionObject> QuerySessionByInfo(const std::string &name,
            const std::string &deviceId) = 0;
    virtual uint32_t ReadUint32() = 0;
    virtual const std::u16string ReadString16() = 0;
};

class IpcObjectProxyInterfaceMock : public IpcObjectProxyInterface {
public:
    IpcObjectProxyInterfaceMock();
    ~IpcObjectProxyInterfaceMock() override;
    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton *());
    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int proto));
    MOCK_METHOD1(CreateSoftbusServer, bool(const std::string &name));
    MOCK_METHOD1(UpdateClientSession, bool(std::shared_ptr<DBinderSessionObject> sessionObject));
    MOCK_METHOD2(ProxyAttachDBinderSession, bool(uint32_t handle, std::shared_ptr<DBinderSessionObject> object));
    MOCK_METHOD2(QuerySessionByInfo, std::shared_ptr<DBinderSessionObject>(
        const std::string &name, const std::string &deviceId));
    MOCK_METHOD0(ReadUint32, uint32_t());
    MOCK_METHOD0(ReadString16, const std::u16string());
};

static void *g_interface = nullptr;

IpcObjectProxyInterfaceMock::IpcObjectProxyInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IpcObjectProxyInterfaceMock::~IpcObjectProxyInterfaceMock()
{
    g_interface = nullptr;
}

static IpcObjectProxyInterface *GetIpcObjectProxyInterface()
{
    return reinterpret_cast<IpcObjectProxyInterface*>(g_interface);
}
extern "C" {
    IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
    {
        IpcObjectProxyInterface* interface = GetIpcObjectProxyInterface();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->GetCurrent();
    }

    IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
    {
        IpcObjectProxyInterface* interface = GetIpcObjectProxyInterface();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->GetRemoteInvoker(proto);
    }

    bool IPCProcessSkeleton::CreateSoftbusServer(const std::string &name)
    {
        IpcObjectProxyInterface* interface = GetIpcObjectProxyInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->CreateSoftbusServer(name);
    }

    bool DBinderDatabusInvoker::UpdateClientSession(std::shared_ptr<DBinderSessionObject> sessionObject)
    {
        IpcObjectProxyInterface* interface = GetIpcObjectProxyInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->UpdateClientSession(sessionObject);
    }

    bool IPCProcessSkeleton::ProxyAttachDBinderSession(uint32_t handle, std::shared_ptr<DBinderSessionObject> object)
    {
        IpcObjectProxyInterface* interface = GetIpcObjectProxyInterface();
        if (interface == nullptr) {
            return false;
        }
        return interface->ProxyAttachDBinderSession(handle, object);
    }

    std::shared_ptr<DBinderSessionObject> IPCProcessSkeleton::QuerySessionByInfo(const std::string &name,
                                                                                 const std::string &deviceId)
    {
        IpcObjectProxyInterface* interface = GetIpcObjectProxyInterface();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->QuerySessionByInfo(name, deviceId);
    }

    uint32_t Parcel::ReadUint32()
    {
        IpcObjectProxyInterface* interface = GetIpcObjectProxyInterface();
        if (interface == nullptr) {
            return 0;
        }
        return interface->ReadUint32();
    }

    const std::u16string Parcel::ReadString16()
    {
        IpcObjectProxyInterface* interface = GetIpcObjectProxyInterface();
        if (interface == nullptr) {
            return 0;
        }
        return interface->ReadString16();
    }
}

/**
 * @tc.name: GetInterfaceDescriptorTest001
 * @tc.desc: Test GetInterfaceDescriptor when the interfaceDesc_ not empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.interfaceDesc_ = u"test";
    auto ret = object.GetInterfaceDescriptor();
    EXPECT_EQ(ret, u"test");
}

/**
 * @tc.name: GetInterfaceDescriptorTest002
 * @tc.desc: Test GetInterfaceDescriptor when the handle is 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest002, TestSize.Level1)
{
    IPCObjectProxy object(0);
    auto ret = object.GetInterfaceDescriptor();
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: GetInterfaceDescriptorTest003
 * @tc.desc: Test for get descriptor when SendRequestInner return error
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.remoteDescriptor_ = "testDesc";
    // test for stub already died
    object.isRemoteDead_ = true;
    auto ret = object.GetInterfaceDescriptor();
    object.isRemoteDead_ = false;
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: GetInterfaceDescriptorTest004
 * @tc.desc: Test for get descriptor when SendRequestInner return success
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest004, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.remoteDescriptor_ = "testDesc";
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_NONE));
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(testing::Return(invoker));
    EXPECT_CALL(mock, ReadString16()).WillOnce(testing::Return(u"testDesc"));
    auto ret = object.GetInterfaceDescriptor();
    delete invoker;
    EXPECT_EQ(ret, u"testDesc");
}

/**
 * @tc.name: GetProtoInfoTest001
 * @tc.desc: Verify the IPCObjectProxy::GetProtoInfo function when handle_ >= DBINDER_HANDLE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetProtoInfoTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->handle_= IPCProcessSkeleton::DBINDER_HANDLE_BASE;
    auto ret = object->GetProtoInfo();
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_ERROR);
}

/**
 * @tc.name: GetProtoInfoTest002
 * @tc.desc: Verify the IPCObjectProxy::GetProtoInfo function when SendRequestInner return error
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetProtoInfoTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->SetObjectDied(true);
    object->handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE - 1;
    auto ret = object->GetProtoInfo();
    object->SetObjectDied(false);
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_ERROR);
}

/**
 * @tc.name: GetProtoInfoTest003
 * @tc.desc: Verify the IPCObjectProxy::GetProtoInfo function when SendRequestInner get reply IF_PROT_BINDER
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetProtoInfoTest003, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(mock, ReadUint32()).WillRepeatedly(testing::Return(IRemoteObject::IF_PROT_BINDER));
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_NONE));
    object->SetObjectDied(false);
    object->handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE - 1;
    auto ret = object->GetProtoInfo();
    delete invoker;
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_BINDER);
}

/**
 * @tc.name: GetProtoInfoTest004
 * @tc.desc: Verify the IPCObjectProxy::GetProtoInfo function when SendRequestInner get reply IF_PROT_DATABUS
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetProtoInfoTest004, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE - 1;
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(mock, ReadUint32()).WillRepeatedly(testing::Return(IRemoteObject::IF_PROT_DATABUS));
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_NONE));
    auto ret = object->GetProtoInfo();
    delete invoker;
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_ERROR);
}

/**
 * @tc.name: GetProtoInfoTest005
 * @tc.desc: Verify the IPCObjectProxy::GetProtoInfo function when SendRequestInner get reply IF_PROT_DEFAULT
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetProtoInfoTest005, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(mock, ReadUint32()).WillRepeatedly(testing::Return(IRemoteObject::IF_PROT_DATABUS + 5));
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_NONE));
    object->handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE - 1;
    auto ret = object->GetProtoInfo();
    delete invoker;
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_ERROR);
}

/**
 * @tc.name: AddDeathRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::AddDeathRecipient function when recipient nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDeathRecipient001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    bool ret = object.AddDeathRecipient(nullptr);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: AddDeathRecipientTest002
 * @tc.desc: Verify the IPCObjectProxy::AddDeathRecipient function when IsObjectDead return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDeathRecipient002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    object.SetObjectDied(true);
    bool ret = object.AddDeathRecipient(death.GetRefPtr());
    object.SetObjectDied(false);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: AddDeathRecipientTest003
 * @tc.desc: Verify the IPCObjectProxy::AddDeathRecipient function when recipients_.size() > 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDeathRecipient003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> recipient1 = new MockDeathRecipient();
    ASSERT_NE(recipient1, nullptr);
    EXPECT_TRUE(object.AddDeathRecipient(recipient1));
    sptr<IRemoteObject::DeathRecipient> recipient2 = new MockDeathRecipient();
    ASSERT_NE(recipient2, nullptr);
    EXPECT_TRUE(object.AddDeathRecipient(recipient2));
}

/**
 * @tc.name: AddDeathRecipientTest004
 * @tc.desc: Verify the IPCObjectProxy::AddDeathRecipient function when handle_ >= DBINDER_HANDLE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDeathRecipient004, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    uint32_t tmp = object.handle_;
    object.handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE;
    bool ret = object.AddDeathRecipient(death.GetRefPtr());
    object.handle_ = tmp;
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: AddDeathRecipientTest005
 * @tc.desc: Verify the IPCObjectProxy::AddDeathRecipient function when RegisterBinderDeathRecipient rturn false
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDeathRecipient005, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(testing::Return(nullptr));
    object.proto_ = IRemoteObject::IF_PROT_DATABUS;
    bool ret = object.AddDeathRecipient(death.GetRefPtr());
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: RemoveDeathRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function when recipient nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    bool ret = object.RemoveDeathRecipient(nullptr);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: RemoveDeathRecipientTest002
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function when IsObjectDead return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    object.SetObjectDied(true);
    bool ret = object.RemoveDeathRecipient(death.GetRefPtr());
    object.SetObjectDied(false);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: RemoveDeathRecipientTest003
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function when handle_ >= DBINDER_HANDLE_BASE
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    uint32_t tmp = object.handle_;
    object.handle_ = IPCProcessSkeleton::DBINDER_HANDLE_BASE;
    object.AddDeathRecipient(death.GetRefPtr());
    bool ret = object.RemoveDeathRecipient(death.GetRefPtr());
    object.handle_ = tmp;
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: UpdateProtoTest001
 * @tc.desc: Verify the IPCObjectProxy::UpdateProto function when CheckHaveSession return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateProtoTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = "test";
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    auto ret = object.UpdateProto(nullptr);
    ASSERT_TRUE(ret == true);
}

/**
 * @tc.name: UpdateProtoTest002
 * @tc.desc: Verify the IPCObjectProxy::UpdateProto function when dbinderData_ nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateProtoTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = "test";
    std::unique_ptr<uint8_t[]> temp = std::move(object.dbinderData_);
    dbinder_negotiation_data dbinderData = {
        .proto = IRemoteObject::IF_PROT_DATABUS,
        .tokenid = 0,
        .stub_index = 0,
        .target_name = "target_name",
        .local_name = "local_name",
        .target_device = "target_device",
        .local_device = "local_device",
        .desc = {},
        .reserved = {0, 0, 0}
    };

    auto ret = object.UpdateProto(&dbinderData);
    ASSERT_FALSE(ret);
    object.dbinderData_ = std::move(temp);
}

/**
 * @tc.name: UpdateProtoTest003
 * @tc.desc: Verify the IPCObjectProxy::UpdateProto function when UpdateDatabusClientSession return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateProtoTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = "test";
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillRepeatedly(Return(nullptr));
    dbinder_negotiation_data dbinderData = {
        .proto = IRemoteObject::IF_PROT_DATABUS,
        .tokenid = 0,
        .stub_index = 0,
        .target_name = "target_name",
        .local_name = "local_name",
        .target_device = "target_device",
        .local_device = "local_device",
        .desc = {},
        .reserved = {0, 0, 0}
    };

    auto ret = object.UpdateProto(&dbinderData);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetStrongRefCountForStubTest001
 * @tc.desc: Verify the GetStrongRefCountForStub function when invoker nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetStrongRefCountForStubTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;
    uint32_t count = object->GetStrongRefCountForStub();
    ASSERT_TRUE(count == 0);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest001
 * @tc.desc: Verify the AddDbinderDeathRecipient function when function GetCurrent nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDbinderDeathRecipientTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    auto ret = object->AddDbinderDeathRecipient();
    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: MakeDBinderTransSessionTest001
 * @tc.desc: Verify the MakeDBinderTransSession function when GetRemoteInvoker return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, MakeDBinderTransSessionTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(nullptr));
    DBinderNegotiationData data = {
        .peerPid = 0,
        .peerUid = 0,
        .peerTokenId = 0,
        .stubIndex = 0,
        .peerServiceName = "test",
        .peerDeviceId = "test",
        .localServiceName = "test",
        .localDeviceId = "test"
    };
    auto ret = object->MakeDBinderTransSession(data);
    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: MakeDBinderTransSessionTest002
 * @tc.desc: Verify the MakeDBinderTransSession function when GetCurrent return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, MakeDBinderTransSessionTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(nullptr));
    DBinderNegotiationData data = {
        .peerPid = 0,
        .peerUid = 0,
        .peerTokenId = 0,
        .stubIndex = 0,
        .peerServiceName = "test",
        .peerDeviceId = "test",
        .localServiceName = "test",
        .localDeviceId = "test"
    };
    auto ret = object->MakeDBinderTransSession(data);
    delete invoker;
    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: MakeDBinderTransSessionTest003
 * @tc.desc: Verify the MakeDBinderTransSession function when peerServiceName is empty
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, MakeDBinderTransSessionTest003, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCProcessSkeleton *current = new IPCProcessSkeleton();
    IPCThreadSkeleton *currentptr = IPCThreadSkeleton::GetCurrent();
    currentptr->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(current));
    DBinderNegotiationData data = {
        .peerPid = 0,
        .peerUid = 0,
        .peerTokenId = 0,
        .stubIndex = 0,
        .peerServiceName = "",
        .peerDeviceId = "test",
        .localServiceName = "test",
        .localDeviceId = "test"
    };
    auto ret = object->MakeDBinderTransSession(data);
    delete current;
    delete invoker;
    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: MakeDBinderTransSessionTest004
 * @tc.desc: Verify the MakeDBinderTransSession function when CreateSoftbusServer return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, MakeDBinderTransSessionTest004, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCProcessSkeleton *current = new IPCProcessSkeleton();
    IPCThreadSkeleton *currentptr = IPCThreadSkeleton::GetCurrent();
    currentptr->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    NiceMock<IpcObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker(testing::_)).WillOnce(Return(invoker));
    EXPECT_CALL(mock, GetCurrent()).WillOnce(Return(current));
    EXPECT_CALL(mock, CreateSoftbusServer(testing::_)).WillOnce(Return(false));
    DBinderNegotiationData data = {
        .peerPid = 0,
        .peerUid = 0,
        .peerTokenId = 0,
        .stubIndex = 0,
        .peerServiceName = "test",
        .peerDeviceId = "test",
        .localServiceName = "test",
        .localDeviceId = "test"
    };
    auto ret = object->MakeDBinderTransSession(data);
    delete current;
    delete invoker;
    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: DeathRecipientAddrInfoTest001
 * @tc.desc: Verify the DeathRecipientAddrInfo function when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, DeathRecipientAddrInfoTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<OHOS::IRemoteObject::DeathRecipient> nullRecipient = nullptr;
    IPCObjectProxy::DeathRecipientAddrInfo info(nullRecipient);
    EXPECT_EQ(info.recipient_, nullptr);
}

/**
 * @tc.name: DeathRecipientAddrInfoTest002
 * @tc.desc: Verify the DeathRecipientAddrInfo function when recipient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, DeathRecipientAddrInfoTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<MockDeathRecipient> recipient = new MockDeathRecipient();
    IPCObjectProxy::DeathRecipientAddrInfo info(recipient);
    EXPECT_NE(info.recipient_, nullptr);
}
} // namespace OHOS
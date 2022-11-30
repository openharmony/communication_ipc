/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#define private public
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "mock_iremote_object.h"
#include "mock_session_impl.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

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
}

/**
 * @tc.name: GetPidAndUidInfoTest001
 * @tc.desc: Verify the IPCObjectProxy::GetPidAndUidInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetPidAndUidInfoTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::string ret = object.GetPidAndUidInfo(1);
    ASSERT_TRUE(ret.size() != 0);
}

/**
 * @tc.name: GetDataBusNameTest001
 * @tc.desc: Verify the IPCObjectProxy::GetDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetDataBusNameTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::string ret = object.GetDataBusName(1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: TransDataBusNameTest001
 * @tc.desc: Verify the IPCObjectProxy::TransDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, TransDataBusNameTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::string ret = object.TransDataBusName(1, 1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetInterfaceDescriptorTest001
 * @tc.desc: Verify the IPCObjectProxy::GetInterfaceDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::u16string ret = object.GetInterfaceDescriptor();
    ASSERT_TRUE(ret.size() != 0);
}

/**
 * @tc.name: GetObjectRefCountTest001
 * @tc.desc: Verify the IPCObjectProxy::GetObjectRefCount function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetObjectRefCountTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    auto ret = object.GetObjectRefCount();
    ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: GetInterfaceDescriptorTest002
 * @tc.desc: Verify the IPCObjectProxy::GetInterfaceDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest002, TestSize.Level1)
{
    IPCObjectProxy object(0);
    object.remoteDescriptor_ = u"";
    auto ret = object.GetInterfaceDescriptor();
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetInterfaceDescriptorTest003
 * @tc.desc: Verify the IPCObjectProxy::GetInterfaceDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.remoteDescriptor_ = u"test";
    auto ret = object.GetInterfaceDescriptor();
    ASSERT_TRUE(ret.size() != 0);
}

/**
 * @tc.name: GetInterfaceDescriptorTest004
 * @tc.desc: Verify the IPCObjectProxy::GetInterfaceDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest004, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.remoteDescriptor_ = u"test";
    auto ret = object.GetInterfaceDescriptor();
    ASSERT_TRUE(ret.size() != 0);
}

/**
 * @tc.name: GetPidAndUidInfoTest002
 * @tc.desc: Verify the IPCObjectProxy::GetPidAndUidInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetPidAndUidInfoTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = true;
    auto ret = object.GetPidAndUidInfo(1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetDataBusNameTest002
 * @tc.desc: Verify the IPCObjectProxy::GetDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetDataBusNameTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = false;
    auto ret = object.GetDataBusName(1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetDataBusNameTest003
 * @tc.desc: Verify the IPCObjectProxy::GetDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetDataBusNameTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = true;
    auto ret = object.GetDataBusName(1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: TransDataBusNameTest002
 * @tc.desc: Verify the IPCObjectProxy::TransDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, TransDataBusNameTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = false;
    auto ret = object.TransDataBusName(1, 1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: TransDataBusNameTest003
 * @tc.desc: Verify the IPCObjectProxy::TransDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, TransDataBusNameTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = true;
    auto ret = object.TransDataBusName(1, 1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: WaitForInitTest001
 * @tc.desc: Verify the IPCObjectProxy::WaitForInit function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, WaitForInitTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = true;
    object.WaitForInit();
    EXPECT_EQ(object.isRemoteDead_, false);
    EXPECT_EQ(object.isFinishInit_, true);
}

#ifndef CONFIG_IPC_SINGLE
/**
 * @tc.name: WaitForInitTest002
 * @tc.desc: Verify the IPCObjectProxy::WaitForInit function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, WaitForInitTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = false;
    object.isRemoteDead_ = true;
    object.proto_ = IRemoteObject::IF_PROT_DATABUS;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->proxyToSession_.clear();
    object.WaitForInit();
    EXPECT_EQ(object.isRemoteDead_, false);
}

/**
 * @tc.name: WaitForInitTest003
 * @tc.desc: Verify the IPCObjectProxy::WaitForInit function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, WaitForInitTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = false;
    object.isRemoteDead_ = true;
    object.proto_ = IRemoteObject::IF_PROT_ERROR;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->proxyToSession_.clear();
    object.WaitForInit();
    EXPECT_NE(object.isRemoteDead_, true);
}

/**
 * @tc.name: WaitForInitTest004
 * @tc.desc: Verify the IPCObjectProxy::WaitForInit function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, WaitForInitTest004, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = false;
    object.isRemoteDead_ = true;
    object.proto_ = IRemoteObject::IF_PROT_ERROR;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->proxyToSession_.clear();
    object.WaitForInit();
    EXPECT_NE(object.isRemoteDead_, true);
}
#endif

/**
 * @tc.name: RemoveDeathRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_ERROR;
    object->recipients_.clear();

    object->RemoveDeathRecipient(death);
    EXPECT_EQ(object->recipients_.empty(), true);
}

/**
 * @tc.name: RemoveDeathRecipientTest002
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_ERROR;
    object->recipients_.clear();

    object->RemoveDeathRecipient(death);
    EXPECT_EQ(object->isRemoteDead_, false);
}

/**
 * @tc.name: RemoveDeathRecipientTest003
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest003, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    sptr<IRemoteObject::DeathRecipient> death2(new MockDeathRecipient());
    object->recipients_.push_back(death);
    object->recipients_.push_back(death2);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_ERROR;

    object->RemoveDeathRecipient(death);
    EXPECT_EQ(object->recipients_.empty(), false);
}

/**
 * @tc.name: RemoveDeathRecipientTest004
 * @tc.desc: Verify the IPCObjectProxy::RemoveDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDeathRecipientTest004, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<IRemoteObject::DeathRecipient> death(new MockDeathRecipient());
    object->recipients_.push_back(death);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_ERROR;

    auto ret = object->RemoveDeathRecipient(death);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: SendObituaryTest001
 * @tc.desc: Verify the IPCObjectProxy::SendObituary function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, SendObituaryTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<IRemoteObject::DeathRecipient> death = new MockDeathRecipient();
    object->recipients_.push_back(death);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DATABUS;

    object->SendObituary();
    ASSERT_TRUE(object->recipients_.size() == 0);
    object->recipients_.clear();
}

/**
 * @tc.name: SendObituaryTest002
 * @tc.desc: Verify the IPCObjectProxy::SendObituary function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, SendObituaryTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->recipients_.clear();
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DATABUS;

    object->SendObituary();
    ASSERT_TRUE(object->recipients_.size() == 0);
}

/**
 * @tc.name: SendObituaryTest003
 * @tc.desc: Verify the IPCObjectProxy::SendObituary function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, SendObituaryTest003, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<IRemoteObject::DeathRecipient> death = nullptr;
    object->recipients_.push_back(death);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DATABUS;

    object->SendObituary();
    ASSERT_TRUE(object->recipients_.size() == 0);
}

#ifndef CONFIG_IPC_SINGLE
/**
 * @tc.name: SendObituaryTest004
 * @tc.desc: Verify the IPCObjectProxy::SendObituary function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, SendObituaryTest004, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    sptr<IRemoteObject::DeathRecipient> death = nullptr;
    object->recipients_.push_back(death);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    object->SendObituary();
    ASSERT_TRUE(object->recipients_.size() == 0);
}
#endif

/**
 * @tc.name: NoticeServiceDieTest001
 * @tc.desc: Verify the IPCObjectProxy::NoticeServiceDie function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, NoticeServiceDieTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);

    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    auto ret = object->NoticeServiceDie();
    EXPECT_EQ(ret, IPC_PROXY_TRANSACTION_ERR);
}

/**
 * @tc.name: NoticeServiceDieTest002
 * @tc.desc: Verify the IPCObjectProxy::NoticeServiceDie function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, NoticeServiceDieTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = true;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    auto ret = object->NoticeServiceDie();
    EXPECT_EQ(ret, IPC_PROXY_TRANSACTION_ERR);
}

/**
 * @tc.name: IncRefToRemoteTest001
 * @tc.desc: Verify the IPCObjectProxy::IncRefToRemote function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, IncRefToRemoteTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    auto ret = object->IncRefToRemote();
    EXPECT_EQ(ret, IPC_STUB_INVALID_DATA_ERR);
}

/**
 * @tc.name: IncRefToRemoteTest002
 * @tc.desc: Verify the IPCObjectProxy::IncRefToRemote function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, IncRefToRemoteTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = true;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    auto ret = object->IncRefToRemote();
    EXPECT_EQ(ret, ERR_DEAD_OBJECT);
}

/**
 * @tc.name: GetSessionFromDBinderServiceTest001
 * @tc.desc: Verify the IPCObjectProxy::GetSessionFromDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionFromDBinderServiceTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = true;
    object->proto_ = IRemoteObject::IF_PROT_DATABUS;

    auto ret = object->GetSessionFromDBinderService();
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_ERROR);
}

/**
 * @tc.name: GetSessionFromDBinderServiceTest002
 * @tc.desc: Verify the IPCObjectProxy::GetSessionFromDBinderService function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionFromDBinderServiceTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = true;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    auto ret = object->GetSessionFromDBinderService();
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_ERROR);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDbinderDeathRecipientTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"test");
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->noticeStub_[object.GetRefPtr()] = objectStub;
    auto ret = object->AddDbinderDeathRecipient();

    ASSERT_TRUE(ret == true);
    current->noticeStub_.erase(object.GetRefPtr());
}

/**
 * @tc.name: AddDbinderDeathRecipientTest002
 * @tc.desc: Verify the IPCObjectProxy::AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDbinderDeathRecipientTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = true;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->noticeStub_.clear();
    auto ret = object->AddDbinderDeathRecipient();

    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: AddDbinderDeathRecipientTest003
 * @tc.desc: Verify the IPCObjectProxy::AddDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, AddDbinderDeathRecipientTest003, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = true;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"test");
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->noticeStub_[object.GetRefPtr()] = objectStub;
    auto ret = object->AddDbinderDeathRecipient();

    ASSERT_TRUE(ret == true);
    current->noticeStub_.erase(object.GetRefPtr());
}

/**
 * @tc.name: RemoveDbinderDeathRecipientTest001
 * @tc.desc: Verify the IPCObjectProxy::RemoveDbinderDeathRecipient function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveDbinderDeathRecipientTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"test");
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->noticeStub_[object.GetRefPtr()] = objectStub;
    auto ret = object->RemoveDbinderDeathRecipient();

    ASSERT_TRUE(ret == true);
    current->noticeStub_.erase(object.GetRefPtr());
}

/**
 * @tc.name: CheckHaveSessionTest001
 * @tc.desc: Verify the IPCObjectProxy::CheckHaveSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, CheckHaveSessionTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(sessionMock, serviceName, serverDeviceId);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    auto session = current->proxyToSession_[1] = dbinderSessionObject;
    ASSERT_TRUE(current->ProxyQueryDBinderSession(1) != nullptr);
    auto ret = object->CheckHaveSession();

    ASSERT_TRUE(ret == true);
}

/**
 * @tc.name: UpdateDatabusClientSessionTest001
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IRemoteInvoker *invoker = nullptr;
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = invoker;
    MessageParcel reply;
    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
    current->invokers_.clear();
}

/**
 * @tc.name: UpdateDatabusClientSessionTest002
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_.clear();

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.ReadUint64(stubIndex);
    std::string serviceName =  "testserviceName";
    reply.WriteString(serviceName);
    std::string peerID =  "testpeerID";
    reply.WriteString(peerID);
    std::string localID =  "testlocalID";
    reply.WriteString(localID);
    std::string localBusName =  "testlocalBusName";
    reply.WriteString(localBusName);
    uint32_t rpcFeatureSet = 1;
    reply.WriteUint32(rpcFeatureSet);

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: UpdateDatabusClientSessionTest003
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest003, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_.clear();

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.ReadUint64(stubIndex);
    std::string serviceName =  "testserviceName";
    reply.WriteString(serviceName);
    std::string peerID =  "testpeerID";
    reply.WriteString(peerID);
    std::string localID =  "testlocalID";
    reply.WriteString(localID);
    std::string localBusName =  "testlocalBusName";
    reply.WriteString(localBusName);
    uint32_t rpcFeatureSet = 0;
    reply.WriteUint32(rpcFeatureSet);

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: UpdateDatabusClientSessionTest004
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest004, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_.clear();

    MessageParcel reply;
    uint64_t stubIndex = 0;
    reply.ReadUint64(stubIndex);
    std::string serviceName =  "testserviceName";
    reply.WriteString(serviceName);
    std::string peerID =  "testpeerID";
    reply.WriteString(peerID);
    std::string localID =  "testlocalID";
    reply.WriteString(localID);
    std::string localBusName =  "testlocalBusName";
    reply.WriteString(localBusName);
    uint32_t rpcFeatureSet = 0;
    reply.WriteUint32(rpcFeatureSet);

    auto ret = object->UpdateDatabusClientSession(1, reply);
    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: UpdateDatabusClientSessionTest005
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSession5 function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest005, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_.clear();

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.ReadUint64(stubIndex);
    std::string serviceName =  "testserviceName";
    reply.WriteString(serviceName);
    std::string peerID =  "testpeerID";
    reply.WriteString(peerID);
    std::string localID =  "testlocalID";
    reply.WriteString(localID);
    std::string localBusName =  "testlocalBusName";
    reply.WriteString(localBusName);
    uint32_t rpcFeatureSet = 1;
    reply.WriteUint32(rpcFeatureSet);

    IPCProcessSkeleton *processCurrent = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(sessionMock, serviceName, peerID);
    processCurrent->proxyToSession_[0] = dbinderSessionObject;

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
    processCurrent->proxyToSession_.clear();
}

/**
 * @tc.name: UpdateDatabusClientSessionTest006
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSession5 function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest006, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_.clear();

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.ReadUint64(stubIndex);
    std::string serviceName =  "testserviceName";
    reply.WriteString(serviceName);
    std::string peerID =  "testpeerID";
    reply.WriteString(peerID);
    std::string localID =  "testlocalID";
    reply.WriteString(localID);
    std::string localBusName =  "testlocalBusName";
    reply.WriteString(localBusName);
    uint32_t rpcFeatureSet = 1;
    reply.WriteUint32(rpcFeatureSet);

    IPCProcessSkeleton *processCurrent = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();

    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(sessionMock, serviceName, peerID);
    processCurrent->proxyToSession_[0] = dbinderSessionObject;
    processCurrent->handleToStubIndex_[1] = 0;

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
    processCurrent->proxyToSession_.clear();
    processCurrent->handleToStubIndex_.clear();
}

/**
 * @tc.name: UpdateDatabusClientSessionTest007
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSession5 function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest007, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_.clear();

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.ReadUint64(stubIndex);
    std::string serviceName =  "testserviceName";
    reply.WriteString(serviceName);
    std::string peerID =  "testpeerID";
    reply.WriteString(peerID);
    std::string localID =  "testlocalID";
    reply.WriteString(localID);
    std::string localBusName =  "";
    reply.WriteString(localBusName);
    uint32_t rpcFeatureSet = 1;
    reply.WriteUint32(rpcFeatureSet);

    IPCProcessSkeleton *processCurrent = IPCProcessSkeleton::GetCurrent();
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(sessionMock, serviceName, peerID);
    processCurrent->proxyToSession_[0] = dbinderSessionObject;
    processCurrent->handleToStubIndex_.clear();

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
    processCurrent->proxyToSession_.clear();
}

/**
 * @tc.name: UpdateDatabusClientSessionTest008
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSession5 function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest008, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_.clear();

    MessageParcel reply;
    uint64_t stubIndex = 0;
    reply.ReadUint64(stubIndex);
    std::string serviceName =  "testserviceName";
    reply.WriteString(serviceName);
    std::string peerID =  "testpeerID";
    reply.WriteString(peerID);
    std::string localID =  "testlocalID";
    reply.WriteString(localID);
    std::string localBusName =  "";
    reply.WriteString(localBusName);
    uint32_t rpcFeatureSet = 0;
    reply.WriteUint32(rpcFeatureSet);

    IPCProcessSkeleton *processCurrent = IPCProcessSkeleton::GetCurrent();
    processCurrent->proxyToSession_.clear();
    processCurrent->handleToStubIndex_.clear();

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: ReleaseDatabusProtoTest001
 * @tc.desc: Verify the IPCObjectProxy::ReleaseDatabusProto function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, ReleaseDatabusProtoTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        0, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);

    object->ReleaseDatabusProto();
    ASSERT_TRUE(object->isRemoteDead_ == false);
}

/**
 * @tc.name: ReleaseDatabusProtoTest002
 * @tc.desc: Verify the IPCObjectProxy::ReleaseDatabusProto function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, ReleaseDatabusProtoTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);

    object->proto_ = IRemoteObject::IF_PROT_DATABUS;
    object->ReleaseDatabusProto();
    object->isRemoteDead_ = true;
    ASSERT_TRUE(object->handle_ != 0);
}

/**
 * @tc.name: ReleaseDatabusProtoTest003
 * @tc.desc: Verify the IPCObjectProxy::ReleaseDatabusProto function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, ReleaseDatabusProtoTest003, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);

    object->proto_ = IRemoteObject::IF_PROT_DATABUS;
    object->ReleaseDatabusProto();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    
    std::shared_ptr<MockSessionImpl> sessionMock = std::make_shared<MockSessionImpl>();
    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(sessionMock, serviceName, serverDeviceId);

    auto session = current->proxyToSession_[1] = dbinderSessionObject;
    ASSERT_TRUE(object->handle_ != 0);
    current->proxyToSession_.clear();
}

/**
 * @tc.name: ReleaseDatabusProtoTest004
 * @tc.desc: Verify the IPCObjectProxy::ReleaseDatabusProto function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, ReleaseDatabusProtoTest004, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);

    object->proto_ = IRemoteObject::IF_PROT_DATABUS;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->proxyToSession_.clear();
    object->ReleaseDatabusProto();
    ASSERT_TRUE(object->handle_ != 0);
}

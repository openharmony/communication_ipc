/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_test_helper.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "mock_iremote_invoker.h"
#include "mock_iremote_object.h"
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
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

/**
 * @tc.name: GetSessionNameTest001
 * @tc.desc: Verify the IPCObjectProxy::GetSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionNameTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::string ret = object.GetSessionName();
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: SendRequestTest001
 * @tc.desc: Verify the IPCObjectProxy::SendRequest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, SendRequestTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    uint32_t code = MAX_TRANSACTION_ID + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    auto ret = object.SendRequest(code, data, reply, option);
    ASSERT_TRUE(ret == IPC_PROXY_INVALID_CODE_ERR);
}

/**
 * @tc.name: SendRequestInnerTest001
 * @tc.desc: Verify the IPCObjectProxy::SendRequestInner function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, SendRequestInnerTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    bool isLocal = true;
    uint32_t code = MAX_TRANSACTION_ID + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_DEAD_OBJECT));

    auto ret = object.SendRequestInner(isLocal, code, data, reply, option);
    ASSERT_TRUE(ret == ERR_DEAD_OBJECT);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetGrantedSessionNameTest001
 * @tc.desc: Verify the IPCObjectProxy::GetGrantedSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetGrantedSessionNameTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::string ret = object.GetGrantedSessionName();
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetSessionNameForPidUidTest001
 * @tc.desc: Verify the IPCObjectProxy::GetSessionNameForPidUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionNameForPidUidTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    IPCTestHelper helper;
    std::string ret = object.GetSessionNameForPidUid(helper.GetPid(), helper.GetUid());
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetPidUidTest001
 * @tc.desc: Verify the IPCObjectProxy::GetPidUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetPidUidTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    MessageParcel reply;
    auto ret = object.GetPidUid(reply);
    ASSERT_TRUE(ret != 0);
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
    ASSERT_TRUE(ret.size() == 0);
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
    ASSERT_TRUE(ret == 0);
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
    object.interfaceDesc_ = u"test";
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
    object.interfaceDesc_ = u"test";
    auto ret = object.GetInterfaceDescriptor();
    ASSERT_TRUE(ret.size() != 0);
}

/**
 * @tc.name: GetInterfaceDescriptorTest005
 * @tc.desc: Verify the IPCObjectProxy::GetInterfaceDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest005, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = u"";

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_DEAD_OBJECT));

    auto ret = object.GetInterfaceDescriptor();
    ASSERT_TRUE(ret.size() == 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetInterfaceDescriptorTest006
 * @tc.desc: Verify the IPCObjectProxy::GetInterfaceDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest006, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = u"";

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(ERR_DEAD_OBJECT));

    auto ret = object.GetInterfaceDescriptor();
    ASSERT_TRUE(ret.size() == 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

int SendRequestMock(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    reply.WriteUint32(IRemoteObject::IF_PROT_DEFAULT);
    return ERR_NONE;
}

/**
 * @tc.name: GetSessionNameTest002
 * @tc.desc: Verify the IPCObjectProxy::GetSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionNameTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = true;
    auto ret = object.GetSessionName();
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetGrantedSessionNameTest002
 * @tc.desc: Verify the IPCObjectProxy::GetGrantedSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetGrantedSessionNameTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = true;
    auto ret = object.GetGrantedSessionName();
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetSessionNameForPidUidTest002
 * @tc.desc: Verify the IPCObjectProxy::GetSessionNameForPidUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionNameForPidUidTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);

    auto ret = object.GetSessionNameForPidUid(1, 1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetSessionNameForPidUidTest003
 * @tc.desc: Verify the IPCObjectProxy::GetSessionNameForPidUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionNameForPidUidTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = true;
    auto ret = object.GetSessionNameForPidUid(1, 1);
    ASSERT_TRUE(ret.size() == 0);
}

/**
 * @tc.name: GetGrantedSessionNameTest003
 * @tc.desc: Verify the IPCObjectProxy::GetGrantedSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetGrantedSessionNameTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = u"";

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(SendRequestMock));

    auto ret = object.GetSessionNameForPidUid(1, 1);
    ASSERT_TRUE(ret.size() == 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetSessionNameForPidUidTest004
 * @tc.desc: Verify the IPCObjectProxy::GetSessionNameForPidUidTest004 function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionNameForPidUidTest004, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = u"";

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(SendRequestMock));

    auto ret = object.GetSessionNameForPidUid(1, 1);
    ASSERT_TRUE(ret.size() == 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetSessionNameForPidUidTest005
 * @tc.desc: Verify the IPCObjectProxy::GetSessionNameForPidUid function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetSessionNameForPidUidTest005, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = u"";

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(SendRequestMock));

    auto ret = object.GetSessionNameForPidUid(1, 1);
    ASSERT_TRUE(ret.size() == 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: OnFirstStrongRefTest005
 * @tc.desc: Verify the IPCObjectProxy::OnFirstStrongRef function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, OnFirstStrongRefTest005, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = u"";

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;

    object.OnFirstStrongRef(nullptr);
    ASSERT_TRUE(object.handle_ == 1);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

/**
 * @tc.name: WaitForInitTest001
 * @tc.desc: Verify the IPCObjectProxy::WaitForInit function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, WaitForInitTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    object.isRemoteDead_ = false;
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
    object.proto_ = IRemoteObject::IF_PROT_DATABUS;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->proxyToSession_.clear();
    object.WaitForInit();
    EXPECT_EQ(object.isRemoteDead_, true);
    EXPECT_EQ(object.isFinishInit_, true);
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
    object.isFinishInit_ = true;
    object.proto_ = IRemoteObject::IF_PROT_DATABUS;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->proxyToSession_.clear();
    object.WaitForInit();
    EXPECT_EQ(object.isRemoteDead_, true);
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
    object.isFinishInit_ = true;
    object.proto_ = IRemoteObject::IF_PROT_ERROR;

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->proxyToSession_.clear();
    object.WaitForInit();
    EXPECT_EQ(object.isRemoteDead_, false);
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
    sptr<IRemoteObject::DeathRecipient> death = new MockDeathRecipient();
    sptr<IRemoteObject::DeathRecipient> death2 = new MockDeathRecipient();
    sptr<IPCObjectProxy::DeathRecipientAddrInfo> deathInfo = new IPCObjectProxy::DeathRecipientAddrInfo(death);
    sptr<IPCObjectProxy::DeathRecipientAddrInfo> deathInfo2 = new IPCObjectProxy::DeathRecipientAddrInfo(death2);
    object->recipients_.push_back(deathInfo);
    object->recipients_.push_back(deathInfo2);
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
    sptr<IRemoteObject::DeathRecipient> death = new MockDeathRecipient();
    sptr<IPCObjectProxy::DeathRecipientAddrInfo> deathInfo = new IPCObjectProxy::DeathRecipientAddrInfo(death);
    object->recipients_.push_back(deathInfo);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

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
    sptr<IPCObjectProxy::DeathRecipientAddrInfo> deathInfo = new IPCObjectProxy::DeathRecipientAddrInfo(death);
    object->recipients_.push_back(deathInfo);
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
    sptr<IPCObjectProxy::DeathRecipientAddrInfo> deathInfo = new IPCObjectProxy::DeathRecipientAddrInfo(death);
    object->recipients_.push_back(deathInfo);
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
    sptr<IPCObjectProxy::DeathRecipientAddrInfo> deathInfo = new IPCObjectProxy::DeathRecipientAddrInfo(death);
    object->recipients_.push_back(deathInfo);
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
    EXPECT_NE(ret, ERR_NONE);
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
    EXPECT_NE(ret, ERR_NONE);
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
 * @tc.name: GetProtoInfoTest001
 * @tc.desc: Verify the IPCObjectProxy::GetProtoInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetProtoInfoTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = true;
    object->proto_ = IRemoteObject::IF_PROT_DATABUS;

    auto ret = object->GetProtoInfo();
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_ERROR);
}

/**
 * @tc.name: GetProtoInfoTest002
 * @tc.desc: Verify the IPCObjectProxy::GetProtoInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetProtoInfoTest002, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = true;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    auto ret = object->GetProtoInfo();
    EXPECT_EQ(ret, IRemoteObject::IF_PROT_ERROR);
}


int SendRequestPortMock(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    reply.WriteUint32(IRemoteObject::IF_PROT_DATABUS);
    reply.WriteUint64(0);
    reply.WriteString("Dbinder0_0");
    reply.WriteString("1");
    reply.WriteString("1");
    reply.WriteString("test");
    reply.WriteUint32(0);
    return ERR_NONE;
}

/**
 * @tc.name: GetProtoInfoTest003
 * @tc.desc: Verify the IPCObjectProxy::GetProtoInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetProtoInfoTest003, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    object.remoteDescriptor_ = u"test";

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke(SendRequestPortMock));

    auto ret = object.GetProtoInfo();
    ASSERT_TRUE(ret != IRemoteObject::IF_PROT_DATABUS);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
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

    ASSERT_TRUE(ret == false);
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

    std::string serviceName = "testserviceName";
    std::string serverDeviceId = "testserverDeviceId";
    int64_t stubIndex = 1;
    IPCObjectProxy *proxy = object.GetRefPtr();
    uint32_t tokenId = 1;

    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(
        serviceName, serverDeviceId, stubIndex, proxy, tokenId);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    auto session = current->proxyToSession_[1] = dbinderSessionObject;
    ASSERT_TRUE(current->ProxyQueryDBinderSession(1) != nullptr);
    auto ret = object->CheckHaveSession();

    ASSERT_TRUE(ret == true);
    dbinderSessionObject->proxy_ = nullptr;
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
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
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
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.WriteUint64(stubIndex);
    std::string serviceName = "DBinder111_222";
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
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.WriteUint64(stubIndex);
    std::string serviceName = "DBinder111_222";
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
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);

    MessageParcel reply;
    uint64_t stubIndex = 0;
    reply.WriteUint64(stubIndex);
    std::string serviceName = "DBinder111_222";
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
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.WriteUint64(stubIndex);
    std::string serviceName = "DBinder111_222";
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
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(
        serviceName, peerID, 1, object.GetRefPtr(), 1);
    processCurrent->proxyToSession_[0] = dbinderSessionObject;

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
    processCurrent->proxyToSession_.clear();
    dbinderSessionObject->proxy_ = nullptr;
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
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.WriteUint64(stubIndex);
    std::string serviceName = "DBinder111_222";
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

    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(
        serviceName, peerID, 1, object.GetRefPtr(), 1);
    processCurrent->proxyToSession_[0] = dbinderSessionObject;

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
    processCurrent->proxyToSession_.clear();
    dbinderSessionObject->proxy_ = nullptr;
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
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.WriteUint64(stubIndex);
    std::string serviceName = "DBinder111_222";
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
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(
        serviceName, peerID, 1, object.GetRefPtr(), 1);
    processCurrent->proxyToSession_[0] = dbinderSessionObject;

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
    processCurrent->proxyToSession_.clear();
    dbinderSessionObject->proxy_ = nullptr;
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
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);

    MessageParcel reply;
    uint64_t stubIndex = 0;
    reply.WriteUint64(stubIndex);
    std::string serviceName = "DBinder111_222";
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

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
}

/**
 * @tc.name: UpdateDatabusClientSessionTest009
 * @tc.desc: Verify the IPCObjectProxy::UpdateDatabusClientSessionTest009 function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, UpdateDatabusClientSessionTest009, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->isRemoteDead_ = false;
    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);

    MessageParcel reply;
    uint64_t stubIndex = 1;
    reply.WriteUint64(stubIndex);
    std::string serviceName = "DBinder111_222";
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
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(
        serviceName, peerID, 1, object.GetRefPtr(), 1);
    processCurrent->proxyToSession_[0] = dbinderSessionObject;

    auto ret = object->UpdateDatabusClientSession(1, reply);

    ASSERT_TRUE(ret == false);
    processCurrent->proxyToSession_.clear();
    dbinderSessionObject->proxy_ = nullptr;
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

    std::string serviceName = "DBinder111_222";
    std::string serverDeviceId = "testserverDeviceId";
    int64_t stubIndex = 1;
    IPCObjectProxy *proxy = object.GetRefPtr();
    uint32_t tokenId = 1;
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(
        serviceName, serverDeviceId, stubIndex, proxy, tokenId);

    auto session = current->proxyToSession_[1] = dbinderSessionObject;
    ASSERT_TRUE(object->handle_ != 0);
    current->proxyToSession_.clear();
    dbinderSessionObject->proxy_ = nullptr;
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

HWTEST_F(IPCObjectProxyTest, GetStrongRefCountForStubTest001, TestSize.Level1)
{
    sptr<IPCObjectProxy> object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);

    object->proto_ = IRemoteObject::IF_PROT_DEFAULT;
    uint32_t count = object->GetStrongRefCountForStub();
    ASSERT_TRUE(count == 0);
}

/**
 * @tc.name: RemoveSessionNameTest001
 * @tc.desc: Verify the IPCObjectProxy::RemoveSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveSessionNameTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);
    std::string sessionName = "testSessionName";

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    ASSERT_TRUE(invoker != nullptr);
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_TRUE(current != nullptr);
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_NONE));

    int result = object.RemoveSessionName(sessionName);
    ASSERT_EQ(result, ERR_NONE);

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: RemoveSessionNameTest002
 * @tc.desc: Verify the IPCObjectProxy::RemoveSessionName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, RemoveSessionNameTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    std::string sessionName = "testSessionName";

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    ASSERT_TRUE(invoker != nullptr);
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_TRUE(current != nullptr);
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_DEAD_OBJECT));

    int result = object.RemoveSessionName(sessionName);
    ASSERT_EQ(result, ERR_DEAD_OBJECT);

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}
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
#include <climits>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define private public
#include "dbinder_session_object.h"
#include "ipc_process_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "ipc_object_stub.h"
#include "ipc_thread_pool.h"
#include "stub_refcount_object.h"
#include "process_skeleton.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace {
constexpr int THREAD_NUM_2 = 2;
constexpr uint32_t INDEX_1 = 1;
constexpr uint32_t INDEX_2 = 2;
constexpr int32_t EXECUTE_TIME_TEST = 500;
constexpr int32_t LARGE_THREAD_NUM = INT_MAX / 2;
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
 * @tc.name: GetRegistryObjectTest001
 * @tc.desc: Verify the GetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetRegistryObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    sptr<IRemoteObject> object = skeleton->GetRegistryObject();
    EXPECT_NE(object, nullptr);
}

/**
 * @tc.name: MakeHandleDescriptorTest001
 * @tc.desc: Verify the MakeHandleDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, MakeHandleDescriptorTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string str = skeleton->MakeHandleDescriptor(1);
    unsigned int size = 0;
    EXPECT_NE(str.size(), size);
}

/**
 * @tc.name: ConvertToSecureStringTest001
 * @tc.desc: Verify the ConvertToSecureString function with short string
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ConvertToSecureStringTest001, TestSize.Level1)
{
    std::string str = "abc";
    std::string ret = IPCProcessSkeleton::ConvertToSecureString(str);

    EXPECT_EQ(ret, "****");
}

/**
 * @tc.name: ConvertToSecureStringTest002
 * @tc.desc: Verify the ConvertToSecureString function with long string
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ConvertToSecureStringTest002, TestSize.Level1)
{
    std::string str = "123456789";
    std::string ret = IPCProcessSkeleton::ConvertToSecureString(str);

    EXPECT_EQ(ret, "1234****6789");
}

/**
 * @tc.name: FindOrNewObjectTest001
 * @tc.desc: Verify the FindOrNewObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, FindOrNewObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = skeleton->FindOrNewObject(0);
    EXPECT_NE(object, nullptr);
}

/**
 * @tc.name: SetMaxWorkThreadTest001
 * @tc.desc: Verify the SetMaxWorkThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetMaxWorkThreadTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool ret = skeleton->SetMaxWorkThread(-1);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetMaxWorkThreadTest002
 * @tc.desc: Verify the SetMaxWorkThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetMaxWorkThreadTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool ret = skeleton->SetMaxWorkThread(1);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: SetMaxWorkThreadTest003
 * @tc.desc: Verify the SetMaxWorkThread function with too large thread number
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetMaxWorkThreadTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool ret = skeleton->SetMaxWorkThread(LARGE_THREAD_NUM);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetRegistryObjectTest001
 * @tc.desc: Verify the SetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetRegistryObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = nullptr;
    bool ret = skeleton->SetRegistryObject(object);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SetRegistryObjectTest002
 * @tc.desc: Verify the SetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SetRegistryObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"test");
    bool ret = skeleton->SetRegistryObject(object);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SpawnThreadTest001
 * @tc.desc: Verify the SpawnThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SpawnThreadTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->SetMaxWorkThread(1);
    int policy = 1;
    int proto = IRemoteObject::IF_PROT_DATABUS;
    bool ret = skeleton->SpawnThread(policy, proto);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: SpawnThreadTest002
 * @tc.desc: Verify the SpawnThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, SpawnThreadTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->SetMaxWorkThread(1);
    int policy = 1;
    int proto = IRemoteObject::IF_PROT_ERROR;
    bool ret = skeleton->SpawnThread(policy, proto);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: OnThreadTerminatedTest001
 * @tc.desc: Verify the OnThreadTerminated function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, OnThreadTerminatedTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->SetMaxWorkThread(1);
    std::string threadName = "threadname";
    bool ret = skeleton->OnThreadTerminated(threadName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: QueryObjectTest001
 * @tc.desc: Verify the QueryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string descriptor = u"test";
    auto object = skeleton->QueryObject(descriptor);
    EXPECT_EQ(object, nullptr);
}

/**
 * @tc.name: QueryObjectTest002
 * @tc.desc: Verify the QueryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string descriptor = u"";
    auto object = skeleton->QueryObject(descriptor);
    EXPECT_EQ(object, nullptr);
}

/**
 * @tc.name: IsContainsObjectTest001
 * @tc.desc: Verify the IsContainsObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsContainsObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    skeleton->AttachObject(object);
    bool ret = skeleton->IsContainsObject(object.GetRefPtr());

    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsContainsObjectTest002
 * @tc.desc: Verify the IsContainsObject function with null object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsContainsObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool ret = skeleton->IsContainsObject(nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: AttachObjectTest001
 * @tc.desc: Verify the AttachObject function with null object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool ret = skeleton->AttachObject(nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: DetachObjectTest001
 * @tc.desc: Verify the DetachObject function with null object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    bool ret = skeleton->DetachObject(nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: DetachObjectTest002
 * @tc.desc: Verify the DetachObject function with empty descriptor
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"");
    bool ret = skeleton->DetachObject(object.GetRefPtr());
    EXPECT_EQ(ret, false);
}

#ifndef CONFIG_IPC_SINGLE
/**
 * @tc.name: IsHandleMadeByUserTest001
 * @tc.desc: Verify the IsHandleMadeByUser function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsHandleMadeByUserTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint32_t handler = IPCProcessSkeleton::DBINDER_HANDLE_BASE + 1;

    bool ret = skeleton->IsHandleMadeByUser(handler);

    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsHandleMadeByUserTest002
 * @tc.desc: Verify the IsHandleMadeByUser function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsHandleMadeByUserTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint32_t handler = IPCProcessSkeleton::DBINDER_HANDLE_BASE;
    bool ret = skeleton->IsHandleMadeByUser(handler);

    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: GetDBinderIdleHandleTest001
 * @tc.desc: Verify the GetDBinderIdleHandle function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetDBinderIdleHandleTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::string serverName = "serverName";
    std::string deviceId = "7001005458323933328a519c2fa83800";
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(serverName, deviceId, 1, nullptr, 1);
    uint32_t ret = skeleton->GetDBinderIdleHandle(remoteSession);

    EXPECT_EQ(ret, IPCProcessSkeleton::DBINDER_HANDLE_BASE + 1);
}

/**
 * @tc.name: GetDBinderIdleHandleTest002
 * @tc.desc: Verify the GetDBinderIdleHandle function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetDBinderIdleHandleTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->dBinderHandle_ = INDEX_1;
    std::string serverName = "serverName";
    std::string deviceId = "7001005458323933328a519c2fa83800";
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(serverName, deviceId, 1, nullptr, 1);
    uint32_t ret = skeleton->GetDBinderIdleHandle(remoteSession);

    EXPECT_EQ(ret, INDEX_2);
}

/**
 * @tc.name: GetDBinderIdleHandleTest003
 * @tc.desc: Verify the GetDBinderIdleHandle function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetDBinderIdleHandleTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->dBinderHandle_ =
        IPCProcessSkeleton::DBINDER_HANDLE_BASE + IPCProcessSkeleton::DBINDER_HANDLE_COUNT + INDEX_1;
    std::string serverName = "serverName";
    std::string deviceId = "7001005458323933328a519c2fa83800";
    std::shared_ptr<DBinderSessionObject> remoteSession =
        std::make_shared<DBinderSessionObject>(serverName, deviceId, 1, nullptr, 1);
    uint32_t ret = skeleton->GetDBinderIdleHandle(remoteSession);

    EXPECT_EQ(ret, IPCProcessSkeleton::DBINDER_HANDLE_BASE);
}

/**
 * @tc.name: ProxyAttachDBinderSessionTest004
 * @tc.desc: Verify the ProxyAttachDBinderSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ProxyAttachDBinderSessionTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::string name("nameTest");
    std::string deviceId("deviceIdTest");
    auto object = std::make_shared<DBinderSessionObject>(name, deviceId, 1, nullptr, 1);

    uint32_t handler = 1;
    bool ret = skeleton->ProxyAttachDBinderSession(handler, object);

    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ProxyQueryDBinderSessionTest001
 * @tc.desc: Verify the ProxyQueryDBinderSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ProxyQueryDBinderSessionTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::string name("nameTest");
    std::string deviceId("deviceIdTest");
    auto object = std::make_shared<DBinderSessionObject>(name, deviceId, 1, nullptr, 1);

    uint32_t handler = 1;
    skeleton->proxyToSession_.insert(
        std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handler, object));
    auto ret = skeleton->ProxyQueryDBinderSession(handler);

    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: QueryProxyBySocketIdTest001
 * @tc.desc: Verify the QueryProxyBySocketId function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryProxyBySocketIdTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::string name("nameTest");
    std::string deviceId("deviceIdTest");
    auto object = std::make_shared<DBinderSessionObject>(name, deviceId, 1, nullptr, 1);

    uint32_t handler = 1;
    std::vector<uint32_t> proxyHandle { 1 };
    skeleton->proxyToSession_.insert(
        std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handler, object));
    auto ret = skeleton->QueryProxyBySocketId(handler, proxyHandle);

    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: QueryHandleByDatabusSessionTest001
 * @tc.desc: Verify the QueryHandleByDatabusSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryHandleByDatabusSessionTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    const std::string name("nameTest");
    const std::string deviceId("deviceIdTest");
    uint64_t index = 1;

    auto object = std::make_shared<DBinderSessionObject>(name, deviceId, 1, nullptr, 1);
    uint32_t handler = 1;
    skeleton->proxyToSession_.insert(
        std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handler, object));
    auto ret = skeleton->QueryHandleByDatabusSession(name, deviceId, index);

    EXPECT_EQ(ret, handler);
}

/**
 * @tc.name: QuerySessionByInfoTest001
 * @tc.desc: Verify the QuerySessionByInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QuerySessionByInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    const std::string name("nameTest");
    const std::string deviceId("deviceIdTest");

    auto object = std::make_shared<DBinderSessionObject>(name, deviceId, 1, nullptr, 1);
    uint32_t handler = 1;
    skeleton->proxyToSession_.insert(
        std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handler, object));

    auto ret = skeleton->QuerySessionByInfo(name, deviceId);

    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: QueryThreadLockInfoTest001
 * @tc.desc: Verify the SetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryThreadLockInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<SocketThreadLockInfo> object =
        std::make_shared<SocketThreadLockInfo>();
    std::thread::id threadId;
    skeleton->AttachThreadLockInfo(object, threadId);

    auto ret = skeleton->QueryThreadLockInfo(threadId);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: DeleteDataThreadFromIdleTest001
 * @tc.desc: Verify the DeleteDataThreadFromIdle function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DeleteDataThreadFromIdleTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::thread::id threadId;
    skeleton->AddDataThreadToIdle(threadId);

    bool ret = skeleton->DeleteDataThreadFromIdle(threadId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: GetIdleDataThreadTest001
 * @tc.desc: Verify the GetIdleDataThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetIdleDataThreadTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::thread::id threadId;
    skeleton->AddDataThreadToIdle(threadId);
    skeleton->GetIdleDataThread();
    EXPECT_NE(skeleton->idleDataThreads_.size(), 0);
}

/**
 * @tc.name: GetSocketIdleThreadNumTest001
 * @tc.desc: Verify the GetSocketIdleThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetSocketIdleThreadNumTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->SetMaxWorkThread(THREAD_NUM_2);
    ASSERT_TRUE(skeleton->threadPool_ != nullptr);

    int num = skeleton->threadPool_->GetSocketIdleThreadNum();
    int ret = skeleton->GetSocketIdleThreadNum();
    EXPECT_EQ(num, ret);
}

/**
 * @tc.name: GetSocketTotalThreadNumTest002
 * @tc.desc: Verify the GetSocketTotalThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetSocketTotalThreadNumTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->SetMaxWorkThread(THREAD_NUM_2);
    ASSERT_TRUE(skeleton->threadPool_ != nullptr);

    int ret = skeleton->GetSocketTotalThreadNum();
    int num = skeleton->threadPool_->GetSocketTotalThreadNum();
    EXPECT_EQ(num, ret);
}

/**
 * @tc.name: PopDataInfoFromThreadTest001
 * @tc.desc: Verify the PopDataInfoFromThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, PopDataInfoFromThreadTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::thread::id threadId;
    std::shared_ptr<ThreadProcessInfo> processInfo =
        std::make_shared<ThreadProcessInfo>();
    skeleton->AddDataInfoToThread(threadId, processInfo);

    auto ret = skeleton->PopDataInfoFromThread(threadId);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: GetSeqNumberTest001
 * @tc.desc: Verify the GetSeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetSeqNumberTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumber_ = 0;
    uint64_t num = skeleton->GetSeqNumber();
    ASSERT_TRUE(num != 0);
}

/**
 * @tc.name: GetSeqNumberTest002
 * @tc.desc: Verify the GetSeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetSeqNumberTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumber_ = std::numeric_limits<uint64_t>::max();
    uint64_t num = skeleton->GetSeqNumber();
    ASSERT_TRUE(num != 0);
}

/**
 * @tc.name: QueryThreadBySeqNumberTest001
 * @tc.desc: Verify the QueryThreadBySeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryThreadBySeqNumberTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t seqNumber = 1;
    std::shared_ptr<ThreadMessageInfo> messageInfo = std::make_shared<ThreadMessageInfo>();
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);
    auto ret = skeleton->QueryThreadBySeqNumber(seqNumber);
    ASSERT_TRUE(ret != nullptr);

    skeleton->EraseThreadBySeqNumber(seqNumber);
    ret = skeleton->QueryThreadBySeqNumber(seqNumber);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: WakeUpThreadBySeqNumberTest001
 * @tc.desc: Verify the WakeUpThreadBySeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, WakeUpThreadBySeqNumberTest001, TestSize.Level1)
{
    uint64_t seqNumber = 1;
    uint32_t handler = 1;
    auto process = [](int32_t timeout) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
    };
    std::thread thread1(process, EXECUTE_TIME_TEST);
    thread1.detach();
    std::thread::id t1ID = thread1.get_id();

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumberToThread_.clear();

    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = handler;
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);
    
    std::shared_ptr<SocketThreadLockInfo> object =
        std::make_shared<SocketThreadLockInfo>();
    skeleton->threadLockInfo_.clear();
    skeleton->AttachThreadLockInfo(object, t1ID);

    skeleton->WakeUpThreadBySeqNumber(seqNumber, handler);
    ASSERT_TRUE(skeleton->threadLockInfo_.size() != 0);
}

/**
 * @tc.name: WakeUpThreadBySeqNumberTest002
 * @tc.desc: Verify the WakeUpThreadBySeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, WakeUpThreadBySeqNumberTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t seqNumber = 1;
    uint32_t handler = 1;
    skeleton->seqNumberToThread_.clear();
    skeleton->WakeUpThreadBySeqNumber(seqNumber, handler);
    ASSERT_TRUE(skeleton->QueryThreadBySeqNumber(seqNumber) == nullptr);
}

/**
 * @tc.name: WakeUpThreadBySeqNumberTest003
 * @tc.desc: Verify the WakeUpThreadBySeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, WakeUpThreadBySeqNumberTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumberToThread_.clear();
    uint64_t seqNumber = 1;
    uint32_t handler = 1;
    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = 0;
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);
    skeleton->WakeUpThreadBySeqNumber(seqNumber, handler);

    ASSERT_TRUE(skeleton->QueryThreadBySeqNumber(seqNumber) != nullptr);
}

/**
 * @tc.name: WakeUpThreadBySeqNumberTest004
 * @tc.desc: Verify the WakeUpThreadBySeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, WakeUpThreadBySeqNumberTest004, TestSize.Level1)
{
    std::thread::id t1ID = std::thread::id();

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumberToThread_.clear();
    uint64_t seqNumber = 1;
    uint32_t handler = 1;
    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = handler;
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);
    
    skeleton->threadLockInfo_.clear();
    std::shared_ptr<SocketThreadLockInfo> object =
        std::make_shared<SocketThreadLockInfo>();
    skeleton->AttachThreadLockInfo(object, t1ID);

    skeleton->WakeUpThreadBySeqNumber(seqNumber, handler);
    ASSERT_TRUE(skeleton->threadLockInfo_.size() != 0);
}

/**
 * @tc.name: WakeUpThreadBySeqNumberTest005
 * @tc.desc: Verify the WakeUpThreadBySeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, WakeUpThreadBySeqNumberTest005, TestSize.Level1)
{
    uint64_t seqNumber = 1;
    uint32_t handler = 1;
    auto process = [](int32_t timeout) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
    };
    std::thread thread1(process, EXECUTE_TIME_TEST);
    thread1.detach();
    std::thread::id t1ID = thread1.get_id();

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->seqNumberToThread_.clear();

    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = handler;
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);
    
    skeleton->threadLockInfo_.clear();
    std::shared_ptr<SocketThreadLockInfo> object = nullptr;
    skeleton->AttachThreadLockInfo(object, t1ID);

    skeleton->WakeUpThreadBySeqNumber(seqNumber, handler);
    ASSERT_TRUE(skeleton->threadLockInfo_.size() != 0);
}

/**
 * @tc.name: AddSendThreadInWaitTest001
 * @tc.desc: Verify the AddSendThreadInWait function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddSendThreadInWaitTest001, TestSize.Level1)
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
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: AddSendThreadInWaitTest002
 * @tc.desc: Verify the AddSendThreadInWait function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddSendThreadInWaitTest002, TestSize.Level1)
{
    uint64_t seqNumber = 1;
    auto process = [](int32_t timeout) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
    };
    std::thread thread1(process, EXECUTE_TIME_TEST);
    std::thread::id t1ID = thread1.get_id();

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = 1;
    skeleton->seqNumberToThread_.clear();
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);

    std::shared_ptr<SocketThreadLockInfo> object =
        std::make_shared<SocketThreadLockInfo>();
    skeleton->threadLockInfo_.clear();
    skeleton->AttachThreadLockInfo(object, t1ID);

    int userWaitTime = 1;
    bool ret = skeleton->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
    ASSERT_FALSE(ret);
    thread1.join();
}

/**
 * @tc.name: AddSendThreadInWaitTest003
 * @tc.desc: Verify the AddSendThreadInWait function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddSendThreadInWaitTest003, TestSize.Level1)
{
    uint64_t seqNumber = 1;
    auto process = [](int32_t timeout) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
    };
    std::thread thread1(process, EXECUTE_TIME_TEST);

    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = 1;
    skeleton->seqNumberToThread_.clear();
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);
    skeleton->threadLockInfo_.clear();

    int userWaitTime = 1;
    bool ret = skeleton->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
    ASSERT_FALSE(ret);
    thread1.join();
}

/**
 * @tc.name: AddSendThreadInWaitTest004
 * @tc.desc: Verify the AddSendThreadInWait function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddSendThreadInWaitTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t seqNumber = 1;
    auto process = [skeleton](int32_t timeout) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        skeleton->WakeUpThreadBySeqNumber(1, 1);
    };
    std::thread thread1(process, EXECUTE_TIME_TEST);

    auto messageInfo = std::make_shared<ThreadMessageInfo>();
    messageInfo->socketId = 1;
    skeleton->seqNumberToThread_.clear();
    skeleton->AddThreadBySeqNumber(seqNumber, messageInfo);
    skeleton->threadLockInfo_.clear();

    int userWaitTime = 1;
    bool ret = skeleton->AddSendThreadInWait(seqNumber, messageInfo, userWaitTime);
    thread1.join();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: QueryStubByIndexTest001
 * @tc.desc: Verify the QueryStubByIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryStubByIndexTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t stubIndex = 1;
    skeleton->stubObjects_.clear();
    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    skeleton->stubObjects_.insert(
        std::pair<uint64_t, IRemoteObject *>(stubIndex, stubObject.GetRefPtr()));
    auto ret = skeleton->QueryStubByIndex(stubIndex);
    EXPECT_NE(ret, nullptr);
    skeleton->stubObjects_.clear();
}

/**
 * @tc.name: QueryStubByIndexTest002
 * @tc.desc: Verify the QueryStubByIndex function
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
}

/**
 * @tc.name: AddStubByIndexTest001
 * @tc.desc: Verify the AddStubByIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddStubByIndexTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t stubIndex = 1;
    skeleton->stubObjects_.clear();

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    skeleton->stubObjects_.insert(
        std::pair<uint64_t, IRemoteObject *>(stubIndex, stubObject.GetRefPtr()));

    auto ret = skeleton->AddStubByIndex(stubObject.GetRefPtr());
    EXPECT_EQ(ret, stubIndex);
}

/**
 * @tc.name: AddStubByIndexTest002
 * @tc.desc: Verify the AddStubByIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddStubByIndexTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t stubIndex = 1;
    skeleton->stubObjects_.clear();

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    skeleton->stubObjects_.insert(
        std::pair<uint64_t, IRemoteObject *>(stubIndex, stubObject.GetRefPtr()));

    sptr<IRemoteObject> object = new IPCObjectStub(u"bject");
    skeleton->randNum_ = 0;
    uint64_t index = skeleton->AddStubByIndex(object.GetRefPtr());
    uint64_t ret = 0;
    EXPECT_EQ(ret, index);
}

/**
 * @tc.name: AddStubByIndexTest003
 * @tc.desc: Verify the AddStubByIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AddStubByIndexTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t stubIndex = 1;
    skeleton->stubObjects_.clear();

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    skeleton->stubObjects_.insert(
        std::pair<uint64_t, IRemoteObject *>(stubIndex, stubObject.GetRefPtr()));

    sptr<IRemoteObject> object = new IPCObjectStub(u"bject");
    skeleton->randNum_ = 10;
    uint64_t index = skeleton->AddStubByIndex(object.GetRefPtr());
    uint64_t ret = 10;
    EXPECT_EQ(ret, index);
}

/**
 * @tc.name: EraseStubIndexTest001
 * @tc.desc: Verify the EraseStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, EraseStubIndexTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->stubObjects_.clear();
    uint64_t stubIndex = 1;
    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    skeleton->stubObjects_.insert(
        std::pair<uint64_t, IRemoteObject *>(stubIndex, stubObject.GetRefPtr()));

    uint64_t ret = skeleton->EraseStubIndex(stubObject.GetRefPtr());
    EXPECT_EQ(ret, stubIndex);
    skeleton->stubObjects_.clear();
}

/**
 * @tc.name: EraseStubIndexTest002
 * @tc.desc: Verify the EraseStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, EraseStubIndexTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->stubObjects_.clear();
    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");

    uint64_t ret = skeleton->EraseStubIndex(stubObject.GetRefPtr());
    uint64_t index = 0;
    EXPECT_EQ(ret, index);
}

/**
 * @tc.name: DetachAppInfoToStubIndexTest001
 * @tc.desc: Verify the DetachAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppInfoToStubIndexTest001, TestSize.Level1)
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
    std::map<uint64_t, int32_t> indexMap = {
        { stubIndex, listenFd }
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    bool ret = skeleton->DetachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: DetachAppInfoToStubIndexTest002
 * @tc.desc: Verify the DetachAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppInfoToStubIndexTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->appInfoToStubIndex_.clear();
    uint32_t pid = 1;
    uint32_t uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "testDeviceId";
    uint64_t stubIndex = 1;
    uint64_t index = 0;
    int32_t listenFd = 1;
    std::string appInfo = deviceId + skeleton->UIntToString(pid) + skeleton->UIntToString(uid) +
        skeleton->UIntToString(tokenId);
    std::map<uint64_t, int32_t> indexMap = {
        { stubIndex, listenFd }
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    bool ret = skeleton->DetachAppInfoToStubIndex(pid, uid, tokenId, deviceId, index, listenFd);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: DetachAppInfoToStubIndexTest003
 * @tc.desc: Verify the DetachAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppInfoToStubIndexTest003, TestSize.Level1)
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
    std::map<uint64_t, int32_t> indexMap = {
        { stubIndex, listenFd }
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    auto ret = skeleton->DetachAppInfoToStubIndex(pid, uid, tokenId, deviceId, listenFd);
    ASSERT_TRUE(ret.size() == 1);
    EXPECT_EQ(ret.front(), 1);
}

/**
 * @tc.name: DetachAppInfoToStubIndexTest004
 * @tc.desc: Verify the DetachAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppInfoToStubIndexTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->appInfoToStubIndex_.clear();
    uint32_t pid = 1;
    uint32_t uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "testDeviceId";
    uint64_t index = 0;
    int32_t listenFd = 1;

    bool ret = skeleton->DetachAppInfoToStubIndex(pid, uid, tokenId, deviceId, index, listenFd);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: DetachAppInfoToStubIndexTest005
 * @tc.desc: Verify the DetachAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppInfoToStubIndexTest005, TestSize.Level1)
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
    std::map<uint64_t, int32_t> indexMap = {
        { stubIndex, listenFd }
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    skeleton->DetachAppInfoToStubIndex(stubIndex);
    auto index = skeleton->appInfoToStubIndex_[appInfo];
    ASSERT_TRUE(index.size() == 0);
}

/**
 * @tc.name: DetachAppInfoToStubIndexTest006
 * @tc.desc: Verify the DetachAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachAppInfoToStubIndexTest006, TestSize.Level1)
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
    std::map<uint64_t, int32_t> indexMap = {
        { 0, listenFd },
        { 1, listenFd },
    };
    skeleton->appInfoToStubIndex_[appInfo] = indexMap;

    skeleton->DetachAppInfoToStubIndex(stubIndex);
    auto index = skeleton->appInfoToStubIndex_[appInfo];
    ASSERT_TRUE(index.size() == 1);
}

/**
 * @tc.name: AttachAppInfoToStubIndexTest001
 * @tc.desc: Verify the AttachAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachAppInfoToStubIndexTest001, TestSize.Level1)
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
    bool ret = skeleton->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    EXPECT_FALSE(ret);

    skeleton->appInfoToStubIndex_.clear();
    std::map<uint64_t, int32_t> indexNewMap = {{ 0, listenFd }};
    skeleton->appInfoToStubIndex_[appInfo] = indexNewMap;
    ret = skeleton->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    EXPECT_TRUE(ret);

    ret = skeleton->AttachAppInfoToStubIndex(pid, uid, tokenId, deviceId, listenFd);
    skeleton->DetachAppInfoToStubIndex(listenFd);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DetachCallbackStubTest001
 * @tc.desc: Verify the DetachCallbackStub function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachCallbackStubTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->noticeStub_.clear();

    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"testObject");
    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(1);
    skeleton->noticeStub_[objectProxy.GetRefPtr()] = objectStub;

    bool ret = skeleton->DetachCallbackStub(objectProxy.GetRefPtr());

    EXPECT_EQ(ret, true);
    skeleton->noticeStub_.clear();
}

/**
 * @tc.name: DetachCallbackStubTest002
 * @tc.desc: Verify the DetachCallbackStub function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachCallbackStubTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"testObject");
    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(1);
    skeleton->noticeStub_.clear();
    bool ret = skeleton->DetachCallbackStub(objectProxy.GetRefPtr());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: QueryCallbackProxyTest001
 * @tc.desc: Verify the QueryCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryCallbackProxyTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->noticeStub_.clear();

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(1);
    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"testObject");
    skeleton->noticeStub_[objectProxy.GetRefPtr()] = objectStub;
    auto ret = skeleton->QueryCallbackProxy(objectStub.GetRefPtr());
    EXPECT_NE(ret, nullptr);
    skeleton->noticeStub_.clear();
}

/**
 * @tc.name: QueryCallbackProxyTest002
 * @tc.desc: Verify the QueryCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryCallbackProxyTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->noticeStub_.clear();

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(1);
    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"testObject");
    skeleton->noticeStub_[objectProxy.GetRefPtr()] = objectStub;
    auto ret = skeleton->QueryCallbackProxy(objectStub.GetRefPtr());
    EXPECT_NE(ret, nullptr);
    skeleton->noticeStub_.clear();
}

/**
 * @tc.name: QueryCallbackProxyTest003
 * @tc.desc: Verify the QueryCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryCallbackProxyTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->noticeStub_.clear();

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(1);
    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"testObject");
    skeleton->noticeStub_[objectProxy.GetRefPtr()] = objectStub;
    auto ret = skeleton->QueryCallbackProxy(objectStub.GetRefPtr());
    EXPECT_NE(ret, nullptr);
    skeleton->noticeStub_.clear();
}

/**
 * @tc.name: CreateSoftbusServerTest001
 * @tc.desc: Verify the CreateSoftbusServer function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, CreateSoftbusServerTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::string name = "";
    auto ret = skeleton->CreateSoftbusServer(name);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: QueryRawDataTest001
 * @tc.desc: Verify the QueryRawData function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryRawDataTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    int32_t socketId = 1;
    uint64_t seqNumber = 1;
    skeleton->rawData_.clear();
    auto rawDataKey = std::to_string(socketId) + "_" + std::to_string(seqNumber);
    skeleton->rawData_[rawDataKey] = std::make_shared<InvokerRawData>(1);

    auto ret = skeleton->QueryRawData(socketId, seqNumber);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: QueryRawDataTest002
 * @tc.desc: Verify the QueryRawData function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryRawDataTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    int32_t socketId = 1;
    uint64_t seqNumber = 1;
    skeleton->rawData_.clear();
    auto ret = skeleton->QueryRawData(socketId, seqNumber);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: IsSameRemoteObjectTest001
 * @tc.desc: Verify the IsSameRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsSameRemoteObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    bool ret = skeleton->IsSameRemoteObject(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId, auth);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsSameRemoteObjectTest002
 * @tc.desc: Verify the IsSameRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsSameRemoteObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    bool ret = skeleton->IsSameRemoteObject(nullptr, pid, uid, tokenId, deviceId, auth);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsSameRemoteObjectTest003
 * @tc.desc: Verify the IsSameRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsSameRemoteObjectTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    bool ret = skeleton->IsSameRemoteObject(stubObject.GetRefPtr(), 0, uid, tokenId, deviceId, auth);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsSameRemoteObjectTest004
 * @tc.desc: Verify the IsSameRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsSameRemoteObjectTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    bool ret = skeleton->IsSameRemoteObject(stubObject.GetRefPtr(), pid, 0, tokenId, deviceId, auth);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsSameRemoteObjectTest005
 * @tc.desc: Verify the IsSameRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsSameRemoteObjectTest005, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    bool ret = skeleton->IsSameRemoteObject(stubObject.GetRefPtr(), pid, uid, 0, deviceId, auth);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsSameRemoteObjectTest006
 * @tc.desc: Verify the IsSameRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsSameRemoteObjectTest006, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    bool ret = skeleton->IsSameRemoteObject(stubObject.GetRefPtr(), pid, uid, tokenId, "testdeviceId", auth);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: AttachCommAuthInfoTest001
 * @tc.desc: Verify the AttachCommAuthInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachCommAuthInfoTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->commAuth_.clear();
    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    skeleton->commAuth_.push_back(auth);
    bool ret = skeleton->AttachCommAuthInfo(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);
    EXPECT_EQ(ret, false);
    skeleton->commAuth_.clear();
}

/**
 * @tc.name: AttachCommAuthInfoTest002
 * @tc.desc: Verify the AttachCommAuthInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachCommAuthInfoTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->commAuth_.clear();
    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";

    bool ret = skeleton->AttachCommAuthInfo(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: QueryIsAuthTest001
 * @tc.desc: Verify the QueryIsAuth function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryIsAuthTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->commAuth_.clear();
    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    skeleton->commAuth_.push_back(auth);
    bool ret = skeleton->QueryCommAuthInfo(pid, uid, tokenId, deviceId);
    EXPECT_EQ(ret, true);
    skeleton->commAuth_.clear();
    auth->stub_ = nullptr;
}

/**
 * @tc.name: QueryIsAuthTest002
 * @tc.desc: Verify the QueryIsAuth function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryIsAuthTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->commAuth_.clear();
    sptr<IRemoteObject> stubObject = new IPCObjectStub(u"testObject");
    int pid = 1;
    int uid = 1;
    uint32_t tokenId = 1;
    std::string deviceId = "test";
    std::shared_ptr<CommAuthInfo> auth =
        std::make_shared<CommAuthInfo>(stubObject.GetRefPtr(), pid, uid, tokenId, deviceId);

    skeleton->commAuth_.push_back(auth);
    bool ret = skeleton->QueryCommAuthInfo(0, uid, tokenId, deviceId);
    EXPECT_EQ(ret, false);
    skeleton->commAuth_.clear();
    auth->stub_ = nullptr;
}

/**
 * @tc.name: GetUndestroyObjectTest001
 * @tc.desc: Verify the GetUndestroyObject function with empty targets
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::unordered_set<std::string> targets;
    std::string result = skeleton->GetUndestroyObject(targets);

    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetUndestroyObjectTest002
 * @tc.desc: Verify the GetUndestroyObject function with non-existent target
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::unordered_set<std::string> targets = {"lib_nonexistent_test.so"};
    std::string result = skeleton->GetUndestroyObject(targets);

    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetUndestroyObjectTest003
 * @tc.desc: Verify the GetUndestroyObject function with valid target
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::unordered_set<std::string> targets = {"libc.so"};
    std::string result = skeleton->GetUndestroyObject(targets);
}

/**
 * @tc.name: GetUndestroyObjectTest004
 * @tc.desc: Verify the GetUndestroyObject function with multiple targets
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest004, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::unordered_set<std::string> targets = {"libc.so", "libm.so", "libpthread.so"};
    std::string result = skeleton->GetUndestroyObject(targets);
}

/**
 * @tc.name: GetUndestroyObjectTest005
 * @tc.desc: Verify the GetUndestroyObject function with attached stub object
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest005, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> stub = new IPCObjectStub(u"testStub");
    skeleton->AttachObject(stub);

    std::unordered_set<std::string> targets = {"libc.so"};
    std::string result = skeleton->GetUndestroyObject(targets);

    skeleton->DetachObject(stub.GetRefPtr());
}

/**
 * @tc.name: GetUndestroyObjectTest006
 * @tc.desc: Verify the GetUndestroyObject function with multiple so names including empty string
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest006, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::unordered_set<std::string> targets = {"libc.so", "", "libm.so"};
    std::string result = skeleton->GetUndestroyObject(targets);

    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetUndestroyObjectTest007
 * @tc.desc: Verify the GetUndestroyObject function with empty targets set
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest007, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::unordered_set<std::string> targets;
    std::string result = skeleton->GetUndestroyObject(targets);

    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetUndestroyObjectTest008
 * @tc.desc: Verify the GetUndestroyObject function with empty string target
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest008, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::unordered_set<std::string> targets = {""};
    std::string result = skeleton->GetUndestroyObject(targets);

    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetUndestroyObjectTest009
 * @tc.desc: Verify GetUndestroyObject returns content by using existing object's so
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetUndestroyObjectTest009, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    
    // 获取ProcessSkeleton实例以访问validObjectRecord_
    auto current = ProcessSkeleton::GetInstance();
    ASSERT_NE(current, nullptr);
    
    // 确保validObjectRecord_中有对象，如果为空则创建一个
    sptr<IRemoteObject> tempStub;
    if (current->validObjectRecord_.empty()) {
        tempStub = new IPCObjectStub(u"testDescriptor");
        ASSERT_TRUE(skeleton->AttachObject(tempStub));
    }
    
    // 从validObjectRecord_中取出第一个对象
    auto it = current->validObjectRecord_.begin();
    ASSERT_NE(it, current->validObjectRecord_.end());
    
    IRemoteObject* obj = it->first;
    ASSERT_NE(obj, nullptr);
    
    // 获取对象的虚函数表指针
    auto** vtbl = reinterpret_cast<void**>(obj);
    ASSERT_NE(vtbl, nullptr);
    ASSERT_NE(*vtbl, nullptr);
    
    // 使用dladdr获取vtbl指针所在的so库信息
    Dl_info dlInfo;
    int ret = dladdr(*vtbl, &dlInfo);
    ASSERT_NE(ret, 0); // dladdr成功返回非0
    
    // 提取so库名称（只取文件名部分，不包含路径）
    std::string soPath = dlInfo.dli_fname;
    ASSERT_FALSE(soPath.empty());
    
    // 从路径中提取文件名
    size_t pos = soPath.find_last_of('/');
    std::string soName = (pos != std::string::npos) ? soPath.substr(pos + 1) : soPath;
    
    // 将这个so库传入GetUndestroyObject
    std::unordered_set<std::string> targets = {soName};
    std::string result = skeleton->GetUndestroyObject(targets);
    
    // 验证结果不为空且包含格式正确的信息
    ASSERT_FALSE(result.empty());
    EXPECT_TRUE(result.find(soName) != std::string::npos);
    EXPECT_TRUE(result.find("-%-") != std::string::npos);
    
    // 清理：如果是我们创建的临时对象，需要detach
    if (tempStub != nullptr) {
        skeleton->DetachObject(tempStub.GetRefPtr());
    }
}

/**
 * @tc.name: QueryDBinderCallbackStubTest001
 * @tc.desc: Verify the QueryDBinderCallbackStub function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryDBinderCallbackStubTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->dbinderSentCallback_.clear();

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(1);
    sptr<DBinderCallbackStub> stub = new DBinderCallbackStub(
        "serviceName", "peerDeviceID", "localDeviceID", 1, 1, 1);
    skeleton->dbinderSentCallback_[objectProxy] = stub;

    auto ret = skeleton->QueryDBinderCallbackStub(objectProxy);
    EXPECT_NE(ret, nullptr);
    skeleton->dbinderSentCallback_.clear();
}

/**
 * @tc.name: QueryDBinderCallbackStubTest002
 * @tc.desc: Verify the QueryDBinderCallbackStub function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryDBinderCallbackStubTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->dbinderSentCallback_.clear();

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(1);

    auto ret = skeleton->QueryDBinderCallbackStub(objectProxy);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryDBinderCallbackProxyTest001
 * @tc.desc: Verify the QueryDBinderCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryDBinderCallbackProxyTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->dbinderSentCallback_.clear();

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    sptr<DBinderCallbackStub> stub = new DBinderCallbackStub(
        "serviceName", "peerDeviceID", "localDeviceID", 1, 1, 1);
    skeleton->dbinderSentCallback_[object] = stub;

    auto ret = skeleton->QueryDBinderCallbackStub(object);
    EXPECT_NE(ret, nullptr);
    skeleton->dbinderSentCallback_.clear();
}


/**
 * @tc.name: QueryDBinderCallbackProxyTest002
 * @tc.desc: Verify the QueryDBinderCallbackProxy function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryDBinderCallbackProxyTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    skeleton->dbinderSentCallback_.clear();

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");

    auto ret = skeleton->QueryDBinderCallbackProxy(object);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: ProxyQueryDBinderSessionTest002
 * @tc.desc: Verify the ProxyQueryDBinderSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ProxyQueryDBinderSessionTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint32_t handler = 1;
    skeleton->proxyToSession_.clear();
    auto ret = skeleton->ProxyQueryDBinderSession(handler);

    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryHandleByDatabusSessionTest002
 * @tc.desc: Verify the QueryHandleByDatabusSession function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryHandleByDatabusSessionTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->proxyToSession_.clear();
    const std::string name("nameTest");
    const std::string deviceId("deviceIdTest");
    uint64_t index = 1;

    auto object = std::make_shared<DBinderSessionObject>(name, deviceId, 1, nullptr, 1);
    uint32_t handler = 1;
    skeleton->proxyToSession_.insert(
        std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handler, object));
    auto ret = skeleton->QueryHandleByDatabusSession(name, deviceId, index);

    EXPECT_EQ(ret, handler);
}

/**
 * @tc.name: QuerySessionByInfoTest002
 * @tc.desc: Verify the QuerySessionByInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QuerySessionByInfoTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    const std::string name("name");
    const std::string deviceId("deviceId");
    const std::string deviceIdTest("deviceIdTest");

    skeleton->proxyToSession_.clear();
    auto object = std::make_shared<DBinderSessionObject>(name, deviceId, 1, nullptr, 1);
    uint32_t handler = 1;
    skeleton->proxyToSession_.insert(
        std::pair<uint32_t, std::shared_ptr<DBinderSessionObject>>(handler, object));

    auto ret = skeleton->QuerySessionByInfo(name, deviceIdTest);

    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QuerySessionByInfoTest003
 * @tc.desc: Verify the QuerySessionByInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QuerySessionByInfoTest003, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    const std::string name("nameTest");
    const std::string deviceId("deviceIdTest");
    skeleton->proxyToSession_.clear();
    auto ret = skeleton->QuerySessionByInfo(name, deviceId);

    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryThreadLockInfoTest002
 * @tc.desc: Verify the QueryThreadLockInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryThreadLockInfoTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::thread::id threadId;
    skeleton->threadLockInfo_.clear();

    auto ret = skeleton->QueryThreadLockInfo(threadId);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: DeleteDataThreadFromIdleTest002
 * @tc.desc: Verify the DeleteDataThreadFromIdle function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DeleteDataThreadFromIdleTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::thread::id threadId;
    skeleton->idleDataThreads_.clear();

    bool ret = skeleton->DeleteDataThreadFromIdle(threadId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: GetIdleDataThreadTest002
 * @tc.desc: Verify the GetIdleDataThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetIdleDataThreadTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::thread::id threadId;
    skeleton->idleDataThreads_.clear();
    auto ret = skeleton->GetIdleDataThread();
    EXPECT_EQ(threadId, ret);
}

/**
 * @tc.name: GetSocketIdleThreadNumTest002
 * @tc.desc: Verify the GetSocketIdleThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetSocketIdleThreadNumTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    delete skeleton->threadPool_;
    skeleton->threadPool_ = nullptr;

    auto ret = skeleton->GetSocketIdleThreadNum();
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: GetSocketTotalThreadNumTest002
 * @tc.desc: Verify the GetSocketTotalThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, GetSocketTotalThreadNumTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    delete skeleton->threadPool_;
    skeleton->threadPool_ = nullptr;

    auto ret = skeleton->GetSocketTotalThreadNum();
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: PopDataInfoFromThreadTest002
 * @tc.desc: Verify the PopDataInfoFromThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, PopDataInfoFromThreadTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::thread::id threadId;
    std::shared_ptr<ThreadProcessInfo> processInfo =
        std::make_shared<ThreadProcessInfo>();
    skeleton->AddDataInfoToThread(threadId, processInfo);
    ASSERT_TRUE(!(skeleton->dataInfoQueue_[threadId]).empty());

    (skeleton->dataInfoQueue_[threadId]).clear();

    auto ret = skeleton->PopDataInfoFromThread(threadId);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: QueryThreadBySeqNumberTest002
 * @tc.desc: Verify the QueryThreadBySeqNumber function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryThreadBySeqNumberTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t seqNumber = 1;
    skeleton->seqNumberToThread_.clear();
    auto ret = skeleton->QueryThreadBySeqNumber(seqNumber);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: ConvertChannelID2IntTest
 * @tc.desc: Verify convert channelId type: int64 to uint32
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ConvertChannelID2IntTest, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    int64_t channelId = -1;
    uint32_t ret = skeleton->ConvertChannelID2Int(channelId);
    ASSERT_EQ(ret, 0);

    channelId = 1;
    ret = skeleton->ConvertChannelID2Int(channelId);
    ASSERT_EQ(ret, 1);
}

/**
 * @tc.name: StubDBinderSessionTest
 * @tc.desc: Verify attach and detach stub dbinder session.
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, StubDBinderSessionTest, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    uint32_t testHandle = 1;
    uint32_t testTokenId = 1;
    bool ret = skeleton->StubDetachDBinderSession(testHandle, testTokenId);
    EXPECT_EQ(ret, false);

    std::string name("DbinderSessionName");
    std::string deviceId("DbinderSessionDeviceId");
    auto object = std::make_shared<DBinderSessionObject>(name, deviceId, 1, nullptr, testTokenId);
    ret = skeleton->StubAttachDBinderSession(testHandle, object);
    EXPECT_EQ(ret, true);

    ret = skeleton->StubDetachDBinderSession(testHandle, testTokenId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ThreadLockInfoTest
 * @tc.desc: Verify attach and detach thread lock.
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, ThreadLockInfoTest, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::shared_ptr<SocketThreadLockInfo> object = std::make_shared<SocketThreadLockInfo>();
    std::thread::id threadId = std::this_thread::get_id();
    bool ret = skeleton->DetachThreadLockInfo(threadId);
    EXPECT_FALSE(ret);

    ret = skeleton->AttachThreadLockInfo(object, threadId);
    EXPECT_TRUE(ret);

    ret = skeleton->DetachThreadLockInfo(threadId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: AttachRawDataTest
 * @tc.desc: Verify attach and detach raw data.
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachRawDataTest, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    int32_t socketId = 1;
    uint64_t seqNumber = 1;
    std::shared_ptr<InvokerRawData> data = std::make_shared<InvokerRawData>(1);
    bool ret = skeleton->DetachRawData(socketId, seqNumber);
    EXPECT_FALSE(ret);

    ret = skeleton->AttachRawData(socketId, seqNumber, data);
    EXPECT_TRUE(ret);
    // test for the old key will be removed first
    ret = skeleton->AttachRawData(socketId, seqNumber, data);
    EXPECT_TRUE(ret);

    ret = skeleton->DetachRawData(socketId, seqNumber);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: AttachDBinderCallbackStubTest
 * @tc.desc: Verify attach and detach dbinder callback stub.
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachDBinderCallbackStubTest, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> proxy = new IPCObjectProxy(1);
    sptr<DBinderCallbackStub> stub = new DBinderCallbackStub(
        "serviceName", "peerDeviceID", "localDeviceID", 1, 1, 1);
    bool ret = skeleton->AttachDBinderCallbackStub(proxy, stub);
    EXPECT_TRUE(ret);

    ret = skeleton->AttachDBinderCallbackStub(proxy, stub);
    EXPECT_FALSE(ret);

    ret = skeleton->DetachDBinderCallbackStubByProxy(proxy);
    EXPECT_TRUE(ret);

    ret = skeleton->DetachDBinderCallbackStubByProxy(proxy);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LockForNumExecutingTest001
 * @tc.desc: Verify the LockForNumExecuting and UnlockForNumExecuting function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, LockForNumExecutingTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    delete skeleton->threadPool_;
    skeleton->threadPool_ = nullptr;
    IPCWorkThreadPool::exitFlag_ = false;
    skeleton->SetMaxWorkThread(1);
    ASSERT_TRUE(skeleton->threadPool_ != nullptr);

    // test full thread duration 1s， max thread is setNum + 1 
    skeleton->LockForNumExecuting();
    skeleton->LockForNumExecuting();
    EXPECT_NE(skeleton->numExecutingFullLastTime_, 0);
    EXPECT_EQ(skeleton->numExecuting_, skeleton->threadPool_->GetMaxThreadNum());
    sleep(1);
    skeleton->UnlockForNumExecuting();
    skeleton->UnlockForNumExecuting();
    EXPECT_EQ(skeleton->numExecutingFullLastTime_, 0);
    delete skeleton->threadPool_;
    skeleton->threadPool_ = nullptr;
    skeleton->SetMaxWorkThread(IPCProcessSkeleton::DEFAULT_WORK_THREAD_NUM);
}

/**
 * @tc.name: JoinWorkThreadTest001
 * @tc.desc: Verify the JoinWorkThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, JoinWorkThreadTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    skeleton.JoinWorkThread();
    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    delete invoker;
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

/**
 * @tc.name: StopWorkThreadTest001
 * @tc.desc: Verify the StopWorkThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, StopWorkThreadTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    skeleton.StopWorkThread();
    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingSidTest001
 * @tc.desc: Verify the GetCallingSidTest function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingSidTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, GetCallerSid())
        .WillRepeatedly(testing::Return(""));

    auto result = skeleton.GetCallingSid();
    EXPECT_EQ(result, "");
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingTokenIDTest001
 * @tc.desc: Verify the GetCallingTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingTokenIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*invoker, GetCallerTokenID())
        .WillRepeatedly(testing::Return(1));

    auto result = skeleton.GetCallingTokenID();
    EXPECT_EQ(result, 1);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingFullTokenIDTest001
 * @tc.desc: Verify the GetCallingFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingFullTokenIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*invoker, GetCallerTokenID())
        .WillRepeatedly(testing::Return(1));
    EXPECT_CALL(*invoker, GetSelfTokenID())
        .WillRepeatedly(testing::Return(1));

    auto result = skeleton.GetCallingFullTokenID();
    EXPECT_EQ(result, 1);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetFirstTokenIDTest001
 * @tc.desc: Verify the GetFirstTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstTokenIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;

    auto result = skeleton.GetFirstTokenID();
    EXPECT_EQ(result, 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

/**
 * @tc.name: GetFirstFullTokenIDTest001
 * @tc.desc: Verify the GetFirstFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;

    auto result = skeleton.GetFirstFullTokenID();
    EXPECT_EQ(result, 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
}

/**
 * @tc.name: GetFirstFullTokenIDTest002
 * @tc.desc: Verify the GetFirstFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenIDTest002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*invoker, GetCallerTokenID())
        .WillRepeatedly(testing::Return(1));
    EXPECT_CALL(*invoker, GetFirstCallerTokenID())
        .WillRepeatedly(testing::Return(1));

    auto result = skeleton.GetFirstFullTokenID();
    EXPECT_EQ(result, 1);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetFirstFullTokenIDTest003
 * @tc.desc: Verify the GetFirstFullTokenID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenIDTest003, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = nullptr;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = nullptr;

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*invoker, GetFirstCallerTokenID())
        .WillRepeatedly(testing::Return(123));

    EXPECT_CALL(*invoker, GetSelfFirstCallerTokenID())
        .WillRepeatedly(testing::Return(111));

    auto result = skeleton.GetFirstFullTokenID();
    EXPECT_EQ(result, 111);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetLocalDeviceIDTest001
 * @tc.desc: Verify the GetLocalDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetLocalDeviceIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    std::string testID = "testID";
    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, GetLocalDeviceID())
        .WillRepeatedly(testing::Return(testID));

    auto result = skeleton.GetLocalDeviceID();
    EXPECT_STREQ(result.c_str(), testID.c_str());
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingDeviceIDTest001
 * @tc.desc: Verify the GetCallingDeviceID function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingDeviceIDTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    std::string testDeviceID = "testDeviceID";
    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, GetCallerDeviceID())
        .WillRepeatedly(testing::Return(testDeviceID));

    auto result = skeleton.GetCallingDeviceID();
    EXPECT_STREQ(result.c_str(), testDeviceID.c_str());
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: IsLocalCallingTest001
 * @tc.desc: Verify the IsLocalCalling function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, IsLocalCallingTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));

    auto result = skeleton.IsLocalCalling();
    ASSERT_TRUE(!result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: FlushCommandsTest001
 * @tc.desc: Verify the FlushCommands function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, FlushCommandsTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*invoker, FlushCommands(testing::_))
        .WillRepeatedly(testing::Return(111));

    IPCObjectProxy *object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->proto_ = IRemoteObject::IF_PROT_BINDER;

    auto result = skeleton.FlushCommands(object);
    EXPECT_EQ(result, 111);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
    delete object;
}

/**
 * @tc.name: ResetCallingIdentityTest001
 * @tc.desc: Verify the ResetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, ResetCallingIdentityTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    std::string testStr = "testStr";
    EXPECT_CALL(*invoker, ResetCallingIdentity())
        .WillRepeatedly(testing::Return(testStr));

    auto result = skeleton.ResetCallingIdentity();
    EXPECT_STREQ(result.c_str(), testStr.c_str());
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: ResetCallingIdentityTest002
 * @tc.desc: Verify the ResetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, ResetCallingIdentityTest002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    std::string testStr = "";

    auto result = skeleton.ResetCallingIdentity();
    EXPECT_STREQ(result.c_str(), testStr.c_str());
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: SetCallingIdentityTest001
 * @tc.desc: Verify the SetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetCallingIdentityTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    std::string testStr = "testStr";
    EXPECT_CALL(*invoker, SetCallingIdentity(testStr, false))
        .WillRepeatedly(testing::Return(false));

    auto result = skeleton.SetCallingIdentity(testStr);
    ASSERT_TRUE(!result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: SetCallingIdentityTest002
 * @tc.desc: Verify the SetCallingIdentity function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetCallingIdentityTest002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(*invoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    std::string testStr = "";

    auto result = skeleton.SetCallingIdentity(testStr);
    ASSERT_TRUE(result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: TriggerThreadReclaim001
 * @tc.desc: Verify the TriggerSystemIPCThreadReclaim function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, TriggerThreadReclaim001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, TriggerSystemIPCThreadReclaim())
        .WillRepeatedly(testing::Return(true));

    auto result = skeleton.TriggerSystemIPCThreadReclaim();
    ASSERT_TRUE(result);

    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: EnableIPCThreadReclaim001
 * @tc.desc: Verify the EnableIPCThreadReclaim function
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, EnableIPCThreadReclaim001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(*invoker, EnableIPCThreadReclaim(false))
        .WillRepeatedly(testing::Return(true));

    auto result = skeleton.EnableIPCThreadReclaim(false);
    ASSERT_TRUE(result);

    EXPECT_CALL(*invoker, EnableIPCThreadReclaim(true))
        .WillRepeatedly(testing::Return(true));

    result = skeleton.EnableIPCThreadReclaim(true);
    ASSERT_TRUE(result);

    ASSERT_TRUE(IPCThreadSkeleton::GetCurrent() != nullptr);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetCallingUidInRPC
 * @tc.desc: Verify the GetCallingUid function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingUidInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    pid_t uid = IPCSkeleton::GetCallingUid();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(uid, -1);
}

/**
 * @tc.name: GetCallingPidInRPC
 * @tc.desc: Verify the GetCallingPid function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingPidInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    pid_t pid = IPCSkeleton::GetCallingPid();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(pid, -1);
}

/**
 * @tc.name: GetCallingRealPidInRPC
 * @tc.desc: Verify the GetCallingRealPid function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingRealPidInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    pid_t pid = IPCSkeleton::GetCallingRealPid();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(pid, -1);
}

/**
 * @tc.name: GetCallingTokenIDInRPC
 * @tc.desc: Verify the GetCallingTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetCallingFullTokenIDInRPC
 * @tc.desc: Verify the GetCallingFullTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetCallingFullTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    uint64_t tokenId = IPCSkeleton::GetCallingFullTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetFirstTokenIDInRPC
 * @tc.desc: Verify the GetFirstTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    uint32_t tokenId = IPCSkeleton::GetFirstTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetFirstFullTokenIDInRPC
 * @tc.desc: Verify the GetFirstFullTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));
    
    uint64_t tokenId = IPCSkeleton::GetFirstFullTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetDCallingTokenIDInIPC
 * @tc.desc: Verify the GetDCallingTokenID function in IPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetDCallingTokenIDInIPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*binderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    uint32_t tokenId = IPCSkeleton::GetDCallingTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetDCallingUidInIPC
 * @tc.desc: Verify the GetDCallingUid function in IPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetDCallingUidInIPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*binderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(true));

    pid_t uid = IPCSkeleton::GetDCallingUid();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(uid, -1);
}

/**
 * @tc.name: GetDCallingTokenIDInRPC
 * @tc.desc: Verify the GetDCallingTokenID function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetDCallingTokenIDInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));

    // The initial value of DBinderDatabusInvoker's callerTokenID_ is 0
    uint32_t tokenId = IPCSkeleton::GetDCallingTokenID();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(tokenId, 0);
}

/**
 * @tc.name: GetDCallingUidInRPC
 * @tc.desc: Verify the GetDCallingUid function in RPC context.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetDCallingUidInRPC, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);
    MockIRemoteInvoker *dbinderInvoker = new (std::nothrow) MockIRemoteInvoker();
    if (dbinderInvoker == nullptr) {
        delete binderInvoker;
        binderInvoker = nullptr;
        FAIL() << "dbinderInvoker new fail";
    }

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;
    current->invokers_[IRemoteObject::IF_PROT_DATABUS] = dbinderInvoker;

    EXPECT_CALL(*binderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::IDLE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, GetStatus())
        .WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));

    EXPECT_CALL(*dbinderInvoker, IsLocalCalling())
        .WillRepeatedly(testing::Return(false));

    EXPECT_CALL(*dbinderInvoker, GetCallerUid())
        .WillRepeatedly(testing::Return(1000));

    pid_t uid = IPCSkeleton::GetDCallingUid();

    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete binderInvoker;
    delete dbinderInvoker;

    ASSERT_EQ(uid, 1000);
}

#ifdef FREEZE_PROCESS_ENABLED
/**
 * @tc.name: FreezeProcessTest
 * @tc.desc: Verify the Freeze function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, FreezeProcessTest, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;

    EXPECT_CALL(*binderInvoker, Freeze(_, _, _))
        .WillRepeatedly(testing::Return(ERR_NONE));

    ASSERT_EQ(IPCSkeleton::Freeze(0, true, 0), ERR_NONE);
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;
    delete binderInvoker;
}

/**
 * @tc.name: CheckFreezeTest
 * @tc.desc: Verify the GetProcessFreezeInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, CheckFreezeTest, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;

    EXPECT_CALL(*binderInvoker, GetProcessFreezeInfo(_, _))
        .WillRepeatedly(testing::Return(ERR_NONE));

    bool isFrozen = false;
    ASSERT_EQ(IPCSkeleton::GetProcessFreezeInfo(0, isFrozen), ERR_NONE);
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;
    delete binderInvoker;
}
#endif // FREEZE_PROCESS_ENABLED

#ifdef MEMORY_USAGE_ENABLED
/**
 * @tc.name: GetMemoryUsageTest01
 * @tc.desc: Verify the GetMemoryUsage function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetMemoryUsageTest01, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);
    MockIRemoteInvoker *binderInvoker = new (std::nothrow) MockIRemoteInvoker();
    ASSERT_NE(binderInvoker, nullptr);

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = binderInvoker;

    EXPECT_CALL(*binderInvoker, GetMemoryUsage(_, _, _))
        .WillRepeatedly(testing::Return(ERR_NONE));

    unsigned long totalSize = 0UL;
    unsigned long oneWayFreeSize = 0UL;
    ASSERT_EQ(IPCSkeleton::GetMemoryUsage(0, totalSize, oneWayFreeSize), ERR_NONE);
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;
    delete binderInvoker;
}

/**
 * @tc.name: GetMemoryUsageTest02
 * @tc.desc: Verify the GetMemoryUsage function.
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetMemoryUsageTest02, TestSize.Level1)
{
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    ASSERT_NE(current, nullptr);

    unsigned long totalSize = 0UL;
    unsigned long oneWayFreeSize = 0UL;
    ASSERT_EQ(IPCSkeleton::GetMemoryUsage(0, totalSize, oneWayFreeSize), ERR_NONE);
    ZLOGI(LOG_LABEL, "get memory usage size : totalSize:%{public}lu, oneWayFreeSize:%{public}lu",
        totalSize, oneWayFreeSize);

    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = nullptr;
}

/**
 * @tc.name: IsContainsObjectTest001
 * @tc.desc: Verify the IsContainsObject function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, IsContainsObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    skeleton->isContainStub_.clear();
    bool ret = skeleton->IsContainsObject(object.GetRefPtr());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: DetachObjectTest001
 * @tc.desc: Verify the DetachObject function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, DetachObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    ASSERT_TRUE(object != nullptr);

    skeleton->AttachObject(object.GetRefPtr(), object->GetObjectDescriptor(), true);
    bool ret = skeleton->DetachObject(object.GetRefPtr(), object->GetObjectDescriptor());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: QueryObjectTest001
 * @tc.desc: Verify the QueryObject function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, QueryObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    ASSERT_TRUE(object != nullptr);
    skeleton->AttachObject(object.GetRefPtr(), object->GetObjectDescriptor(), true);
    sptr<IRemoteObject> queriedObject = skeleton->QueryObject(object->GetObjectDescriptor(), true);
    EXPECT_EQ(queriedObject.GetRefPtr(), object.GetRefPtr());
}

/**
 * @tc.name: AttachValidObjectTest001
 * @tc.desc: Verify the AttachValidObject function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, AttachValidObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);
    std::u16string str(u"testObject");
    sptr<IRemoteObject> object = new IPCObjectStub(str);
    ASSERT_TRUE(object != nullptr);

    bool ret = skeleton->AttachValidObject(object.GetRefPtr(), str);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: DetachValidObjectTest001
 * @tc.desc: Verify the DetachValidObject function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, DetachValidObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string str(u"testObject");
    sptr<IRemoteObject> object = new IPCObjectStub(str);
    skeleton->AttachValidObject(object.GetRefPtr(), str);
    bool ret = skeleton->DetachValidObject(object.GetRefPtr());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsValidObjectTest001
 * @tc.desc: Verify the IsValidObject function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, IsValidObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string str(u"testObject");
    sptr<IRemoteObject> object = new IPCObjectStub(str);
    skeleton->AttachValidObject(object.GetRefPtr(), str);
    std::u16string desc;
    bool ret = skeleton->IsValidObject(object.GetRefPtr(), desc);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: SetRegistryObjectTest001
 * @tc.desc: Verify the SetRegistryObject and GetRegistryObject functions
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, SetRegistryObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    skeleton->SetRegistryObject(object);
    sptr<IRemoteObject> registryObject = skeleton->GetRegistryObject();
    EXPECT_EQ(registryObject.GetRefPtr(), object.GetRefPtr());
}

/**
 * @tc.name: SetSamgrFlagTest001
 * @tc.desc: Verify the SetSamgrFlag functions
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, SetSamgrFlagTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->SetSamgrFlag(true);
    ASSERT_TRUE(skeleton->GetSamgrFlag());
}

/**
 * @tc.name: LockObjectMutexTest001
 * @tc.desc: Verify the LockObjectMutex and UnlockObjectMutex functions
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, LockObjectMutexTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    bool lockRet = skeleton->LockObjectMutex();
    EXPECT_EQ(lockRet, true);

    bool unlockRet = skeleton->UnlockObjectMutex();
    EXPECT_EQ(unlockRet, true);
}

/**
 * @tc.name: SetIPCProxyLimitTest001
 * @tc.desc: Verify the SetIPCProxyLimit function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, SetIPCProxyLimitTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    uint64_t limit = 1000;
    bool ret = skeleton->SetIPCProxyLimit(limit, nullptr);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ConvertToSecureDescTest001
 * @tc.desc: Verify the ConvertToSecureDesc function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, ConvertToSecureDescTest001, TestSize.Level1)
{
    std::string desc = "test.example.com";
    std::string secureDesc = ProcessSkeleton::ConvertToSecureDesc(desc);
    EXPECT_EQ(secureDesc, "*.com");
}

/**
 * @tc.name: IsPrintTest001
 * @tc.desc: Verify the IsPrint function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, IsPrintTest001, TestSize.Level1)
{
    std::atomic<int> lastErr = 0;
    std::atomic<int> lastErrCnt = 0;
    bool isPrint = ProcessSkeleton::IsPrint(1, lastErr, lastErrCnt);
    EXPECT_EQ(isPrint, true);
    EXPECT_EQ(lastErr, 1);
    EXPECT_EQ(lastErrCnt, 0);
}

/**
 * @tc.name: UnFlattenDBinderDataTest001
 * @tc.desc: Verify the UnFlattenDBinderData functions
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, UnFlattenDBinderData001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);
    Parcel data;
    dbinder_negotiation_data *bindingData;
    bool ret = skeleton->UnFlattenDBinderData(data, bindingData);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UnFlattenDBinderDataTest002
 * @tc.desc: Verify the UnFlattenDBinderData functions
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, UnFlattenDBinderDataTest002, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);
    Parcel data;
    dbinder_negotiation_data *dbinderData = nullptr;
    binder_buffer_object bufferObject;
    bufferObject.hdr.type = BINDER_TYPE_PTR;
    bufferObject.flags = BINDER_BUFFER_FLAG_HAS_DBINDER;
    bufferObject.buffer = reinterpret_cast<binder_uintptr_t>(dbinderData);
    bufferObject.length = sizeof(dbinder_negotiation_data);
    data.WriteBuffer(&bufferObject, sizeof(binder_buffer_object));
    bool ret = skeleton->UnFlattenDBinderData(data, dbinderData);
    ASSERT_FALSE(ret);
}
/**
 * @tc.name: StrToUint64001
 * @tc.desc: Verify the IsPrint function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, StrToUint64001, TestSize.Level1)
{
    uint64_t value = 0;
    bool ret = false;

    ret = ProcessSkeleton::StrToUint64("", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToUint64("0", value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, 0);

    ret = ProcessSkeleton::StrToUint64("1", value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, 1);

    std::string uint64MaxVal = std::to_string(UINT64_MAX);
    ret = ProcessSkeleton::StrToUint64(uint64MaxVal, value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, UINT64_MAX);

    // UINT64_MAX + 1
    ret = ProcessSkeleton::StrToUint64("18446744073709551616", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToUint64("-0", value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, 0);

    ret = ProcessSkeleton::StrToUint64("-1", value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, UINT64_MAX);

    ret = ProcessSkeleton::StrToUint64("- 1", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToUint64("a1", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToUint64("1a", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToUint64("99999999999999999999", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToUint64("3.14", value);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StrToInt32001
 * @tc.desc: Verify the IsPrint function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, StrToInt32001, TestSize.Level1)
{
    int32_t value = 0;
    bool ret = false;

    ret = ProcessSkeleton::StrToInt32("", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToInt32("0", value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, 0);

    ret = ProcessSkeleton::StrToInt32("1", value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, 1);

    std::string int32MaxVal = std::to_string(INT32_MAX);
    ret = ProcessSkeleton::StrToInt32(int32MaxVal, value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, INT32_MAX);

    // INT32_MAX + 1
    ret = ProcessSkeleton::StrToInt32("2147483648", value);
    EXPECT_FALSE(ret);

    std::string int32MinVal = std::to_string(INT32_MIN);
    ret = ProcessSkeleton::StrToInt32(int32MinVal, value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, INT32_MIN);

    // INT32_MIN - 1
    ret = ProcessSkeleton::StrToInt32("-2147483649", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToInt32("-0", value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, 0);

    ret = ProcessSkeleton::StrToInt32("-1", value);
    EXPECT_TRUE(ret);
    EXPECT_EQ(value, -1);

    ret = ProcessSkeleton::StrToInt32("- 1", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToInt32("a1", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToInt32("1a", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToInt32("99999999999999999999", value);
    EXPECT_FALSE(ret);

    ret = ProcessSkeleton::StrToInt32("3.14", value);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: NotifyChildThreadStop001
 * @tc.desc: Verify the NotifyChildThreadStop function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, NotifyChildThreadStop001, TestSize.Level1)
{
    ProcessSkeleton *processSkeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(processSkeleton != nullptr);

    processSkeleton->NotifyChildThreadStop();
    EXPECT_TRUE(processSkeleton->GetThreadStopFlag());
}

/**
 * @tc.name: NotifyChildThreadStop002
 * @tc.desc: Verify the NotifyChildThreadStop function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, NotifyChildThreadStop002, TestSize.Level1)
{
    ProcessSkeleton *processSkeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(processSkeleton != nullptr);

    processSkeleton->IncreaseThreadCount();
    processSkeleton->NotifyChildThreadStop();
    EXPECT_TRUE(processSkeleton->GetThreadStopFlag());
    processSkeleton->DecreaseThreadCount();
}

/**
 * @tc.name: NotifyChildThreadStop003
 * @tc.desc: Verify the NotifyChildThreadStop function
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, NotifyChildThreadStop003, TestSize.Level1)
{
    ProcessSkeleton *processSkeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(processSkeleton != nullptr);

    processSkeleton->IncreaseThreadCount();
    processSkeleton->DecreaseThreadCount();
    processSkeleton->NotifyChildThreadStop();
    EXPECT_TRUE(processSkeleton->GetThreadStopFlag());
}

/**
 * @tc.name: AttachObjectTest001
 * @tc.desc: Verify the AttachObject function with empty descriptor
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, AttachObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"");
    ASSERT_TRUE(object != nullptr);

    bool ret = skeleton->AttachObject(object.GetRefPtr(), object->GetObjectDescriptor(), true);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: DetachObjectTest002
 * @tc.desc: Verify the DetachObject function when descriptor does not exist
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, DetachObjectTest002, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    ASSERT_TRUE(object != nullptr);

    bool ret = skeleton->DetachObject(object.GetRefPtr(), u"missing");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsValidObjectTest002
 * @tc.desc: Verify the IsValidObject function with null object
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, IsValidObjectTest002, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string desc;
    bool ret = skeleton->IsValidObject(nullptr, desc);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ConvertToSecureDescTest002
 * @tc.desc: Verify the ConvertToSecureDesc function with short string
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonUnitTest, ConvertToSecureDescTest002, TestSize.Level1)
{
    std::string desc = "abc";
    std::string secureDesc = ProcessSkeleton::ConvertToSecureDesc(desc);
    EXPECT_EQ(secureDesc, "abc");
}
#endif
} // namespace OHOS
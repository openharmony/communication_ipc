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
#include "ipc_types.h"
#include "ipc_thread_pool.h"
#include "ipc_workthread.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class IPCWorkThreadPoolUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void IPCWorkThreadPoolUnitTest::SetUpTestCase()
{
}

void IPCWorkThreadPoolUnitTest::TearDownTestCase()
{
}

void IPCWorkThreadPoolUnitTest::SetUp() {}

void IPCWorkThreadPoolUnitTest::TearDown() {}

/**
 * @tc.name: RemoveThreadTest001
 * @tc.desc: Verify the RemoveThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadPoolUnitTest, RemoveThreadTest001, TestSize.Level1)
{
    IPCWorkThreadPool threadPool(1);
    std::string threadName = "threadName1";

    auto ipcThread = new (std::nothrow) IPCWorkThread(threadName);
    ASSERT_TRUE(ipcThread != nullptr);
    ipcThread->proto_ = IRemoteObject::IF_PROT_DEFAULT;
    threadPool.threads_[threadName] = ipcThread;
    IPCWorkThreadPool::exitFlag_ = false;
    auto ret = threadPool.RemoveThread(threadName);

    EXPECT_EQ(ret, true);
    threadPool.threads_.clear();
    ASSERT_TRUE(ipcThread != nullptr);
}

/**
 * @tc.name: RemoveThreadTest002
 * @tc.desc: Verify the RemoveThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadPoolUnitTest, RemoveThreadTest002, TestSize.Level1)
{
    IPCWorkThreadPool threadPool(1);
    std::string threadName = "threadName2";

    auto ipcThread = new (std::nothrow) IPCWorkThread(threadName);
    ipcThread->proto_ = IRemoteObject::IF_PROT_DATABUS;
    threadPool.threads_[threadName] = ipcThread;
    IPCWorkThreadPool::exitFlag_ = false;
    auto ret = threadPool.RemoveThread(threadName);

    EXPECT_EQ(ret, true);
    threadPool.threads_.clear();
}

/**
 * @tc.name: RemoveThreadTest003
 * @tc.desc: Verify the RemoveThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadPoolUnitTest, RemoveThreadTest003, TestSize.Level1)
{
    IPCWorkThreadPool threadPool(1);
    std::string threadName = "threadName3";

    auto ipcThread = new (std::nothrow) IPCWorkThread(threadName);
    ipcThread->proto_ = IRemoteObject::IF_PROT_ERROR;
    threadPool.threads_[threadName] = ipcThread;
    IPCWorkThreadPool::exitFlag_ = false;
    auto ret = threadPool.RemoveThread(threadName);

    EXPECT_EQ(ret, true);
    threadPool.threads_.clear();
}

/**
 * @tc.name: RemoveThreadTest004
 * @tc.desc: Verify the RemoveThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadPoolUnitTest, RemoveThreadTest004, TestSize.Level1)
{
    IPCWorkThreadPool threadPool(1);
    std::string threadName = "threadName4";

    sptr<IPCWorkThread> ipcThread = nullptr;
    threadPool.threads_[threadName] = ipcThread;
    auto ret = threadPool.RemoveThread(threadName);

    EXPECT_EQ(ret, false);
    threadPool.threads_.clear();
}

/**
 * @tc.name: RemoveThreadTest005
 * @tc.desc: Verify the RemoveThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadPoolUnitTest, RemoveThreadTest005, TestSize.Level1)
{
    IPCWorkThreadPool threadPool(1);
    std::string threadName = "threadName5";

    auto ret = threadPool.RemoveThread(threadName);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: UpdateMaxThreadNumTest001
 * @tc.desc: Verify the UpdateMaxThreadNum function
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadPoolUnitTest, UpdateMaxThreadNumTest001, TestSize.Level1)
{
    IPCWorkThreadPool threadPool(1);
    threadPool.UpdateMaxThreadNum(0);

    EXPECT_EQ(threadPool.maxThreadNum_, 2);
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
} // namespace OHOS
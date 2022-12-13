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

class IPCWorkThreadPoolUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
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
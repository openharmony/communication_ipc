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

#include "dbinder_databus_invoker.h"
#include "ipc_workthread.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {

namespace {
const std::string THREAD_NAME = "test_thread";
}

struct IPCWorkThreadParam {
public:
    int proto;
    int policy;
    int index;
};

class IPCWorkThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCWorkThreadTest::SetUpTestCase()
{
}

void IPCWorkThreadTest::TearDownTestCase()
{
}

void IPCWorkThreadTest::SetUp()
{
}

void IPCWorkThreadTest::TearDown()
{
}

class IPCWorkThreadInterface {
public:
    IPCWorkThreadInterface() {};
    virtual ~IPCWorkThreadInterface() {};

    virtual IRemoteInvoker *GetRemoteInvoker(int proto) = 0;
    virtual ProcessSkeleton *GetInstance() = 0;
    virtual void JoinProcessThread(bool initiative) = 0;
    virtual int pthread_create(pthread_t *thread,
                               const pthread_attr_t *attr,
                               void *(*start_routine)(void *),
                               void *arg) = 0;
    virtual int pthread_detach(pthread_t thread) = 0;
};

class IPCWorkThreadInterfaceMock : public IPCWorkThreadInterface {
public:
    IPCWorkThreadInterfaceMock();
    ~IPCWorkThreadInterfaceMock() override;

    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
    MOCK_METHOD0(GetInstance, ProcessSkeleton *());
    MOCK_METHOD1(JoinProcessThread, void(bool));
    MOCK_METHOD4(pthread_create, int(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *));
    MOCK_METHOD1(pthread_detach, int(pthread_t));
};

static void *g_interface = nullptr;

IPCWorkThreadInterfaceMock::IPCWorkThreadInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCWorkThreadInterfaceMock::~IPCWorkThreadInterfaceMock()
{
    g_interface = nullptr;
}

static IPCWorkThreadInterface *GetIPCWorkThreadInterface()
{
    return reinterpret_cast<IPCWorkThreadInterface *>(g_interface);
}

extern "C" {
IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
{
    auto interface = GetIPCWorkThreadInterface();
    if (interface == nullptr) {
        return nullptr;
    }
    return interface->GetRemoteInvoker(proto);
}

ProcessSkeleton *ProcessSkeleton::GetInstance()
{
    auto interface = GetIPCWorkThreadInterface();
    if (interface == nullptr) {
        return nullptr;
    }
    return interface->GetInstance();
}

void DBinderDatabusInvoker::JoinProcessThread(bool initiative)
{
    auto interface = GetIPCWorkThreadInterface();
    if (interface == nullptr) {
        return;
    }
    interface->JoinProcessThread(initiative);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
{
    auto interface = GetIPCWorkThreadInterface();
    if (interface == nullptr) {
        return -1;
    }
    return interface->pthread_create(thread, attr, start_routine, arg);
}

int pthread_detach(pthread_t thread)
{
    auto interface = GetIPCWorkThreadInterface();
    if (interface == nullptr) {
        return -1;
    }
    return interface->pthread_detach(thread);
}
}

/**
 * @tc.name: JoinThread001
 * @tc.desc: Verify the JoinThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadTest, JoinThread001, TestSize.Level1)
{
    int proto = 1;
    int policy = IPCWorkThread::PROCESS_ACTIVE + 1;
    IPCWorkThread workThread(THREAD_NAME);
    NiceMock<IPCWorkThreadInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new (std::nothrow) DBinderDatabusInvoker();
    EXPECT_NE(invoker, nullptr);
    EXPECT_CALL(mock, GetRemoteInvoker(proto)).Times(1).WillOnce(Return(invoker));
    workThread.JoinThread(proto, policy);
    delete invoker;
}

/**
 * @tc.name: JoinThread002
 * @tc.desc: Verify the JoinThread function
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadTest, JoinThread002, TestSize.Level1)
{
    int proto = 1;
    int policy = IPCWorkThread::PROCESS_ACTIVE;
    IPCWorkThread workThread(THREAD_NAME);
    NiceMock<IPCWorkThreadInterfaceMock> mock;
    DBinderDatabusInvoker *invoker = new (std::nothrow) DBinderDatabusInvoker();
    EXPECT_NE(invoker, nullptr);
    EXPECT_CALL(mock, GetRemoteInvoker(_)).Times(1).WillOnce(Return(invoker));
    EXPECT_CALL(mock, JoinProcessThread(true)).Times(1);
    workThread.JoinThread(proto, policy);
    delete invoker;
}

/**
 * @tc.name: ThreadHandler001
 * @tc.desc: Verify the ThreadHandler function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadTest, ThreadHandler001, TestSize.Level1)
{
    IPCWorkThread workThread(THREAD_NAME);
    EXPECT_EQ(workThread.ThreadHandler(nullptr), nullptr);
}

/**
 * @tc.name: ThreadHandler002
 * @tc.desc: Verify the ThreadHandler function when process is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadTest, ThreadHandler002, TestSize.Level1)
{
    auto param = new (std::nothrow) IPCWorkThreadParam();
    EXPECT_NE(param, nullptr);
    IPCWorkThread workThread(THREAD_NAME);
    NiceMock<IPCWorkThreadInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).Times(1).WillOnce(Return(nullptr));
    EXPECT_EQ(workThread.ThreadHandler(param), nullptr);
}

/**
 * @tc.name: Start001
 * @tc.desc: Verify the Start function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadTest, Start001, TestSize.Level1)
{
    int policy = 0;
    int proto = 0;
    int threadIndex = 0;
    NiceMock<IPCWorkThreadInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).Times(1).WillOnce(Return(nullptr));
    IPCWorkThread workThread(THREAD_NAME);
    EXPECT_FALSE(workThread.Start(policy, proto, threadIndex));
}

/**
 * @tc.name: Start002
 * @tc.desc: Verify the Start function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadTest, Start002, TestSize.Level1)
{
    int policy = 0;
    int proto = 0;
    int threadIndex = 0;
    NiceMock<IPCWorkThreadInterfaceMock> mock;
    std::shared_ptr<ProcessSkeleton> process = std::make_shared<ProcessSkeleton>();
    EXPECT_NE(process, nullptr);
    EXPECT_CALL(mock, GetInstance()).Times(1).WillOnce(Return(process.get()));
    EXPECT_CALL(mock, pthread_create).Times(1).WillOnce(Return(-1));
    IPCWorkThread workThread(THREAD_NAME);
    EXPECT_FALSE(workThread.Start(policy, proto, threadIndex));
}

/**
 * @tc.name: Start003
 * @tc.desc: Verify the Start function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCWorkThreadTest, Start003, TestSize.Level1)
{
    int policy = 0;
    int proto = 0;
    int threadIndex = 0;
    NiceMock<IPCWorkThreadInterfaceMock> mock;
    std::shared_ptr<ProcessSkeleton> process = std::make_shared<ProcessSkeleton>();
    EXPECT_NE(process, nullptr);
    EXPECT_CALL(mock, GetInstance()).Times(1).WillOnce(Return(process.get()));
    EXPECT_CALL(mock, pthread_create).Times(1).WillOnce(Return(0));
    EXPECT_CALL(mock, pthread_detach).Times(1).WillOnce(Return(-1));
    IPCWorkThread workThread(THREAD_NAME);
    EXPECT_FALSE(workThread.Start(policy, proto, threadIndex));
}
} // namespace OHOS
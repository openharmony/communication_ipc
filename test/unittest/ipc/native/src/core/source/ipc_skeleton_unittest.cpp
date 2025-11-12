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
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "mock_iremote_invoker.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace {
    const std::u16string DESCRIPTOR_TEST = u"test";
    const int HANDLE_TEST = 1;
    const int RESULT_TEST = 111;
}

class IPCSkeletonInterface {
public:
    IPCSkeletonInterface() {};
    virtual ~IPCSkeletonInterface() {};

    virtual sptr<IRemoteObject> GetRegistryObject() = 0;
    virtual bool SetRegistryObject(sptr<IRemoteObject> &object) = 0;
    virtual bool SetMaxWorkThread(int maxThreadNum) = 0;
    virtual IRemoteInvoker *GetDefaultInvoker() = 0;
    virtual IRemoteInvoker *GetActiveInvoker() = 0;
    virtual IRemoteInvoker *GetProxyInvoker(IRemoteObject *object) = 0;
};

class IPCSkeletonInterfaceMock : public IPCSkeletonInterface {
public:
    IPCSkeletonInterfaceMock();
    ~IPCSkeletonInterfaceMock() override;

    MOCK_METHOD0(GetRegistryObject, sptr<IRemoteObject>());
    MOCK_METHOD1(SetRegistryObject, bool(sptr<IRemoteObject> &object));
    MOCK_METHOD1(SetMaxWorkThread, bool(int maxThreadNum));
    MOCK_METHOD0(GetDefaultInvoker, IRemoteInvoker *());
    MOCK_METHOD0(GetActiveInvoker, IRemoteInvoker *());
    MOCK_METHOD1(GetProxyInvoker, IRemoteInvoker *(IRemoteObject *object));
};

static void *g_interface = nullptr;

IPCSkeletonInterfaceMock::IPCSkeletonInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCSkeletonInterfaceMock::~IPCSkeletonInterfaceMock()
{
    g_interface = nullptr;
}

static IPCSkeletonInterface *GetIPCSkeletonInterface()
{
    return reinterpret_cast<IPCSkeletonInterface *>(g_interface);
}

extern "C" {
    sptr<IRemoteObject> IPCProcessSkeleton::GetRegistryObject()
    {
        if (GetIPCSkeletonInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCSkeletonInterface()->GetRegistryObject();
    }
    bool IPCProcessSkeleton::SetRegistryObject(sptr<IRemoteObject> &object)
    {
        if (GetIPCSkeletonInterface() == nullptr) {
            return false;
        }
        return GetIPCSkeletonInterface()->SetRegistryObject(object);
    }
    bool IPCProcessSkeleton::SetMaxWorkThread(int maxThreadNum)
    {
        if (GetIPCSkeletonInterface() == nullptr) {
            return false;
        }
        return GetIPCSkeletonInterface()->SetMaxWorkThread(maxThreadNum);
    }
    IRemoteInvoker *IPCThreadSkeleton::GetDefaultInvoker()
    {
        if (GetIPCSkeletonInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCSkeletonInterface()->GetDefaultInvoker();
    }
    IRemoteInvoker *IPCThreadSkeleton::GetActiveInvoker()
    {
        if (GetIPCSkeletonInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCSkeletonInterface()->GetActiveInvoker();
    }
    IRemoteInvoker *IPCThreadSkeleton::GetProxyInvoker(IRemoteObject *object)
    {
        if (GetIPCSkeletonInterface() == nullptr) {
            return nullptr;
        }
        return GetIPCSkeletonInterface()->GetProxyInvoker(object);
    }
}

class IPCSkeletonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void IPCSkeletonTest::SetUpTestCase()
{
}

void IPCSkeletonTest::TearDownTestCase()
{
}

void IPCSkeletonTest::SetUp() const
{
}

void IPCSkeletonTest::TearDown() const
{
}

/**
 * @tc.name: SetContextObject001
 * @tc.desc: Verify the SetContextObject function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetContextObject001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    sptr<IRemoteObject> obj;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    bool ret = skeleton.SetContextObject(obj);
    EXPECT_FALSE(ret);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: SetContextObject002
 * @tc.desc: Verify the SetContextObject function when SetRegistryObject function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetContextObject002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    sptr<IRemoteObject> obj;
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, SetRegistryObject(testing::_)).WillRepeatedly(testing::Return(false));

    bool ret = skeleton.SetContextObject(obj);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetContextObject003
 * @tc.desc: Verify the SetContextObject function when SetRegistryObject function return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetContextObject003, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    sptr<IRemoteObject> obj;
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, SetRegistryObject(testing::_)).WillRepeatedly(testing::Return(true));

    bool ret = skeleton.SetContextObject(obj);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetContextObject001
 * @tc.desc: Verify the GetContextObject function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetContextObject001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    sptr<IRemoteObject> ret = skeleton.GetContextObject();
    EXPECT_EQ(ret, nullptr);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: GetContextObject002
 * @tc.desc: Verify the GetContextObject function when GetRegistryObject function return obj
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetContextObject002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    sptr<IRemoteObject> obj;
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, GetRegistryObject()).WillRepeatedly(testing::Return(obj));

    sptr<IRemoteObject> ret = skeleton.GetContextObject();
    EXPECT_EQ(ret, obj);
}

/**
 * @tc.name: GetContextObject003
 * @tc.desc: Verify the GetContextObject function when GetRegistryObject function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetContextObject003, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, GetRegistryObject()).WillRepeatedly(testing::Return(nullptr));

    sptr<IRemoteObject> ret = skeleton.GetContextObject();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: SetMaxWorkThreadNum001
 * @tc.desc: Verify the SetMaxWorkThreadNum function when GetCurrent function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetMaxWorkThreadNum001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    current->instance_ = nullptr;
    current->exitFlag_ = true;

    bool ret = skeleton.SetMaxWorkThreadNum(1);
    EXPECT_FALSE(ret);
    current->instance_ = nullptr;
    current->exitFlag_ = false;
}

/**
 * @tc.name: SetMaxWorkThreadNum002
 * @tc.desc: Verify the SetMaxWorkThreadNum function when SetMaxWorkThread function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetMaxWorkThreadNum002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, SetMaxWorkThread(testing::_)).WillRepeatedly(testing::Return(false));

    bool ret = skeleton.SetMaxWorkThreadNum(1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetMaxWorkThreadNum003
 * @tc.desc: Verify the SetMaxWorkThreadNum function when SetMaxWorkThread function return false
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, SetMaxWorkThreadNum003, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, SetMaxWorkThread(testing::_)).WillRepeatedly(testing::Return(true));

    bool ret = skeleton.SetMaxWorkThreadNum(1);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetSelfTokenID001
 * @tc.desc: Verify the GetSelfTokenID function when GetDefaultInvoker function return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetSelfTokenID001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(nullptr));

    uint64_t ret = skeleton.GetSelfTokenID();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetSelfTokenID002
 * @tc.desc: Verify the GetSelfTokenID function when GetSelfTokenID function return 1
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetSelfTokenID002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(*invoker, GetSelfTokenID()).WillRepeatedly(testing::Return(1));

    uint64_t ret = skeleton.GetSelfTokenID();
    EXPECT_EQ(ret, 1);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetFirstTokenID001
 * @tc.desc: Verify the GetFirstTokenID function return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstTokenID001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, GetActiveInvoker()).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(invoker));

    uint64_t ret = skeleton.GetFirstTokenID();
    EXPECT_EQ(ret, 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetFirstFullTokenID001
 * @tc.desc: Verify the GetFirstFullTokenID function return 0
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetFirstFullTokenID001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;

    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, GetActiveInvoker()).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(invoker));

    uint64_t ret = skeleton.GetFirstFullTokenID();
    EXPECT_EQ(ret, 0);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: FlushCommands001
 * @tc.desc: Verify the FlushCommands function return IPC_SKELETON_NULL_OBJECT_ERR
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, FlushCommands001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;
    IPCObjectProxy *object = new IPCObjectProxy(
        1, u"test", IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->proto_ = IRemoteObject::IF_PROT_BINDER;

    EXPECT_CALL(mock, GetProxyInvoker(testing::_)).WillRepeatedly(testing::Return(nullptr));

    int ret = skeleton.FlushCommands(object);
    EXPECT_EQ(ret, IPC_SKELETON_NULL_OBJECT_ERR);
    delete object;
}

/**
 * @tc.name: FlushCommandsTest002
 * @tc.desc: Verify the FlushCommands function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, FlushCommandsTest002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;

    EXPECT_CALL(mock, GetProxyInvoker(testing::_)).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(*invoker, GetStatus()).WillRepeatedly(testing::Return(IRemoteInvoker::ACTIVE_INVOKER));
    EXPECT_CALL(*invoker, FlushCommands(testing::_)).WillRepeatedly(testing::Return(RESULT_TEST));

    IPCObjectProxy *object = new IPCObjectProxy(HANDLE_TEST, DESCRIPTOR_TEST, IPCProcessSkeleton::DBINDER_HANDLE_BASE);
    object->proto_ = IRemoteObject::IF_PROT_BINDER;

    auto result = skeleton.FlushCommands(object);
    EXPECT_EQ(result, RESULT_TEST);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
    delete object;
}

/**
 * @tc.name: TriggerSystemIPCThreadReclaim001
 * @tc.desc: Verify the TriggerSystemIPCThreadReclaim function when GetDefaultInvoker function nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, TriggerSystemIPCThreadReclaim001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(nullptr));

    bool ret = skeleton.TriggerSystemIPCThreadReclaim();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TriggerThreadReclaim002
 * @tc.desc: Verify the TriggerSystemIPCThreadReclaim function when TriggerSystemIPCThreadReclaim function return true
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, TriggerThreadReclaim002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(*invoker, TriggerSystemIPCThreadReclaim()).WillRepeatedly(testing::Return(true));

    bool result = skeleton.TriggerSystemIPCThreadReclaim();
    EXPECT_TRUE(result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: EnableIPCThreadReclaim001
 * @tc.desc: Verify the EnableIPCThreadReclaim function when GetDefaultInvoker function nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, EnableIPCThreadReclaim001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;

    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(nullptr));

    bool ret = skeleton.EnableIPCThreadReclaim(true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EnableIPCThreadReclaim002
 * @tc.desc: Verify the EnableIPCThreadReclaim function when GetDefaultInvoker function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, EnableIPCThreadReclaim002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;
    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(*invoker, EnableIPCThreadReclaim(false)).WillRepeatedly(testing::Return(false));

    auto result = skeleton.EnableIPCThreadReclaim(false);
    EXPECT_FALSE(result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: EnableIPCThreadReclaim003
 * @tc.desc: Verify the EnableIPCThreadReclaim function when GetDefaultInvoker function return valid value
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, EnableIPCThreadReclaim003, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    NiceMock<IPCSkeletonInterfaceMock> mock;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;
    EXPECT_CALL(mock, GetDefaultInvoker()).WillRepeatedly(testing::Return(invoker));
    EXPECT_CALL(*invoker, EnableIPCThreadReclaim(true)).WillRepeatedly(testing::Return(true));

    auto result = skeleton.EnableIPCThreadReclaim(true);
    EXPECT_TRUE(result);
    std::fill(current->invokers_, current->invokers_ + IPCThreadSkeleton::INVOKER_MAX_COUNT, nullptr);
    delete invoker;
}

/**
 * @tc.name: GetThreadInvokationStateTest001
 * @tc.desc: cover GetThreadInvokationState branch
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetThreadInvocationStateTest001, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    BinderInvoker *invoker = new BinderInvoker();
    EXPECT_TRUE(invoker != nullptr);

    invoker->isFirstInvoke_ = STATUS_FIRST_INVOKE;
    invoker->status_ = IRemoteInvoker::ACTIVE_INVOKER;
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    EXPECT_TRUE(current != nullptr);

    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    EXPECT_EQ(skeleton.GetThreadInvocationState(), STATUS_FIRST_INVOKE);
    delete invoker;
}

/**
 * @tc.name: GetThreadInvokationStateTest002
 * @tc.desc: cover GetThreadInvokationState branch
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetThreadInvocationStateTest002, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    BinderInvoker *invoker = new BinderInvoker();
    EXPECT_TRUE(invoker != nullptr);

    invoker->status_ = IRemoteInvoker::ACTIVE_INVOKER;
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    EXPECT_TRUE(current != nullptr);

    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    EXPECT_EQ(skeleton.GetThreadInvocationState(), STATUS_INIT);
    delete invoker;
}

/**
 * @tc.name: GetThreadInvokationStateTest003
 * @tc.desc: cover GetThreadInvokationState branch
 * @tc.type: FUNC
 */
HWTEST_F(IPCSkeletonTest, GetThreadInvocationStateTest003, TestSize.Level1)
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    EXPECT_TRUE(current != nullptr);

    current->usingFlag_ = 0;
    EXPECT_EQ(skeleton.GetThreadInvocationState(), STATUS_UNKNOWN);
}

} // namespace OHOS
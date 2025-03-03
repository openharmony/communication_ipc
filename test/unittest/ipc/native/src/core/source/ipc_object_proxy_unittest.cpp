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
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "mock_iremote_invoker.h"
#include "mock_iremote_object.h"
#undef private

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

/**
 * @tc.name: GetInterfaceDescriptorTest001
 * @tc.desc: Test for the handle is 0(for samgr), and proxy do not need to get descriptor
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest001, TestSize.Level1)
{
    IPCObjectProxy object(0);
    auto ret = object.GetInterfaceDescriptor();
    ASSERT_EQ(ret.size(), 0);

    object.interfaceDesc_ = u"test";
    ret = object.GetInterfaceDescriptor();
    ASSERT_NE(ret.size(), 0);
}

/**
 * @tc.name: GetInterfaceDescriptorTest002
 * @tc.desc: Test for get descriptor
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest002, TestSize.Level1)
{
    IPCObjectProxy object(1);
    object.remoteDescriptor_ = "testDesc";
    // test for stub already died
    object.isRemoteDead_ = true;
    auto ret = object.GetInterfaceDescriptor();
    ASSERT_EQ(ret.size(), 0);

    object.isRemoteDead_ = false;
    object.proto_ = IRemoteObject::IF_PROT_BINDER;
    MockIRemoteInvoker *invoker = new MockIRemoteInvoker();
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_BINDER] = invoker;
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;
    // test for stub died
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_DEAD_OBJECT));
    ret = object.GetInterfaceDescriptor();
    ASSERT_EQ(ret.size(), 0);

    // test for succ
    object.isRemoteDead_ = false;
    EXPECT_CALL(*invoker, SendRequest(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_NONE));
    ret = object.GetInterfaceDescriptor();
    ASSERT_EQ(ret.size(), 0);
    delete invoker;
}
} // namespace OHOS
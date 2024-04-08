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
#include "dbinder_session_object.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "ipc_object_stub.h"
#include "ipc_thread_pool.h"
#include "stub_refcount_object.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

namespace {
}
class IPCThreadSkeletonUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IPCThreadSkeletonUnitTest::SetUpTestCase()
{
}

void IPCThreadSkeletonUnitTest::TearDownTestCase()
{
}

void IPCThreadSkeletonUnitTest::SetUp() {}

void IPCThreadSkeletonUnitTest::TearDown() {}

/**
 * @tc.name: GetRegistryObjectTest001
 * @tc.desc: Verify the GetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonUnitTest, GetRegistryObjectTest001, TestSize.Level1)
{
    IPCThreadSkeleton *skeleton = IPCThreadSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(1);

    IRemoteInvoker *object = skeleton->GetProxyInvoker(objectProxy.GetRefPtr());
    EXPECT_NE(object, nullptr);
}

/**
 * @tc.name: GetRegistryObjectTest002
 * @tc.desc: Verify the GetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonUnitTest, GetRegistryObjectTest002, TestSize.Level1)
{
    IPCThreadSkeleton *skeleton = IPCThreadSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    IRemoteInvoker *object = skeleton->GetProxyInvoker(nullptr);
    EXPECT_EQ(object, nullptr);
}

/**
 * @tc.name: GetRegistryObjectTest003
 * @tc.desc: Verify the GetRegistryObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCThreadSkeletonUnitTest, GetRegistryObjectTest003, TestSize.Level1)
{
    IPCThreadSkeleton *skeleton = IPCThreadSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IPCObjectStub> objectStub = new IPCObjectStub(u"testObject");

    IRemoteInvoker *object = skeleton->GetProxyInvoker(objectStub.GetRefPtr());
    EXPECT_EQ(object, nullptr);
}
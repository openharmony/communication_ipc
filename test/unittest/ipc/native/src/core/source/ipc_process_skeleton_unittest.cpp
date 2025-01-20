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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define private public
#include "dbinder_session_object.h"
#include "ipc_process_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "ipc_object_stub.h"
#include "ipc_thread_pool.h"
#include "ipc_thread_skeleton.h"
#include "stub_refcount_object.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

class IPCProcessSkeletonUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
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
 * @tc.name: IsContainsObjectTest001
 * @tc.desc: Verify the IsContainsObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, IsContainsObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);
    
    EXPECT_FALSE(skeleton->IsContainsObject(nullptr));
    delete skeleton;
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: AttachObjectTest001
 * @tc.desc: Verify the AttachObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    EXPECT_FALSE(skeleton->AttachObject(nullptr));
    delete skeleton;
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: AttachObjectTest002
 * @tc.desc: Verify the AttachObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, AttachObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    EXPECT_TRUE(skeleton->AttachObject(object, false));
    delete skeleton;
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: DetachObjectTest001
 * @tc.desc: Verify the DetachObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachObjectTest001, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(u"");
    EXPECT_FALSE(skeleton->DetachObject(object));
    delete skeleton;
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: DetachObjectTest002
 * @tc.desc: Verify the DetachObject function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, DetachObjectTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    EXPECT_FALSE(skeleton->DetachObject(nullptr));
    delete skeleton;
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: QueryAppInfoToStubIndexTest001
 * @tc.desc: Verify the QueryAppInfoToStubIndex function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, QueryAppInfoToStubIndexTest001, TestSize.Level1)
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
    bool ret = skeleton->QueryAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    EXPECT_TRUE(ret);

    skeleton->appInfoToStubIndex_.clear();
    std::map<uint64_t, int32_t> indexNewMap = {{ 0, listenFd }};
    skeleton->appInfoToStubIndex_[appInfo] = indexNewMap;
    ret = skeleton->QueryAppInfoToStubIndex(pid, uid, tokenId, deviceId, stubIndex, listenFd);
    EXPECT_FALSE(ret);
    delete skeleton;
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
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
    delete skeleton;
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: CreateSoftbusServerTest002
 * @tc.desc: Verify the CreateSoftbusServer function
 * @tc.type: FUNC
 */
HWTEST_F(IPCProcessSkeletonUnitTest, CreateSoftbusServerTest002, TestSize.Level1)
{
    IPCProcessSkeleton *skeleton = IPCProcessSkeleton::GetCurrent();
    ASSERT_TRUE(skeleton != nullptr);

    std::string name = "";
    auto ret = skeleton->CreateSoftbusServer(name);
    EXPECT_EQ(ret, false);
    delete skeleton;
    skeleton->instance_ = nullptr;
    skeleton->exitFlag_ = false;
}
}

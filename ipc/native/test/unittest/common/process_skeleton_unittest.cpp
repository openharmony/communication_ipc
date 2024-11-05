/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "process_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "ipc_object_stub.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

class ProcessSkeletonUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ProcessSkeletonUnitTest::SetUpTestCase()
{
}

void ProcessSkeletonUnitTest::TearDownTestCase()
{
}

void ProcessSkeletonUnitTest::SetUp() {}

void ProcessSkeletonUnitTest::TearDown() {}

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
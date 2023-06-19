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

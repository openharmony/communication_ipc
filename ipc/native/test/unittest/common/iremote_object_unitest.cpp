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
#include "ipc_object_proxy.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

class IRemoteObjectTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IRemoteObjectTest::SetUpTestCase()
{
}

void IRemoteObjectTest::TearDownTestCase()
{
}

void IRemoteObjectTest::SetUp()
{
}

void IRemoteObjectTest::TearDown()
{
}

/**
 * @tc.name: CheckObjectLegalityTest001
 * @tc.desc: Verify the IRemoteObject::CheckObjectLegality function
 * @tc.type: FUNC
 */
HWTEST_F(IRemoteObjectTest, CheckObjectLegalityTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    auto ret = object.CheckObjectLegality();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: IsObjectDeadTest001
 * @tc.desc: Verify the IRemoteObject::IsObjectDead function
 * @tc.type: FUNC
 */
HWTEST_F(IRemoteObjectTest, IsObjectDeadTest001, TestSize.Level1)
{
    sptr<IRemoteObject> object = new IPCObjectProxy(16);

    auto ret = object->IsObjectDead();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetInterfaceDescriptorTest001
 * @tc.desc: Verify the IRemoteObject::GetInterfaceDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IRemoteObjectTest, GetInterfaceDescriptorTest001, TestSize.Level1)
{
    sptr<IRemoteObject> object = new IPCObjectProxy(0);

    EXPECT_EQ(object->descriptor_, object->GetInterfaceDescriptor());
}

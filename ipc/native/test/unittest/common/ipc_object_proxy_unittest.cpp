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

#include "ipc_object_proxy.h"
#include "ipc_types.h"

using namespace testing::ext;
using namespace OHOS;

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
}

/**
 * @tc.name: GetPidAndUidInfoTest001
 * @tc.desc: Verify the IPCObjectProxy::GetPidAndUidInfo function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetPidAndUidInfoTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::string ret = object.GetPidAndUidInfo(1);
    EXPECT_NE(ret.size(), 0);
}

/**
 * @tc.name: GetDataBusNameTest001
 * @tc.desc: Verify the IPCObjectProxy::GetDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetDataBusNameTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::string ret = object.GetDataBusName(1);
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.name: TransDataBusNameTest001
 * @tc.desc: Verify the IPCObjectProxy::TransDataBusName function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, TransDataBusNameTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::string ret = object.TransDataBusName(1, 1);
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.name: GetInterfaceDescriptorTest001
 * @tc.desc: Verify the IPCObjectProxy::GetInterfaceDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(IPCObjectProxyTest, GetInterfaceDescriptorTest001, TestSize.Level1)
{
    IPCObjectProxy object(1);

    std::u16string ret = object.GetInterfaceDescriptor();
    EXPECT_NE(ret.size(), 0);
}
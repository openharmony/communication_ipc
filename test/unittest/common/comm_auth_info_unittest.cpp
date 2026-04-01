/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "comm_auth_info.h"
#include "ipc_object_stub.h"

using namespace testing::ext;

namespace OHOS {
class CommAuthInfoUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ConstructorTest001
 * @tc.desc: Verify default socketId is zero
 * @tc.type: FUNC
 */
HWTEST_F(CommAuthInfoUnitTest, ConstructorTest001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new IPCObjectStub(u"comm_auth_info");
    CommAuthInfo info(remoteObject.GetRefPtr(), 1, 2, 3, "deviceA");

    EXPECT_EQ(info.GetRemoteSocketId(), 0);
}

/**
 * @tc.name: GetStubObjectTest001
 * @tc.desc: Verify nullptr stub is preserved
 * @tc.type: FUNC
 */
HWTEST_F(CommAuthInfoUnitTest, GetStubObjectTest001, TestSize.Level1)
{
    CommAuthInfo info(nullptr, 1, 2, 3, "deviceA");

    EXPECT_EQ(info.GetStubObject(), nullptr);
}

/**
 * @tc.name: GetRemoteDeviceIdTest001
 * @tc.desc: Verify empty device id is preserved
 * @tc.type: FUNC
 */
HWTEST_F(CommAuthInfoUnitTest, GetRemoteDeviceIdTest001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new IPCObjectStub(u"comm_auth_info");
    CommAuthInfo info(remoteObject.GetRefPtr(), 1, 2, 3, "");

    EXPECT_TRUE(info.GetRemoteDeviceId().empty());
}

/**
 * @tc.name: GetRemoteTokenIdTest001
 * @tc.desc: Verify max token id is preserved
 * @tc.type: FUNC
 */
HWTEST_F(CommAuthInfoUnitTest, GetRemoteTokenIdTest001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new IPCObjectStub(u"comm_auth_info");
    CommAuthInfo info(remoteObject.GetRefPtr(), 1, 2, UINT32_MAX, "deviceA");

    EXPECT_EQ(info.GetRemoteTokenId(), UINT32_MAX);
}
} // namespace OHOS

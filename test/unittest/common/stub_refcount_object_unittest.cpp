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

#include "ipc_object_stub.h"
#include "stub_refcount_object.h"

using namespace testing::ext;

namespace OHOS {
class StubRefCountObjectUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: GetStubObjectTest001
 * @tc.desc: Verify GetStubObject returns the same stub pointer
 * @tc.type: FUNC
 */
HWTEST_F(StubRefCountObjectUnitTest, GetStubObjectTest001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new IPCObjectStub(u"stub_refcount_object");
    StubRefCountObject object(remoteObject.GetRefPtr(), 100, "deviceA");

    EXPECT_EQ(object.GetStubObject(), remoteObject.GetRefPtr());
}

/**
 * @tc.name: GetStubObjectTest002
 * @tc.desc: Verify GetStubObject keeps nullptr when constructed with nullptr
 * @tc.type: FUNC
 */
HWTEST_F(StubRefCountObjectUnitTest, GetStubObjectTest002, TestSize.Level1)
{
    StubRefCountObject object(nullptr, 100, "deviceA");

    EXPECT_EQ(object.GetStubObject(), nullptr);
}

/**
 * @tc.name: GetRemotePidTest001
 * @tc.desc: Verify GetRemotePid preserves negative values
 * @tc.type: FUNC
 */
HWTEST_F(StubRefCountObjectUnitTest, GetRemotePidTest001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new IPCObjectStub(u"stub_refcount_object");
    StubRefCountObject object(remoteObject.GetRefPtr(), -1, "deviceA");

    EXPECT_EQ(object.GetRemotePid(), -1);
}

/**
 * @tc.name: GetDeviceIdTest001
 * @tc.desc: Verify GetDeviceId preserves an empty device id
 * @tc.type: FUNC
 */
HWTEST_F(StubRefCountObjectUnitTest, GetDeviceIdTest001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new IPCObjectStub(u"stub_refcount_object");
    StubRefCountObject object(remoteObject.GetRefPtr(), 100, "");

    EXPECT_TRUE(object.GetDeviceId().empty());
}
} // namespace OHOS

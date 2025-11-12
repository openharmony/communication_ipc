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

#include "ipc_object_proxy.h"
#include "iremote_broker.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {
namespace {
    const std::u16string DESCRIPTOR_TEST = u"test_descriptor";
    const std::string SO_PATH_TEST = "test_so_path";
}

class IremoteBrokerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void IremoteBrokerTest::SetUpTestCase()
{
}

void IremoteBrokerTest::TearDownTestCase()
{
}

void IremoteBrokerTest::SetUp() const
{
}

void IremoteBrokerTest::TearDown() const
{
}

/**
 * @tc.name: RegisterTest001
 * @tc.desc: Verify the Register function when descriptor is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IremoteBrokerTest, RegisterTest001, TestSize.Level1)
{
    BrokerRegistration registration;
    auto creator = [](const sptr<IRemoteObject>& obj) {
        return sptr<IRemoteBroker>(nullptr);
    };
    BrokerDelegatorBase obj;
    std::u16string descriptor;

    bool result = registration.Register(descriptor, creator, &obj);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: RegisterTest002
 * @tc.desc: Verify the Register function when isUnloading is true
 * @tc.type: FUNC
 */
HWTEST_F(IremoteBrokerTest, RegisterTest002, TestSize.Level1)
{
    BrokerRegistration registration;
    registration.isUnloading = true;
    auto creator = [](const sptr<IRemoteObject> &obj)
    {
        return sptr<IRemoteBroker>(nullptr);
    };
    BrokerDelegatorBase obj;
    std::u16string descriptor = DESCRIPTOR_TEST;

    bool result = registration.Register(descriptor, creator, &obj);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: RegisterTest003
 * @tc.desc: Verify the Register function when isUnloading is false and descriptor is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IremoteBrokerTest, RegisterTest003, TestSize.Level1)
{
    BrokerRegistration registration;
    auto creator = [](const sptr<IRemoteObject> &obj)
    {
        return sptr<IRemoteBroker>(nullptr);
    };
    BrokerDelegatorBase obj;
    std::u16string descriptor = DESCRIPTOR_TEST;
    std::string soPath = SO_PATH_TEST;
    registration.creators_.clear();
    registration.GetObjectSoPath(reinterpret_cast<uintptr_t>(&obj));

    bool result = registration.Register(descriptor, creator, &obj);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: UnregisterTest001
 * @tc.desc: Verify the Unregister function when isUnloading is true
 * @tc.type: FUNC
 */
HWTEST_F(IremoteBrokerTest, UnregisterTest001, TestSize.Level1)
{
    BrokerRegistration registration;
    registration.isUnloading = true;
    std::u16string descriptor = DESCRIPTOR_TEST;

    ASSERT_NO_FATAL_FAILURE(registration.Unregister(descriptor));
}

/**
 * @tc.name: UnregisterTest002
 * @tc.desc: Verify the Unregister function when descriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(IremoteBrokerTest, UnregisterTest002, TestSize.Level1)
{
    BrokerRegistration registration;
    std::u16string descriptor;

    ASSERT_NO_FATAL_FAILURE(registration.Unregister(descriptor));
}

/**
 * @tc.name: GetObjectSoPathTest001
 * @tc.desc: Verify the GetObjectSoPath function when invalidPtr is 0 and dladdr function return failed
 * @tc.type: FUNC
 */
HWTEST_F(IremoteBrokerTest, GetObjectSoPathTest001, TestSize.Level1)
{
    BrokerRegistration registration;
    uintptr_t invalidPtr = 0;
    std::string result = registration.GetObjectSoPath(invalidPtr);
    EXPECT_TRUE(result.empty());
}
} // namespace OHOS
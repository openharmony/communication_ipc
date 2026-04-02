/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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
#define private public
#include "invoker_factory.h"
#undef private
#include "binder_invoker.h"
#include "iremote_invoker.h"

namespace OHOS {
using namespace testing::ext;
using namespace OHOS;

namespace {
constexpr int TEST_PROTOCOL_BASE = 10000;

class TestInvoker final : public BinderInvoker {
public:
    ~TestInvoker() override = default;
};

void ResetTestProtocol(InvokerFactory &invokerFactory, int protocol)
{
    invokerFactory.creators_.erase(protocol);
    invokerFactory.isAvailable_ = true;
}
} // namespace

class InvokerFactoryTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void InvokerFactoryTest::SetUp() {}

void InvokerFactoryTest::TearDown() {}

void InvokerFactoryTest::SetUpTestCase() {}

void InvokerFactoryTest::TearDownTestCase() {}

/**
 * @tc.name: Register001
 * @tc.desc: Register
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, Register001, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    invokerFactory.isAvailable_ = false;
    int protocol = 1;

    IRemoteInvoker* invoker = nullptr;
    auto creator = [&invoker]() -> IRemoteInvoker* {
        invoker = new (std::nothrow) BinderInvoker();
        if (invoker == nullptr) {
            return nullptr;
        }
        return invoker;
    };

    bool ret = invokerFactory.Register(protocol, creator);
    EXPECT_EQ(ret, false);
    if (invoker != nullptr) {
        delete invoker;
        invoker = nullptr;
    }
    invokerFactory.isAvailable_ = true;

    ret = invokerFactory.Register(protocol, creator);
    EXPECT_EQ(ret, false);
    IRemoteInvoker* iRemoteInvoker = invokerFactory.newInstance(protocol);
    EXPECT_NE(iRemoteInvoker, nullptr);
    if (invoker != nullptr) {
        delete invoker;
        invoker = nullptr;
    }
    // after leaving the scope, the captured 'invoker' object will be invalid in 'creator' lambda expression
    // so we need to delete 'creator' lambda expression
    invokerFactory.Unregister(protocol);
}

/**
 * @tc.name: Register002
 * @tc.desc: Register
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, Register002, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    invokerFactory.isAvailable_ = false;
    int protocol = 1;

    IRemoteInvoker* invoker = nullptr;
    auto creator = [&invoker]() -> IRemoteInvoker* {
        invoker = new (std::nothrow) BinderInvoker();
        if (invoker == nullptr) {
            return nullptr;
        }
        return invoker;
    };

    bool ret = invokerFactory.Register(protocol, creator);
    if (invoker != nullptr) {
        delete invoker;
        invoker = nullptr;
    }
    EXPECT_EQ(ret, false);
    // after leaving the scope, the captured 'invoker' object will be invalid in 'creator' lambda expression
    // so we need to delete 'creator' lambda expression
    invokerFactory.Unregister(protocol);
}

/**
 * @tc.name: Unregister001
 * @tc.desc: Unregister
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, Unregister001, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    invokerFactory.isAvailable_ = false;
    int protocol = 1;
    invokerFactory.Unregister(protocol);
    EXPECT_EQ(invokerFactory.isAvailable_, false);
}

/**
 * @tc.name: newInstance002
 * @tc.desc: Unregister
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, Unregister002, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    invokerFactory.isAvailable_ = true;
    int protocol = 1;
    invokerFactory.Unregister(protocol);
    EXPECT_EQ(invokerFactory.isAvailable_, true);
}

/**
 * @tc.name: newInstance002
 * @tc.desc: newInstance
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, newInstance002, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    invokerFactory.isAvailable_ = true;
    int protocol = 1;
    invokerFactory.newInstance(protocol);
    EXPECT_EQ(invokerFactory.isAvailable_, true);
}

/**
 * @tc.name: RegisterBranch001
 * @tc.desc: Verify duplicate register returns false and keeps original creator
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, RegisterBranch001, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    const int protocol = TEST_PROTOCOL_BASE + 1;
    ResetTestProtocol(invokerFactory, protocol);

    auto creator = []() -> IRemoteInvoker* {
        return new (std::nothrow) BinderInvoker();
    };
    auto duplicateCreator = []() -> IRemoteInvoker* {
        return nullptr;
    };

    EXPECT_TRUE(invokerFactory.Register(protocol, creator));
    EXPECT_FALSE(invokerFactory.Register(protocol, duplicateCreator));

    std::unique_ptr<IRemoteInvoker> invoker(invokerFactory.newInstance(protocol));
    EXPECT_NE(invoker, nullptr);
    invokerFactory.Unregister(protocol);
    ResetTestProtocol(invokerFactory, protocol);
}

/**
 * @tc.name: RegisterBranch002
 * @tc.desc: Verify nullptr creator path returns nullptr from newInstance
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, RegisterBranch002, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    const int protocol = TEST_PROTOCOL_BASE + 2;
    ResetTestProtocol(invokerFactory, protocol);

    EXPECT_TRUE(invokerFactory.Register(protocol, nullptr));
    EXPECT_EQ(invokerFactory.newInstance(protocol), nullptr);

    invokerFactory.Unregister(protocol);
    ResetTestProtocol(invokerFactory, protocol);
}

/**
 * @tc.name: UnregisterBranch001
 * @tc.desc: Verify unregister removes registered creator
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, UnregisterBranch001, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    const int protocol = TEST_PROTOCOL_BASE + 3;
    ResetTestProtocol(invokerFactory, protocol);

    auto creator = []() -> IRemoteInvoker* {
        return new (std::nothrow) BinderInvoker();
    };

    EXPECT_TRUE(invokerFactory.Register(protocol, creator));
    invokerFactory.Unregister(protocol);
    EXPECT_EQ(invokerFactory.newInstance(protocol), nullptr);
    ResetTestProtocol(invokerFactory, protocol);
}

/**
 * @tc.name: newInstanceBranch001
 * @tc.desc: Verify unavailable factory returns nullptr directly
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, newInstanceBranch001, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    const int protocol = TEST_PROTOCOL_BASE + 4;
    ResetTestProtocol(invokerFactory, protocol);

    invokerFactory.isAvailable_ = false;
    EXPECT_EQ(invokerFactory.newInstance(protocol), nullptr);
    invokerFactory.isAvailable_ = true;
    ResetTestProtocol(invokerFactory, protocol);
}

/**
 * @tc.name: UnregisterBranch002
 * @tc.desc: Verify unregistering one protocol does not affect other creators
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, UnregisterBranch002, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    const int firstProtocol = TEST_PROTOCOL_BASE + 5;
    const int secondProtocol = TEST_PROTOCOL_BASE + 6;
    ResetTestProtocol(invokerFactory, firstProtocol);
    ResetTestProtocol(invokerFactory, secondProtocol);

    auto creator = []() -> IRemoteInvoker* {
        return new (std::nothrow) BinderInvoker();
    };

    EXPECT_TRUE(invokerFactory.Register(firstProtocol, creator));
    EXPECT_TRUE(invokerFactory.Register(secondProtocol, creator));

    invokerFactory.Unregister(firstProtocol);
    EXPECT_EQ(invokerFactory.newInstance(firstProtocol), nullptr);

    std::unique_ptr<IRemoteInvoker> secondInvoker(invokerFactory.newInstance(secondProtocol));
    EXPECT_NE(secondInvoker, nullptr);

    invokerFactory.Unregister(secondProtocol);
    ResetTestProtocol(invokerFactory, firstProtocol);
    ResetTestProtocol(invokerFactory, secondProtocol);
}

/**
 * @tc.name: RegisterBranch003
 * @tc.desc: Verify the same protocol can be registered again after unregister
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, RegisterBranch003, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    const int protocol = TEST_PROTOCOL_BASE + 7;
    ResetTestProtocol(invokerFactory, protocol);

    auto creator = []() -> IRemoteInvoker* {
        return new (std::nothrow) BinderInvoker();
    };

    EXPECT_TRUE(invokerFactory.Register(protocol, creator));
    invokerFactory.Unregister(protocol);
    EXPECT_TRUE(invokerFactory.Register(protocol, creator));

    std::unique_ptr<IRemoteInvoker> invoker(invokerFactory.newInstance(protocol));
    EXPECT_NE(invoker, nullptr);

    invokerFactory.Unregister(protocol);
    ResetTestProtocol(invokerFactory, protocol);
}

/**
 * @tc.name: InvokerDelegatorBranch001
 * @tc.desc: Verify InvokerDelegator registers a creator for the target protocol
 * @tc.type: FUNC
 */
HWTEST_F(InvokerFactoryTest, InvokerDelegatorBranch001, TestSize.Level1)
{
    InvokerFactory &invokerFactory = InvokerFactory::Get();
    const int protocol = TEST_PROTOCOL_BASE + 8;
    ResetTestProtocol(invokerFactory, protocol);

    {
        InvokerDelegator<TestInvoker> delegator(protocol);
        std::unique_ptr<IRemoteInvoker> invoker(invokerFactory.newInstance(protocol));
        EXPECT_NE(invoker, nullptr);
    }

    invokerFactory.Unregister(protocol);
    ResetTestProtocol(invokerFactory, protocol);
}

} // namespace OHOS

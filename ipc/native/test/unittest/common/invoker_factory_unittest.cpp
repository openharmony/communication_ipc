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

class InvokerFactoryTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
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

} // namespace OHOS

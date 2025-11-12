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

#include <algorithm>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ipc_inner_object.h"
#include "ipc_object_proxy.h"
#include "iremote_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

namespace {
    const std::u16string DESCRIPTOR_TEST = u"test_descriptor";
}

class IPCInnerObjectTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void IPCInnerObjectTest::SetUpTestCase()
{
}

void IPCInnerObjectTest::TearDownTestCase()
{
}

void IPCInnerObjectTest::SetUp() const
{
}

void IPCInnerObjectTest::TearDown() const
{
}

/**
 * @tc.name: CreateIPCRemoteProxyTest001
 * @tc.desc: Verify the CreateIPCRemoteProxy function when remote is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCInnerObjectTest, CreateIPCRemoteProxyTest001, TestSize.Level1) {
    sptr<IRemoteObject> nullRemote = nullptr;
    OHIPCRemoteProxy* nullProxy = CreateIPCRemoteProxy(nullRemote);
    EXPECT_EQ(nullProxy, nullptr);
}

/**
 * @tc.name: CreateIPCRemoteProxyTest002
 * @tc.desc: Verify the CreateIPCRemoteProxy function when remote is valid value
 * @tc.type: FUNC
 */
HWTEST_F(IPCInnerObjectTest, CreateIPCRemoteProxyTest002, TestSize.Level1) {
    sptr<IRemoteObject> remote = new (std::nothrow) IPCObjectProxy(1, DESCRIPTOR_TEST);

    OHIPCRemoteProxy* proxy = CreateIPCRemoteProxy(remote);
    EXPECT_NE(proxy, nullptr);
    EXPECT_EQ(proxy->remote, remote);
    if (proxy != nullptr) {
        delete proxy;
    }
}
} // namespace OHOS
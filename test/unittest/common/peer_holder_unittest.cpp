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

#define private public
#include "peer_holder.h"
#undef private

#include "ipc_object_stub.h"

using namespace testing::ext;

namespace OHOS {
namespace {
class TestPeerHolder : public PeerHolder {
public:
    explicit TestPeerHolder(const sptr<IRemoteObject> &object) : PeerHolder(object) {}
    using PeerHolder::Remote;
};
} // namespace

class PeerHolderUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: RemoteTest001
 * @tc.desc: Verify Remote returns the held object for a valid holder
 * @tc.type: FUNC
 */
HWTEST_F(PeerHolderUnitTest, RemoteTest001, TestSize.Level1)
{
    sptr<IRemoteObject> object = new IPCObjectStub(u"peer_holder_stub");
    TestPeerHolder holder(object);

    EXPECT_EQ(holder.Remote(), object);
}

/**
 * @tc.name: RemoteTest002
 * @tc.desc: Verify Remote returns nullptr when holder is created with nullptr
 * @tc.type: FUNC
 */
HWTEST_F(PeerHolderUnitTest, RemoteTest002, TestSize.Level1)
{
    TestPeerHolder holder(nullptr);

    EXPECT_EQ(holder.Remote(), nullptr);
}

/**
 * @tc.name: RemoteTest003
 * @tc.desc: Verify Remote rejects holders with an invalid before magic
 * @tc.type: FUNC
 */
HWTEST_F(PeerHolderUnitTest, RemoteTest003, TestSize.Level1)
{
    sptr<IRemoteObject> object = new IPCObjectStub(u"peer_holder_stub");
    TestPeerHolder holder(object);

    holder.beforeMagic_ = 0;
    EXPECT_EQ(holder.Remote(), nullptr);
}

/**
 * @tc.name: RemoteTest004
 * @tc.desc: Verify Remote rejects holders with an invalid after magic
 * @tc.type: FUNC
 */
HWTEST_F(PeerHolderUnitTest, RemoteTest004, TestSize.Level1)
{
    sptr<IRemoteObject> object = new IPCObjectStub(u"peer_holder_stub");
    TestPeerHolder holder(object);

    holder.afterMagic_ = 0;
    EXPECT_EQ(holder.Remote(), nullptr);
}
} // namespace OHOS

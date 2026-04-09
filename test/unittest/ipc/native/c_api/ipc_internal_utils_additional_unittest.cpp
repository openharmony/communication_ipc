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

#include <gtest/gtest.h>

#define private public
#include "ipc_inner_object.h"
#include "ipc_internal_utils.h"
#include "ipc_object_stub.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class IPCInternalUtilsAdditionalTest : public testing::Test {
};

static void *AdditionalMemAllocator(int32_t len)
{
    return len > 0 ? malloc(len) : nullptr;
}

/**
 * @tc.name: IsIPCParcelValidTest003
 * @tc.desc: Verify IsIPCParcelValid returns false when msgParcel is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsAdditionalTest, IsIPCParcelValidTest003, TestSize.Level1)
{
    OHIPCParcel parcel {};
    parcel.msgParcel = nullptr;
    EXPECT_FALSE(IsIPCParcelValid(&parcel, "NullMsgParcelTest"));
}

/**
 * @tc.name: IsIPCRemoteProxyValidTest003
 * @tc.desc: Verify IsIPCRemoteProxyValid returns true when remote proxy is valid
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsAdditionalTest, IsIPCRemoteProxyValidTest003, TestSize.Level1)
{
    sptr<IRemoteObject> remote(new IPCObjectStub(u"test"));
    OHIPCRemoteProxy proxy {};
    proxy.remote = remote;
    EXPECT_TRUE(IsIPCRemoteProxyValid(&proxy, "ValidRemoteProxyTest"));
}

/**
 * @tc.name: IsMemoryParamsValidTest003
 * @tc.desc: Verify IsMemoryParamsValid returns false when str is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsAdditionalTest, IsMemoryParamsValidTest003, TestSize.Level1)
{
    int32_t len = 1;
    EXPECT_FALSE(IsMemoryParamsValid(nullptr, &len, AdditionalMemAllocator, "NullStrPtrAddrTest"));
}

/**
 * @tc.name: IsMemoryParamsValidTest004
 * @tc.desc: Verify IsMemoryParamsValid returns false when len is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsAdditionalTest, IsMemoryParamsValidTest004, TestSize.Level1)
{
    char *str = nullptr;
    EXPECT_FALSE(IsMemoryParamsValid(&str, nullptr, AdditionalMemAllocator, "NullLenPtrAddrTest"));
}

/**
 * @tc.name: IsMemoryParamsValidTest005
 * @tc.desc: Verify IsMemoryParamsValid returns false when allocator is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsAdditionalTest, IsMemoryParamsValidTest005, TestSize.Level1)
{
    char *str = nullptr;
    int32_t len = 1;
    EXPECT_FALSE(IsMemoryParamsValid(&str, &len, nullptr, "NullAllocatorTest"));
}
} // namespace OHOS

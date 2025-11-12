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

#include <cstring>
#include <securec.h>

#define private public
#include "ipc_inner_object.h"
#include "ipc_internal_utils.h"
#undef private

static constexpr int MAX_MEMORY_SIZE = 204800;

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {
    
class IPCInternalUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void IPCInternalUtilsTest::SetUpTestCase()
{
}

void IPCInternalUtilsTest::TearDownTestCase()
{
}

void IPCInternalUtilsTest::SetUp() const
{
}

void IPCInternalUtilsTest::TearDown() const
{
}

static void* TestMemAllocator(int32_t len)
{
    if (len <= 0 || len > MAX_MEMORY_SIZE) {
        return nullptr;
    }
    void *buffer = malloc(len);
    if (buffer != nullptr) {
        if (memset_s(buffer, len, 0, len) != EOK) {
            free(buffer);
            return nullptr;
        }
    }
    return buffer;
}

/**
 * @tc.name:IsIPCParcelValidTest001
 * @tc.desc: Verify the IsIPCParcelValid function when parcel nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsTest, IsIPCParcelValidTest001, TestSize.Level1)
{
    OHIPCParcel* parcel = nullptr;
    bool result = IsIPCParcelValid(parcel, "NullParcelTest");
    EXPECT_FALSE(result);
}

/**
 * @tc.name:IsIPCParcelValidTest002
 * @tc.desc: Verify the IsIPCParcelValid function when parcel valid
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsTest, IsIPCParcelValidTest002, TestSize.Level1)
{
    OHIPCParcel parcel;
    parcel.msgParcel = new MessageParcel();
    bool result = IsIPCParcelValid(&parcel, "ValidParcelTest");
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsIPCRemoteProxyValidTest001
 * @tc.desc: Verify the IsIPCRemoteProxyValid function when proxy nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsTest, IsIPCRemoteProxyValidTest001, TestSize.Level1)
{
    OHIPCRemoteProxy* proxy = nullptr;
    const char *promot = "NullProxyTest";
    EXPECT_FALSE(IsIPCRemoteProxyValid(proxy, promot));
}

/**
 * @tc.name: IsIPCRemoteProxyValidTest002
 * @tc.desc: Verify the IsIPCRemoteProxyValid function when proxy valid
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsTest, IsIPCRemoteProxyValidTest002, TestSize.Level1)
{
    OHIPCRemoteProxy proxy;
    proxy.remote = nullptr;
    const char *promot = "NullRemoteTest";
    EXPECT_FALSE(IsIPCRemoteProxyValid(&proxy, promot));
}

/**
 * @tc.name: IsMemoryParamsValidTest001
 * @tc.desc: Verify the IsMemoryParamsValid function Str pointer address is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsTest, IsMemoryParamsValidTest001, TestSize.Level1)
{
    char* str = nullptr;
    int32_t len = 0;
    const char *promot = "NullStrTest";
    EXPECT_FALSE(IsMemoryParamsValid(&str, &len, nullptr, promot));
}

/**
 * @tc.name: IsMemoryParamsValidTest002
 * @tc.desc: Verify the IsMemoryParamsValid function Str pointer address is valid
 * @tc.type: FUNC
 */
HWTEST_F(IPCInternalUtilsTest, IsMemoryParamsValidTest002, TestSize.Level1)
{
    char* str = nullptr;
    int32_t len = 0;
    const char *promot = "NullStrTest";
    EXPECT_TRUE(IsMemoryParamsValid(&str, &len, TestMemAllocator, promot));
}
} // namespace OHOS
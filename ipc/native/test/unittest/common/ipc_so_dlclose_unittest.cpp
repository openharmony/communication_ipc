/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include <dlfcn.h>

using namespace testing::ext;

class IpcSoDlcloseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void IpcSoDlcloseTest::SetUpTestCase()
{
}

void IpcSoDlcloseTest::TearDownTestCase()
{
}

void IpcSoDlcloseTest::SetUp()
{
}

void IpcSoDlcloseTest::TearDown()
{
}

/**
 * @tc.name: SingleSoDlcloseTest001
 * @tc.desc: test if ipc_core.so ipc_single.so dlclose normal
 * @tc.type: FUNC
 */
HWTEST_F(IpcSoDlcloseTest, SingleSoDlcloseTest001, TestSize.Level1)
{
    std::string path = std::string("libipc_single.z.so");
    for (int i = 0; i < 100; i++) {
        void *handle = dlopen(path.c_str(), RTLD_NOW);
        EXPECT_NE(handle, nullptr);
        int ret = dlclose(handle);
        handle = nullptr;
        EXPECT_EQ(ret, 0);
    }
}

/**
 * @tc.name: CoreSoDlcloseTest001
 * @tc.desc: test if ipc_core.so ipc_single.so dlclose normal
 * @tc.type: FUNC
 */
HWTEST_F(IpcSoDlcloseTest, CoreSoDlcloseTest001, TestSize.Level1)
{
    std::string path = std::string("libipc_core.z.so");
    for (int i = 0; i < 100; i++) {
        void *handle = dlopen(path.c_str(), RTLD_NOW);
        EXPECT_NE(handle, nullptr);
        int ret = dlclose(handle);
        handle = nullptr;
        EXPECT_EQ(ret, 0);
    }
}
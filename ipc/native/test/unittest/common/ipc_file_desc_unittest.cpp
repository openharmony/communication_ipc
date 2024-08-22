/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <gtest/gtest.h>

#define private public
#include "binder_invoker.h"
#include "ipc_debug.h"
#include "ipc_file_descriptor.h"
#include "log_tags.h"
#include "ipc_thread_skeleton.h"
#undef private

namespace OHOS {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;

class IPCFileDescOpsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "IPCFdTest" };
};

void IPCFileDescOpsTest::SetUp() {}

void IPCFileDescOpsTest::TearDown() {}

void IPCFileDescOpsTest::SetUpTestCase() {}

void IPCFileDescOpsTest::TearDownTestCase() {}

HWTEST_F(IPCFileDescOpsTest, fd_parcelable_001, TestSize.Level1)
{
    int testFdNum;
    testFdNum = open("/data/fd_unit_test.txt", O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);

    if (testFdNum == -1) {
        ZLOGD(LABEL, "%s(%d):open failed.", __func__, __LINE__);
    }
    ASSERT_TRUE(testFdNum >= 0);

    Parcel parcel(nullptr);
    sptr<IPCFileDescriptor> wdesc = new IPCFileDescriptor(testFdNum);
    bool result = false;

    result = parcel.WriteObject<IPCFileDescriptor>(wdesc);
    EXPECT_EQ(true, result);

    sptr<IPCFileDescriptor> rdesc = parcel.ReadObject<IPCFileDescriptor>();
    ASSERT_TRUE(rdesc != nullptr);
    EXPECT_EQ(testFdNum, rdesc->GetFd());
    close(testFdNum);
}

HWTEST_F(IPCFileDescOpsTest, fd_parcelable_002, TestSize.Level1)
{
    int invalidFdNum = -2;
    Parcel parcel(nullptr);
    sptr<IPCFileDescriptor> wdesc = new IPCFileDescriptor(invalidFdNum);
    bool result = false;
    result = parcel.WriteObject<IPCFileDescriptor>(wdesc);
    EXPECT_EQ(false, result);

    IPCFileDescriptor *rdesc = parcel.ReadObject<IPCFileDescriptor>();
    EXPECT_EQ(nullptr, rdesc);
}

HWTEST_F(IPCFileDescOpsTest, fd_parcelable_003, TestSize.Level1)
{
    int fd = 9876;
    IPCFileDescriptor fdesc;

    fdesc.SetFd(fd);
    EXPECT_EQ(fd, fdesc.GetFd());
}

HWTEST_F(IPCFileDescOpsTest, Marshalling001, TestSize.Level1)
{
    int fd = 9876;
    IPCFileDescriptor fdesc;

    fdesc.SetFd(fd);
    BinderInvoker *invoker = nullptr;
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    Parcel parcel;
    auto ret = fdesc.Marshalling(parcel);
    ASSERT_TRUE(ret);
}

HWTEST_F(IPCFileDescOpsTest, Unmarshalling001, TestSize.Level1)
{
    int fd = 9876;
    IPCFileDescriptor fdesc;

    fdesc.SetFd(fd);
    BinderInvoker *invoker = nullptr;
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    Parcel parcel;
    auto ret = fdesc.Unmarshalling(parcel);
    ASSERT_TRUE(ret == nullptr);
}

HWTEST_F(IPCFileDescOpsTest, Unmarshalling002, TestSize.Level1)
{
    int fd = 9876;
    IPCFileDescriptor fdesc;
    Parcel parcel;

    fdesc.SetFd(fd);
    BinderInvoker *invoker = new BinderInvoker();
    invoker->WriteFileDescriptor(parcel, fd, true);
    IPCThreadSkeleton *current = IPCThreadSkeleton::GetCurrent();
    current->invokers_[IRemoteObject::IF_PROT_DEFAULT] = invoker;

    auto ret = fdesc.Unmarshalling(parcel);
    ASSERT_TRUE(ret != nullptr);
}
} // namespace OHOS

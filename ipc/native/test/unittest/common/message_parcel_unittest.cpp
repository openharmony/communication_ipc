/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#define private public
#include "buffer_object.h"
#include "dbinder_session_object.h"
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "message_option.h"
#include "message_parcel.h"
#undef private

using namespace testing::ext;
using namespace OHOS;

namespace {
constexpr int INVALID_LEN = 9999;
}

class MessageParcelTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MessageParcelTest::SetUpTestCase()
{
}

void MessageParcelTest::TearDownTestCase()
{
}

void MessageParcelTest::SetUp()
{
}

void MessageParcelTest::TearDown()
{
}

/**
 * @tc.name: SyncTransaction010
 * @tc.desc: Test write and read exception.
 * @tc.type: FUNC
 * @tc.require: AR000E1QEG
 */
HWTEST_F(MessageParcelTest, SyncTransaction010, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteNoException();
    ASSERT_EQ(parcel.ReadException(), 0);
}

/**
 * @tc.name: GetRawDataCapacityTest001
 * @tc.desc: Verify the GetRawDataCapacity function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, GetRawDataCapacityTest001, TestSize.Level1)
{
    MessageParcel parcel;
    size_t ret = parcel.GetRawDataCapacity();
    EXPECT_EQ(ret, MAX_RAWDATA_SIZE);
}

/**
 * @tc.name: GetRawDataCapacityTest002
 * @tc.desc: Verify the GetRawDataCapacity function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, GetRawDataCapacityTest002, TestSize.Level1)
{
    MessageParcel data;
    uint8_t bytes[8] = {0};
    data.WriteBuffer(bytes, 8);
    MessageParcel parcel;
    bool ret = parcel.Append(data);
    EXPECT_EQ(ret, true);
}

#ifndef CONFIG_IPC_SINGLE
/**
 * @tc.name: WriteDBinderProxyTest001
 * @tc.desc: Verify the MessageParcel::WriteDBinderProxy function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteDBinderProxyTest001, TestSize.Level1)
{
    MessageParcel parcel;
    uint32_t handle = 1;
    uint64_t stubIndex = 1;
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>("name", "deviceId", 1, nullptr, 1);
    current->proxyToSession_[handle] = dbinderSessionObject;
    auto ret = parcel.WriteDBinderProxy(object, handle, stubIndex);
    EXPECT_EQ(ret, true);
    current->proxyToSession_.erase(handle);
}

/**
 * @tc.name: WriteDBinderProxyTest002
 * @tc.desc: Verify the MessageParcel::WriteDBinderProxy function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteDBinderProxyTest002, TestSize.Level1)
{
    MessageParcel parcel;
    sptr<IRemoteObject> object = new IPCObjectStub(u"testObject");
    uint32_t handle = 1;
    uint64_t stubIndex = 1;

    auto ret = parcel.WriteDBinderProxy(object, handle, stubIndex);
    EXPECT_EQ(ret, false);
}


/**
 * @tc.name: WriteRemoteObjectTest001
 * @tc.desc: Verify the MessageParcel::WriteRemoteObject function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRemoteObjectTest001, TestSize.Level1)
{
    MessageParcel parcel;
    uint32_t handle = IPCProcessSkeleton::DBINDER_HANDLE_BASE + 1;
    sptr<IPCObjectProxy> objectProxy = new IPCObjectProxy(handle, u"test");

    auto ret = parcel.WriteRemoteObject(objectProxy);
    EXPECT_EQ(ret, false);
}
#endif

/**
 * @tc.name: WriteFileDescriptorTest001
 * @tc.desc: Verify the MessageParcel::WriteFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteFileDescriptorTest001, TestSize.Level1)
{
    MessageParcel parcel;
    int fd = 1;
    auto ret = parcel.WriteFileDescriptor(fd);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: WriteFileDescriptorTest002
 * @tc.desc: Verify the MessageParcel::WriteFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteFileDescriptorTest002, TestSize.Level1)
{
    MessageParcel parcel;
    int fd = -1;
    auto ret = parcel.WriteFileDescriptor(fd);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ClearFileDescriptorTest001
 * @tc.desc: Verify the MessageParcel::ClearFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ClearFileDescriptorTest001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.ClearFileDescriptor();
    ASSERT_TRUE(parcel.rawDataSize_ == 0);
}

/**
 * @tc.name: ContainFileDescriptorsTest001
 * @tc.desc: Verify the MessageParcel::ContainFileDescriptors function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ContainFileDescriptorsTest001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.ContainFileDescriptors();
    ASSERT_TRUE(parcel.rawDataSize_ == 0);
}

/**
 * @tc.name: RestoreRawDataTest001
 * @tc.desc: Verify the MessageParcel::RestoreRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, RestoreRawDataTest001, TestSize.Level1)
{
    MessageParcel parcel;
    std::shared_ptr<char> rawData = std::make_shared<char>();
    size_t size = 1;

    parcel.rawData_= nullptr;
    auto ret = parcel.RestoreRawData(nullptr, size);
    ASSERT_FALSE(ret);

    ret = parcel.RestoreRawData(rawData, size);
    ASSERT_TRUE(ret);

    ret = parcel.RestoreRawData(nullptr, size);
    ASSERT_FALSE(ret);

    parcel.rawData_= rawData;
    ret = parcel.RestoreRawData(rawData, size);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ReadRawDataTest001
 * @tc.desc: Verify the MessageParcel::ReadRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadRawDataTest001, TestSize.Level1)
{
    MessageParcel parcel;
    auto ret = parcel.ReadRawData(INVALID_LEN);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: ReadRawDataTest002
 * @tc.desc: Verify the MessageParcel::ReadRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadRawDataTest002, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(MessageParcel::MIN_RAWDATA_SIZE);
    auto ret = parcel.ReadRawData(1);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: ReadRawDataTest003
 * @tc.desc: Verify the MessageParcel::ReadRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadRawDataTest003, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(MessageParcel::MIN_RAWDATA_SIZE + 1);
    auto ret = parcel.ReadRawData(MessageParcel::MIN_RAWDATA_SIZE + 1);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: ReadRawDataTest004
 * @tc.desc: Verify the MessageParcel::ReadRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadRawDataTest004, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(MessageParcel::MIN_RAWDATA_SIZE + 1);
    parcel.rawData_ = std::make_shared<char>(1);
    parcel.rawDataSize_ = 1;
    parcel.writeRawDataFd_ = 0;
    auto ret = parcel.ReadRawData(1);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: ReadRawDataTest005
 * @tc.desc: Verify the MessageParcel::ReadRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadRawDataTest005, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(MessageParcel::MIN_RAWDATA_SIZE + 1);
    parcel.rawData_ = std::make_shared<char>(1);
    parcel.rawDataSize_ = 1;
    parcel.writeRawDataFd_ = -1;
    auto ret = parcel.ReadRawData(1);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: ReadRawDataTest006
 * @tc.desc: Verify the MessageParcel::ReadRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadRawDataTest006, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(MessageParcel::MIN_RAWDATA_SIZE + 1);
    parcel.rawData_ = nullptr;
    parcel.rawDataSize_ = 0;
    parcel.writeRawDataFd_ = -1;
    auto ret = parcel.ReadRawData(1);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: ReadRawDataTest007
 * @tc.desc: Verify the MessageParcel::ReadRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadRawDataTest007, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(MessageParcel::MIN_RAWDATA_SIZE + 1);
    parcel.rawDataSize_ = 0;
    parcel.writeRawDataFd_ = 0;
    parcel.rawData_ = std::make_shared<char>(MessageParcel::MIN_RAWDATA_SIZE + 1);
    auto ret = parcel.ReadRawData(MessageParcel::MIN_RAWDATA_SIZE + 1);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: ReadRawDataTest008
 * @tc.desc: Verify the MessageParcel::ReadRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadRawDataTest008, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(MessageParcel::MIN_RAWDATA_SIZE + 1);
    parcel.rawData_ = std::make_shared<char>(MessageParcel::MIN_RAWDATA_SIZE + 1);
    parcel.writeRawDataFd_ = 0;
    auto ret = parcel.ReadRawData(MessageParcel::MIN_RAWDATA_SIZE);
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: GetRawDataTest001
 * @tc.desc: Verify the MessageParcel::GetRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, GetRawDataTest001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.rawData_ = std::make_shared<char>(1);
    auto ret = parcel.GetRawData();
    ASSERT_TRUE(ret != nullptr);
}

/**
 * @tc.name: GetRawDataTest002
 * @tc.desc: Verify the MessageParcel::GetRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, GetRawDataTest002, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.rawData_ = nullptr;
    auto ret = parcel.GetRawData();
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: GetRawDataTest003
 * @tc.desc: Verify the MessageParcel::GetRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, GetRawDataTest003, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.rawData_ = nullptr;
    int tmp = 1;
    void *ptr = &tmp;
    parcel.kernelMappedWrite_ = ptr;

    auto ret = parcel.GetRawData();
    ASSERT_TRUE(ret != nullptr);
}

/**
 * @tc.name: GetRawDataTest004
 * @tc.desc: Verify the MessageParcel::GetRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, GetRawDataTest004, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.rawData_ = nullptr;
    parcel.kernelMappedWrite_ = nullptr;
    int tmp = 1;
    void *ptr = &tmp;
    parcel.kernelMappedRead_ = ptr;
    auto ret = parcel.GetRawData();
    ASSERT_TRUE(ret != nullptr);
}

/**
 * @tc.name: WriteAshmemTest001
 * @tc.desc: Verify the MessageParcel::WriteAshmem function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteAshmemTest001, TestSize.Level1)
{
    MessageParcel parcel;
    std::string name = "ashmem1";
    sptr<Ashmem> ashmem =
        Ashmem::CreateAshmem(name.c_str(), 1);
    ASSERT_TRUE(ashmem != nullptr);

    auto ret = parcel.WriteAshmem(ashmem);
    ASSERT_TRUE(ret == true);
    ashmem->CloseAshmem();
}

/**
 * @tc.name: ReadAshmemTest001
 * @tc.desc: Verify the MessageParcel::ReadAshmem function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, ReadAshmemTest001, TestSize.Level1)
{
    MessageParcel parcel;

    auto ret = parcel.ReadAshmem();
    ASSERT_TRUE(ret == nullptr);
}

/**
 * @tc.name: AppendTest001
 * @tc.desc: Verify the MessageParcel::Append function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AppendTest001, TestSize.Level1)
{
    MessageParcel parcel;
    MessageParcel data;
    auto ret = parcel.Append(data);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: WriteRawDataTest001
 * @tc.desc: Verify the MessageParcel::WriteRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest001, TestSize.Level1)
{
    MessageParcel parcel;
    char data[1] = { 0 };
    auto ret = parcel.WriteRawData(data, 1);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: WriteRawDataTest002
 * @tc.desc: Verify the MessageParcel::WriteRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest002, TestSize.Level1)
{
    MessageParcel parcel;
    auto ret = parcel.WriteRawData(nullptr, 1);
    ASSERT_TRUE(!ret);
}

/**
 * @tc.name: WriteRawDataTest003
 * @tc.desc: Verify the MessageParcel::WriteRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest003, TestSize.Level1)
{
    MessageParcel parcel;
    char data[1] = { 0 };
    auto ret = parcel.WriteRawData(data, MAX_RAWDATA_SIZE + 1);
    ASSERT_TRUE(!ret);
}

/**
 * @tc.name: WriteRawDataTest004
 * @tc.desc: Verify the MessageParcel::WriteRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest004, TestSize.Level1)
{
    MessageParcel parcel;
    char data[MessageParcel::MIN_RAWDATA_SIZE + 1] = { 0 };
    auto ret = parcel.WriteRawData(data, MessageParcel::MIN_RAWDATA_SIZE + 1);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: WriteRawDataTest005
 * @tc.desc: Verify the MessageParcel::WriteRawData function
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest005, TestSize.Level1)
{
    MessageParcel parcel;
    char data[1] = { 0 };
    parcel.kernelMappedWrite_ = data;
    auto ret = parcel.WriteRawData(data, 1);
    ASSERT_TRUE(!ret);
}


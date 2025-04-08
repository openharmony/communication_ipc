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
#include <gmock/gmock.h>

#include "buffer_object.h"
#include "dbinder_session_object.h"
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "message_option.h"
#include "message_parcel.h"
#include "mock_ipc_process_skeleton.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
namespace OHOS {

namespace {
const std::string NAME_TEST = "name";
const std::string DEVICE_TEST = "deviceId";
const std::string LOCAL_TEST = "localId";
constexpr uint8_t NUMBER_TEST = 1;
constexpr uint8_t BNUMBER_TEST = 8;
constexpr uint32_t HANDLE_TEST = 1;
constexpr uint64_t STUBINDEX_TEST = 1;
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
class MessageParcelInterface {
public:
    MessageParcelInterface() {};
    virtual ~MessageParcelInterface() {};
    virtual bool WriteInt32(int32_t value) = 0;
};

class MessageParcelInterfaceMock : public MessageParcelInterface {
public:
    MessageParcelInterfaceMock();
    ~MessageParcelInterfaceMock() override;
    MOCK_METHOD1(WriteInt32, bool(int32_t value));
};

static void *g_interface = nullptr;

MessageParcelInterfaceMock::MessageParcelInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

MessageParcelInterfaceMock::~MessageParcelInterfaceMock()
{
    g_interface = nullptr;
}

static MessageParcelInterface *GetMessageParcelInterface()
{
    return reinterpret_cast<MessageParcelInterface *>(g_interface);
}
extern "C" {
    bool Parcel::WriteInt32(int32_t value)
    {
        MessageParcelInterface* interface = GetMessageParcelInterface();
        if (interface == nullptr) {
        return false;
        }
        return interface->WriteInt32(value);
    }
}

/**
 * @tc.name: WriteDBinderProxyTest001
 * @tc.desc: Verify the MessageParcel::WriteDBinderProxy function return false
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteDBinderProxyTest001, TestSize.Level1)
{
    MessageParcel parcel;
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

    sptr<IRemoteObject> object = new IPCObjectStub();
    EXPECT_CALL(*instance, GetCurrent())
        .WillRepeatedly(testing::Return(nullptr));
    auto ret = parcel.WriteDBinderProxy(object, HANDLE_TEST, STUBINDEX_TEST);
    EXPECT_EQ(ret, false);
    delete instance;
}

/**
 * @tc.name: WriteDBinderProxyTest002
 * @tc.desc: Verify the MessageParcel::WriteDBinderProxy function return false
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteDBinderProxyTest002, TestSize.Level1)
{
    MessageParcel parcel;
    MockIPCProcessSkeleton *instance = new MockIPCProcessSkeleton();
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    sptr<IRemoteObject> object = new IPCObjectStub();
    auto dbinderSessionObject = std::make_shared<DBinderSessionObject>(NAME_TEST, DEVICE_TEST,
        NUMBER_TEST, nullptr, NUMBER_TEST);
    current->proxyToSession_[HANDLE_TEST] = dbinderSessionObject;
    sptr<DBinderCallbackStub> fakeStub = new DBinderCallbackStub(NAME_TEST, DEVICE_TEST, LOCAL_TEST, STUBINDEX_TEST,
        HANDLE_TEST, NUMBER_TEST);
    EXPECT_CALL(*instance, QueryDBinderCallbackStub(object)).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*instance, AttachDBinderCallbackStub(object, fakeStub)).WillRepeatedly(Return(false));
    auto ret = parcel.WriteDBinderProxy(object, HANDLE_TEST, STUBINDEX_TEST);
    EXPECT_EQ(ret, false);
    current->proxyToSession_.erase(HANDLE_TEST);
    delete instance;
}

/**
 * @tc.name: WriteRawDataTest001
 * @tc.desc: Verify the MessageParcel::WriteRawData function return true
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest001, TestSize.Level1)
{
    MessageParcel parcel;
    char data[NUMBER_TEST] = { 0 };
    NiceMock<MessageParcelInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillOnce(Return(true));
    auto ret = parcel.WriteRawData(data, sizeof(data));
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: WriteRawDataTest002
 * @tc.desc: Verify the MessageParcel::WriteRawData function return false
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest002, TestSize.Level1)
{
    MessageParcel parcel;
    auto ret = parcel.WriteRawData(nullptr, NUMBER_TEST);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: WriteRawDataTest003
 * @tc.desc: Verify the MessageParcel::WriteRawData function return true
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest003, TestSize.Level1)
{
    MessageParcel parcel;
    NiceMock<MessageParcelInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillOnce(Return(true));
    char data[MessageParcel::MIN_RAWDATA_SIZE + NUMBER_TEST] = { 0 };
    auto ret = parcel.WriteRawData(data, MessageParcel::MIN_RAWDATA_SIZE + NUMBER_TEST);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: WriteRawDataTest004
 * @tc.desc: Verify the MessageParcel::WriteRawData function return false
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest004, TestSize.Level1)
{
    MessageParcel parcel;
    char data[NUMBER_TEST] = { 0 };
    parcel.kernelMappedWrite_ = data;
    auto ret = parcel.WriteRawData(data, NUMBER_TEST);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: WriteRawDataTest005
 * @tc.desc: Verify the MessageParcel::WriteRawData function return false
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest005, TestSize.Level1)
{
    MessageParcel parcel;
    char data[NUMBER_TEST] = { 0 };
    NiceMock<MessageParcelInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillOnce(Return(false));
    auto ret = parcel.WriteRawData(data, sizeof(data));
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: WriteRawDataTest006
 * @tc.desc: Verify the MessageParcel::WriteRawData function size is MessageParcel::MAX_RAWDATA_SIZE + NUMBER_TEST
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, WriteRawDataTest006, TestSize.Level1)
{
    MessageParcel parcel;
    NiceMock<MessageParcelInterfaceMock> mock;
    char data[NUMBER_TEST] = { 0 };
    auto ret = parcel.WriteRawData(data, MessageParcel::MAX_RAWDATA_SIZE + NUMBER_TEST);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: AppendTest001
 * @tc.desc: Verify the Append function return true
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AppendTest001, TestSize.Level1)
{
    MessageParcel data;
    uint8_t bytes[BNUMBER_TEST] = {0};
    data.WriteBuffer(bytes, BNUMBER_TEST);
    MessageParcel parcel;
    bool ret = parcel.Append(data);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(data.GetDataSize(), BNUMBER_TEST);
}

/**
 * @tc.name: AppendTest002
 * @tc.desc: Verify the MessageParcel::Append function return true
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelTest, AppendTest002, TestSize.Level1)
{
    MessageParcel parcel;
    MessageParcel data;
    auto ret = parcel.Append(data);
    EXPECT_EQ(ret, true);
}
}
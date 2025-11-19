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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "process_skeleton.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace {
    const std::u16string DESCRIPTOR_TEST = u"test_descriptor";
    const std::string DIGIT_STR_TEST = "12345";
    const std::string NON_DIGIT_STR_TEST = "123abc";
    const std::string PUNCTUATION_STR_TEST = "123,45";
}

class ProcessSkeletonInterface {
public:
    ProcessSkeletonInterface() {};
    virtual ~ProcessSkeletonInterface() {};

    virtual bool WriteBuffer(const void *data, size_t size) = 0;
};
class ProcessSkeletonInterfaceMock : public ProcessSkeletonInterface {
public:
    ProcessSkeletonInterfaceMock();
    ~ProcessSkeletonInterfaceMock() override;

    MOCK_METHOD2(WriteBuffer, bool(const void *data, size_t size));
};
static void *g_interface = nullptr;

ProcessSkeletonInterfaceMock::ProcessSkeletonInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

ProcessSkeletonInterfaceMock::~ProcessSkeletonInterfaceMock()
{
    g_interface = nullptr;
}

static ProcessSkeletonInterface *GetProcessSkeletonInterface()
{
    return reinterpret_cast<ProcessSkeletonInterface *>(g_interface);
}

extern "C" {
    bool Parcel::WriteBuffer(const void *data, size_t size)
    {
        return GetProcessSkeletonInterface()->WriteBuffer(data, size);
    }
}

class ProcessSkeletonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ProcessSkeletonTest::SetUpTestCase()
{
}

void ProcessSkeletonTest::TearDownTestCase()
{
}

void ProcessSkeletonTest::SetUp()
{
}

void ProcessSkeletonTest::TearDown()
{
}

/**
 * @tc.name: IsContainsObjectTest001
 * @tc.desc: Verify the IsContainsObject function when object is valid value
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsContainsObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(DESCRIPTOR_TEST);
    skeleton->isContainStub_.clear();
    bool ret = skeleton->IsContainsObject(object.GetRefPtr());
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsContainsObjectTest002
 * @tc.desc: Verify the IsContainsObject function when object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsContainsObjectTest002, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->isContainStub_.clear();
    bool ret = skeleton->IsContainsObject(nullptr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsContainsObjectTest003
 * @tc.desc: Verify the IsContainsObject function when isContainStub_[object] is false
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsContainsObjectTest003, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);
    sptr<IRemoteObject> object = new IPCObjectStub(DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);
    skeleton->isContainStub_[object] = false;
    bool ret = skeleton->IsContainsObject(object.GetRefPtr());
    EXPECT_FALSE(ret);
    skeleton->isContainStub_.clear();
}

/**
 * @tc.name: IsContainsObjectTest004
 * @tc.desc: Verify the IsContainsObject function when isContainStub_[object] is true
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsContainsObjectTest004, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);
    sptr<IRemoteObject> object = new IPCObjectStub(DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);
    skeleton->isContainStub_[object] = true;
    bool ret = skeleton->IsContainsObject(object.GetRefPtr());
    EXPECT_TRUE(ret);
    skeleton->isContainStub_.clear();
}

/**
 * @tc.name: QueryObjectTest001
 * @tc.desc: Verify the QueryObject function execute normally
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, QueryObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);
    skeleton->AttachObject(object.GetRefPtr(), object->GetObjectDescriptor(), true);
    sptr<IRemoteObject> queriedObject = skeleton->QueryObject(object->GetObjectDescriptor(), true);
    EXPECT_EQ(queriedObject.GetRefPtr(), object.GetRefPtr());
    skeleton->objects_.clear();
}

/**
 * @tc.name: QueryObjectTest002
 * @tc.desc: Verify the QueryObject function when descriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, QueryObjectTest002, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string descriptor;
    sptr<IRemoteObject> queriedObject = skeleton->QueryObject(descriptor, false);
    EXPECT_EQ(queriedObject.GetRefPtr(), nullptr);
}

/**
 * @tc.name: QueryObjectTest003
 * @tc.desc: Verify the QueryObject function when exitFlag_ is true
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, QueryObjectTest003, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    skeleton->exitFlag_ = true;
    std::u16string descriptor = DESCRIPTOR_TEST;
    sptr<IRemoteObject> queriedObject = skeleton->QueryObject(descriptor, false);
    EXPECT_EQ(queriedObject.GetRefPtr(), nullptr);
    skeleton->exitFlag_ = false;
}

/**
 * @tc.name: QueryObjectTest004
 * @tc.desc: Verify the QueryObject function when there is no 'descriptor' in the objects_ collection
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, QueryObjectTest004, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string descriptor = DESCRIPTOR_TEST;
    skeleton->objects_.clear();
    sptr<IRemoteObject> queriedObject = skeleton->QueryObject(descriptor, false);
    EXPECT_EQ(queriedObject.GetRefPtr(), nullptr);
}

/**
 * @tc.name: QueryObjectTest005
 * @tc.desc: Verify the QueryObject function when AttemptIncStrong function is false
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, QueryObjectTest005, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    sptr<IRemoteObject> object = new IPCObjectStub(DESCRIPTOR_TEST);
    ASSERT_TRUE(object != nullptr);
    std::u16string descriptor = DESCRIPTOR_TEST;
    skeleton->objects_[descriptor] = object;
    skeleton->validObjectRecord_.clear();
    sptr<IRemoteObject> queriedObject = skeleton->QueryObject(descriptor, false);
    EXPECT_EQ(queriedObject.GetRefPtr(), nullptr);
}

/**
 * @tc.name: IsValidObjectTest001
 * @tc.desc: Verify the IsValidObject function when validObjectRecord_ collection contains object
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsValidObjectTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string str(DESCRIPTOR_TEST);
    sptr<IRemoteObject> object = new IPCObjectStub(str);
    skeleton->AttachValidObject(object.GetRefPtr(), str);
    std::u16string desc;
    bool ret = skeleton->IsValidObject(object.GetRefPtr(), desc);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsValidObjectTest002
 * @tc.desc: Verify the IsValidObject function when object is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsValidObjectTest002, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string desc;
    skeleton->validObjectRecord_.clear();
    bool ret = skeleton->IsValidObject(nullptr, desc);
    EXPECT_EQ(ret, false);
    skeleton->objects_.clear();
    skeleton->isContainStub_.clear();
}

/**
 * @tc.name: IsValidObjectTest003
 * @tc.desc: Verify the IsValidObject function when validObjectRecord_ collection is empty
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsValidObjectTest003, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::u16string desc;
    std::u16string str(DESCRIPTOR_TEST);
    sptr<IRemoteObject> object = new IPCObjectStub(str);
    skeleton->validObjectRecord_.clear();
    bool ret = skeleton->IsValidObject(object.GetRefPtr(), desc);
    EXPECT_EQ(ret, false);
    skeleton->objects_.clear();
    skeleton->isContainStub_.clear();
}

/**
 * @tc.name: FlattenDBinderDataTest001
 * @tc.desc: Verify the FlattenDBinderData function when WriteBuffer function return false
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, FlattenDBinderDataTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    Parcel parcel;
    dbinder_negotiation_data data;
    const dbinder_negotiation_data* dbinderData = &data;
    NiceMock<ProcessSkeletonInterfaceMock> processSkeletonMock;

    EXPECT_CALL(processSkeletonMock, WriteBuffer(testing::_, testing::_)).WillOnce(testing::Return(false));

    bool ret = skeleton->FlattenDBinderData(parcel, dbinderData);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: FlattenDBinderDataTest002
 * @tc.desc: Verify the FlattenDBinderData function when WriteBuffer function return true
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, FlattenDBinderDataTest002, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    Parcel parcel;
    dbinder_negotiation_data data;
    const dbinder_negotiation_data* dbinderData = &data;
    NiceMock<ProcessSkeletonInterfaceMock> processSkeletonMock;

    EXPECT_CALL(processSkeletonMock, WriteBuffer(testing::_, testing::_)).WillOnce(testing::Return(true));

    bool ret = skeleton->FlattenDBinderData(parcel, dbinderData);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: IsNumStrTest001
 * @tc.desc: Verify the IsNumStr function when str is empty
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsNumStrTest001, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::string emptyStr = "";
    bool ret = skeleton->IsNumStr(emptyStr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsNumStrTest002
 * @tc.desc: Verify the IsNumStr function when str contains numbers
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsNumStrTest002, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::string digitStr = DIGIT_STR_TEST;
    bool ret = skeleton->IsNumStr(digitStr);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: IsNumStrTest003
 * @tc.desc: Verify the IsNumStr function when str contains nonDigit
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsNumStrTest003, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::string nonDigitStr = NON_DIGIT_STR_TEST;
    bool ret = skeleton->IsNumStr(nonDigitStr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsNumStrTest004
 * @tc.desc: Verify the IsNumStr function when str contains punctuation
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, IsNumStrTest004, TestSize.Level1)
{
    ProcessSkeleton *skeleton = ProcessSkeleton::GetInstance();
    ASSERT_TRUE(skeleton != nullptr);

    std::string punctuationStr = PUNCTUATION_STR_TEST;
    bool ret = skeleton->IsNumStr(punctuationStr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ConvertBytesToHexString001
 * @tc.desc: Verify the ConvertBytesToHexString function when data pointer is null
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, ConvertBytesToHexString001, TestSize.Level1)
{
    const uint8_t *data = nullptr;
    size_t length = 100;
    std::string result = ProcessSkeleton::ConvertBytesToHexString(data, length);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: ConvertBytesToHexString002
 * @tc.desc: Verify the ConvertBytesToHexString function when data pointer is ok
 * @tc.type: FUNC
 */
HWTEST_F(ProcessSkeletonTest, ConvertBytesToHexString002, TestSize.Level1)
{
    const uint8_t data[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    const std::string checkResult = "00112233445566778899AABBCCDDEEFF";
    std::string result = ProcessSkeleton::ConvertBytesToHexString(data, sizeof(data));
    EXPECT_TRUE(result == checkResult);
}
} // namespace OHOS
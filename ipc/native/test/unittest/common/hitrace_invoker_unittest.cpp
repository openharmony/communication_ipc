/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "hitrace_invoker.h"
#include "process_skeleton.h"
#include "message_parcel.h"
#include "iremote_invoker.h"

using namespace OHOS;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::HiviewDFX;
namespace OHOS {

class HitraceInvokerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() const;
    void TearDown() const;
};

void HitraceInvokerTest::SetUp() const {}

void HitraceInvokerTest::TearDown() const {}

void HitraceInvokerTest::SetUpTestCase() {}

void HitraceInvokerTest::TearDownTestCase() {}

class HitraceInvokerInterface {
public:
    HitraceInvokerInterface() {};
    virtual ~HitraceInvokerInterface() {};

    virtual int ToBytes(uint8_t* pIdArray, int len) = 0;
    virtual bool IsValid() = 0;
    virtual bool WriteBuffer(const void *data, size_t size) = 0;
    virtual bool WriteUint8(uint8_t value) = 0;
    virtual size_t GetDataSize() = 0;
    virtual uint8_t ReadUint8() = 0;
    virtual const uint8_t *ReadUnpadBuffer(size_t length) = 0;
};
class HitraceInvokerInterfaceMock : public HitraceInvokerInterface {
public:
    HitraceInvokerInterfaceMock();
    ~HitraceInvokerInterfaceMock() override;

    MOCK_METHOD2(ToBytes, int(uint8_t*, int));
    MOCK_METHOD0(IsValid, bool());
    MOCK_METHOD2(WriteBuffer, bool(const void *, size_t));
    MOCK_METHOD1(WriteUint8, bool(uint8_t));
    MOCK_METHOD0(GetDataSize, size_t());
    MOCK_METHOD0(ReadUint8, uint8_t());
    MOCK_METHOD1(ReadUnpadBuffer, const uint8_t *(size_t));
};
static void *g_mockInterface = nullptr;

HitraceInvokerInterfaceMock::HitraceInvokerInterfaceMock()
{
    g_mockInterface = reinterpret_cast<void *>(this);
}

HitraceInvokerInterfaceMock::~HitraceInvokerInterfaceMock()
{
    g_mockInterface = nullptr;
}

static HitraceInvokerInterface *GetHitraceInvokerInterface()
{
    return reinterpret_cast<HitraceInvokerInterface *>(g_mockInterface);
}

extern "C" {
    int HiTraceId::ToBytes(uint8_t* pIdArray, int len) const
    {
        return GetHitraceInvokerInterface()->ToBytes(pIdArray, len);
    }
    bool HiTraceId::IsValid() const
    {
        return GetHitraceInvokerInterface()->IsValid();
    }
    bool Parcel::WriteBuffer(const void *data, size_t size)
    {
        return GetHitraceInvokerInterface()->WriteBuffer(data, size);
    }
    bool Parcel::WriteUint8(uint8_t value)
    {
        return GetHitraceInvokerInterface()->WriteUint8(value);
    }
    size_t Parcel::GetDataSize() const
    {
        return GetHitraceInvokerInterface()->GetDataSize();
    }
    uint8_t Parcel::ReadUint8()
    {
        return GetHitraceInvokerInterface()->ReadUint8();
    }
    const uint8_t *Parcel::ReadUnpadBuffer(size_t length)
    {
        return GetHitraceInvokerInterface()->ReadUnpadBuffer(length);
    }
}
/**
 * @tc.name: TraceClientSendTest001
 * @tc.desc: TraceClientSend
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, TraceClientSendTest001, TestSize.Level1)  // line 77
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    MessageParcel newData;
    const HiTraceId traceId;
    int handle = 1;
    uint32_t code = 1001;
    uint32_t flags = 2;

    EXPECT_CALL(mock, IsValid).WillOnce(Return(true));
    EXPECT_CALL(mock, ToBytes).WillOnce(Return(HITRACE_ID_LEN));
    EXPECT_CALL(mock, WriteBuffer).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteUint8).WillOnce(Return(true));

    HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);
    EXPECT_EQ(flags, 130);
}

/**
 * @tc.name: TraceClientSendTest005
 * @tc.desc: TraceClientSend
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, TraceClientSendTest005, TestSize.Level1)  // line 52
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    MessageParcel newData;
    const HiTraceId traceId;
    int handle = 1;
    uint32_t code = 1001;
    uint32_t flags = 2;

    EXPECT_CALL(mock, IsValid).WillOnce(Return(true));
    EXPECT_CALL(mock, ToBytes).WillOnce(Return(1));
    HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);
    EXPECT_EQ(flags, 2);
}

/**
 * @tc.name: TraceClientSendTest002
 * @tc.desc: TraceClientSend
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, TraceClientSendTest002, TestSize.Level1)  // line: 58
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    MessageParcel newData;
    const HiTraceId traceId;
    int handle = 1;
    uint32_t code = 1001;
    uint32_t flags = 2;

    EXPECT_CALL(mock, IsValid).WillOnce(Return(true));
    EXPECT_CALL(mock, ToBytes).WillOnce(Return(HITRACE_ID_LEN));
    EXPECT_CALL(mock, WriteBuffer).WillOnce(Return(false));

    HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);
    EXPECT_EQ(flags, 2);
}

/**
 * @tc.name: TraceClientSendTest003
 * @tc.desc: TraceClientSend
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, TraceClientSendTest003, TestSize.Level1)  // line: 66
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    MessageParcel newData;
    const HiTraceId traceId;
    int handle = 1;
    uint32_t code = 1001;
    uint32_t flags = 2;

    EXPECT_CALL(mock, IsValid).WillOnce(Return(true));
    EXPECT_CALL(mock, ToBytes).WillOnce(Return(HITRACE_ID_LEN));
    EXPECT_CALL(mock, WriteBuffer).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteUint8).WillOnce(Return(false));
    HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);
    EXPECT_EQ(flags, 2);
}

/**
 * @tc.name: TraceClientSendTest004
 * @tc.desc: TraceClientSend
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, TraceClientSendTest004, TestSize.Level1)  // line: 79
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    MessageParcel newData;
    const HiTraceId traceId;
    int handle = 0;
    uint32_t code = 1001;
    uint32_t flags = 129;

    EXPECT_CALL(mock, IsValid).WillOnce(Return(false));
    HitraceInvoker::TraceClientSend(handle, code, newData, flags, traceId);
    EXPECT_EQ(flags, 1);
}

/**
 * @tc.name: RecoveryDataAndFlagTest001
 * @tc.desc: RecoveryDataAndFlag
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, RecoveryDataAndFlagTest001, TestSize.Level1)  // line: 107
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    Parcel data;
    uint32_t flags = 129;
    size_t oldReadPosition = 64;

    EXPECT_CALL(mock, GetDataSize).WillOnce(Return(128));
    HitraceInvoker::RecoveryDataAndFlag(data, flags, oldReadPosition, 128);
    EXPECT_EQ(flags, 129);
}

/**
 * @tc.name: TraceServerReceiveTest001
 * @tc.desc: TraceServerReceive
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, TraceServerReceiveTest001, TestSize.Level1)  // line: 150
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    int handle = 1;
    MessageParcel data;
    uint32_t flags = 129;
    uint32_t code = 1001;
    int num = sizeof(HiTraceIdStruct);
    uint8_t readUnpadBuffer = 128;

    EXPECT_CALL(mock, GetDataSize).WillRepeatedly(Return(num + 8));
    EXPECT_CALL(mock, ReadUint8).WillOnce(Return(num + 2));
    EXPECT_CALL(mock, ReadUnpadBuffer).WillOnce(Return(&readUnpadBuffer));
    bool ret = HitraceInvoker::TraceServerReceive(handle, code, data, flags);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: TraceServerReceiveTest002
 * @tc.desc: TraceServerReceive
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, TraceServerReceiveTest002, TestSize.Level1)  // line: 136
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    int handle = 1;
    MessageParcel data;
    uint32_t flags = 129;
    uint32_t code = 1001;
    int num = sizeof(HiTraceIdStruct);

    EXPECT_CALL(mock, GetDataSize).WillRepeatedly(Return(num + 8));
    EXPECT_CALL(mock, ReadUint8).WillOnce(Return(num + 2));
    EXPECT_CALL(mock, ReadUnpadBuffer).WillOnce(Return(nullptr));
    bool ret = HitraceInvoker::TraceServerReceive(handle, code, data, flags);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: TraceServerReceiveTest003
 * @tc.desc: TraceServerReceive
 * @tc.type: FUNC
 */
HWTEST_F(HitraceInvokerTest, TraceServerReceiveTest003, TestSize.Level1)  // line: 154
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    int handle = 1;
    MessageParcel data;
    uint32_t flags = 129;
    uint32_t code = 1001;
    int num = sizeof(HiTraceIdStruct);

    EXPECT_CALL(mock, GetDataSize).WillRepeatedly(Return(num + 8));
    EXPECT_CALL(mock, ReadUint8).WillOnce(Return(num - 1));
    bool ret = HitraceInvoker::TraceServerReceive(handle, code, data, flags);
    EXPECT_EQ(ret, true);
}

} // namespace OHOS

/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hitraceinvokermock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class HitraceInvokerInterface {
public:
    HitraceInvokerInterface() {};
    virtual ~HitraceInvokerInterface() {};

    virtual size_t GetDataSize() const = 0;
    virtual uint8_t ReadUint8() = 0;
    virtual const uint8_t *ReadUnpadBuffer(size_t length) = 0;
    virtual bool IsValid() = 0;
    virtual int ToBytes(uint8_t *pIdArray, int len) = 0;
    virtual bool WriteBuffer(const void *data, size_t size) = 0;
    virtual bool WriteUint8(uint8_t value) = 0;
};

class HitraceInvokerInterfaceMock : public HitraceInvokerInterface {
public:
    HitraceInvokerInterfaceMock();
    ~HitraceInvokerInterfaceMock() override;

    MOCK_METHOD(size_t, GetDataSize, (), (const, override));
    MOCK_METHOD(uint8_t, ReadUint8, (), (override));
    MOCK_METHOD(const uint8_t *, ReadUnpadBuffer, (size_t length), (override));
    MOCK_METHOD(bool, IsValid, (), (override));
    MOCK_METHOD(int, ToBytes, (uint8_t * pIdArray, int len), (override));
    MOCK_METHOD(bool, WriteBuffer, (const void *data, size_t size), (override));
    MOCK_METHOD(bool, WriteUint8, (uint8_t value), (override));
};

static void *g_interface = nullptr;

HitraceInvokerInterfaceMock::HitraceInvokerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

HitraceInvokerInterfaceMock::~HitraceInvokerInterfaceMock()
{
    g_interface = nullptr;
}

static HitraceInvokerInterface *GetHitraceInvokerInterface()
{
    return reinterpret_cast<HitraceInvokerInterface *>(g_interface);
}

extern "C" {
size_t Parcel::GetDataSize() const
{
    if (g_interface == nullptr) {
        return 0;
    }
    return GetHitraceInvokerInterface()->GetDataSize();
}

uint8_t Parcel::ReadUint8()
{
    if (g_interface == nullptr) {
        return 0;
    }
    return GetHitraceInvokerInterface()->ReadUint8();
}

const uint8_t *Parcel::ReadUnpadBuffer(size_t length)
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetHitraceInvokerInterface()->ReadUnpadBuffer(length);
}

bool HiviewDFX::HiTraceId::IsValid() const
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetHitraceInvokerInterface()->IsValid();
}

int HiviewDFX::HiTraceId::ToBytes(uint8_t *pIdArray, int len) const
{
    if (pIdArray == nullptr) {
        return 0;
    }
    return GetHitraceInvokerInterface()->ToBytes(pIdArray, len);
}

bool Parcel::WriteBuffer(const void *data, size_t size)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetHitraceInvokerInterface()->WriteBuffer(data, size);
}

bool Parcel::WriteUint8(uint8_t value)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetHitraceInvokerInterface()->WriteUint8(value);
}
}

void TraceServerReceieveFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t handle = provider.ConsumeIntegral<uint64_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t flags = 129;
    MessageParcel data;
    NiceMock<HitraceInvokerInterfaceMock> mock;
    size_t dataSize = HITRACE_ID_LEN + 8;
    uint8_t idLen = HITRACE_ID_LEN + 2;
    EXPECT_CALL(mock, GetDataSize).WillRepeatedly(Return(dataSize));
    EXPECT_CALL(mock, ReadUint8).WillOnce(Return(idLen));
    EXPECT_CALL(mock, ReadUnpadBuffer).WillOnce(Return(nullptr));
    HitraceInvoker::TraceServerReceieve(handle, code, data, flags);
}

void TraceClientSendFuzzTest(FuzzedDataProvider &provider)
{
    NiceMock<HitraceInvokerInterfaceMock> mock;
    MessageParcel data;
    const HiviewDFX::HiTraceId traceId;
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t flags = 2;

    EXPECT_CALL(mock, IsValid).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, ToBytes).WillRepeatedly(Return(HITRACE_ID_LEN));
    EXPECT_CALL(mock, WriteBuffer).WillRepeatedly(Return(false));
    HitraceInvoker::TraceClientSend(handle, code, data, flags, traceId);

    EXPECT_CALL(mock, WriteBuffer).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, WriteUint8).WillRepeatedly(Return(false));
    HitraceInvoker::TraceClientSend(handle, code, data, flags, traceId);

    EXPECT_CALL(mock, WriteUint8).WillRepeatedly(Return(true));
    HitraceInvoker::TraceClientSend(handle, code, data, flags, traceId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TraceServerReceieveFuzzTest(provider);
    OHOS::TraceClientSendFuzzTest(provider);
    return 0;
}

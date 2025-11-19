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

#include "messageparcelmock_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>
#include "ipc_object_stub.h"
#include "ipc_file_descriptor.h"
#include "iremote_object.h"
#include "ipc_process_skeleton.h"
#include "process_skeleton.h"
#include "message_parcel.h"
#include "sys_binder.h"
#include "string_ex.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
const static size_t MAX_STRING_PARAM_LEN = 100;

class MessageParcelInstence {
public:
    MessageParcelInstence() {};
    virtual ~MessageParcelInstence() {};

    virtual IPCProcessSkeleton *GetCurrent() = 0;
    virtual bool WriteInt32(int32_t value) = 0;
    virtual bool WriteBuffer(const void *data, size_t size) = 0;
    virtual bool WriteObjectOffset(binder_size_t offset) = 0;
    virtual bool RewindWrite(size_t position) = 0;
    virtual bool WriteFileDescriptor(int fd) = 0;
};

class MessageParcelInstenceMock : public MessageParcelInstence {
public:
    MessageParcelInstenceMock();
    ~MessageParcelInstenceMock() override;
    
    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton *());
    MOCK_METHOD1(WriteInt32, bool(int32_t value));
    MOCK_METHOD2(WriteBuffer, bool(const void *data, size_t size));
    MOCK_METHOD1(WriteObjectOffset, bool(binder_size_t offset));
    MOCK_METHOD1(RewindWrite, bool(size_t position));
    MOCK_METHOD1(WriteFileDescriptor, bool(int fd));
};

static void *g_interface = nullptr;

MessageParcelInstenceMock::MessageParcelInstenceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

MessageParcelInstenceMock::~MessageParcelInstenceMock()
{
    g_interface = nullptr;
}

static MessageParcelInstenceMock *GetMessageParcelInstenceMock()
{
    return reinterpret_cast<MessageParcelInstenceMock *>(g_interface);
}

extern "C" {
    IPCProcessSkeleton *IPCProcessSkeleton::GetCurrent()
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return nullptr;
        }
        return interface->GetCurrent();
    }

    bool Parcel::WriteInt32(int32_t value)
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteInt32(value);
    }

    bool Parcel::WriteBuffer(const void *data, size_t size)
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteBuffer(data, size);
    }

    bool Parcel::WriteObjectOffset(binder_size_t offset)
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteObjectOffset(offset);
    }

    bool Parcel::RewindWrite(size_t newPosition)
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->RewindWrite(newPosition);
    }

    bool MessageParcel::WriteFileDescriptor(int fd)
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteFileDescriptor(fd);
    }
}

void WriteDBinderProxyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    sptr<IPCObjectProxy> object = new (std::nothrow) IPCObjectProxy(handle);
    if (object == nullptr) {
        return;
    }
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, GetCurrent).WillOnce(Return(nullptr));
    parcel.WriteDBinderProxy(object, handle, stubIndex);
}

void UpdateDBinderDataOffsetFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    binder_buffer_object bufferObject;
    bufferObject.parent = provider.ConsumeIntegral<uint64_t>();
    bufferObject.parent_offset = provider.ConsumeIntegral<uint64_t>();
    bufferObject.hdr.type = BINDER_TYPE_PTR;
    bufferObject.flags = BINDER_BUFFER_FLAG_HAS_DBINDER;
    bufferObject.length = sizeof(dbinder_negotiation_data);
    parcel.WriteBuffer(&bufferObject, sizeof(binder_buffer_object));
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, WriteObjectOffset).WillOnce(Return(false));
    parcel.UpdateDBinderDataOffset((reinterpret_cast<uintptr_t>(&bufferObject) - parcel.GetData()));
}

void WriteInterfaceTokenFuzzTest(FuzzedDataProvider &provider)
{
    std::string interfaceToken = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    std::u16string interfaceToken16 = Str8ToStr16(interfaceToken);
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillOnce(Return(false));
    MessageParcel parcel;
    parcel.WriteInterfaceToken(interfaceToken16);

    int strictModePolicy = 0x100;
    constexpr int workSource = 0;
    EXPECT_CALL(mock, WriteInt32(strictModePolicy)).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteInt32(workSource)).WillRepeatedly(testing::Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(Return(false));
    parcel.WriteInterfaceToken(interfaceToken16);
}

void WriteRawDataFuzzTest001(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    std::string rawData = provider.ConsumeRandomLengthString(MessageParcel::MAX_RAWDATA_SIZE);
    size_t bytesSize = rawData.size();
    if (bytesSize <= MessageParcel::MIN_RAWDATA_SIZE || bytesSize > MessageParcel::MAX_RAWDATA_SIZE) {
        return;
    }
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillOnce(Return(false));
    parcel.WriteRawData(static_cast<const void*>(rawData.c_str()), bytesSize);

    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteFileDescriptor).WillOnce(Return(false));
    parcel.WriteRawData(static_cast<const void*>(rawData.c_str()), bytesSize);
}

void WriteRawDataFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    std::string rawData = provider.ConsumeRandomLengthString(MessageParcel::MAX_RAWDATA_SIZE);
    if (rawData.size() <= MessageParcel::MIN_RAWDATA_SIZE) {
        return;
    }
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, WriteFileDescriptor).WillOnce(Return(true));
    parcel.WriteRawData(static_cast<const void*>(rawData.c_str()), rawData.size());
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::WriteDBinderProxyFuzzTest(provider);
    OHOS::UpdateDBinderDataOffsetFuzzTest(provider);
    OHOS::WriteInterfaceTokenFuzzTest(provider);
    OHOS::WriteRawDataFuzzTest001(provider);
    OHOS::WriteRawDataFuzzTest002(provider);
    return 0;
}

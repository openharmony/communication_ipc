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
#include "ipc_object_stub.h"
#include "ipc_file_descriptor.h"
#include "iremote_object.h"
#include "ipc_process_skeleton.h"
#include "process_skeleton.h"
#include "message_parcel.h"
#include "sys_binder.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
const static size_t MAX_STRING_PARAM_LEN = 100;

class MessageParcelInstence {
public:
    MessageParcelInstence() {};
    virtual ~MessageParcelInstence() {};

    virtual size_t GetOffsetsSize() = 0;
    virtual size_t GetDataSize() = 0;
    virtual binder_size_t GetObjectOffsets() = 0;
    virtual bool WriteBuffer(const void *data, size_t size) = 0;
    virtual bool EnsureObjectsCapacity() = 0;
};

class MessageParcelInstenceMock : public MessageParcelInstence {
public:
    MessageParcelInstenceMock();
    ~MessageParcelInstenceMock() override;
    
    MOCK_METHOD0(GetOffsetsSize, size_t());
    MOCK_METHOD0(GetDataSize, size_t());
    MOCK_METHOD0(GetObjectOffsets, binder_size_t());
    MOCK_METHOD2(WriteBuffer, bool(const void *data, size_t size));
    MOCK_METHOD0(EnsureObjectsCapacity, bool());
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
    size_t Parcel::GetOffsetsSize() const
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->GetOffsetsSize();
    }

    size_t Parcel::GetDataSize() const
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->GetDataSize();
    }

    binder_size_t Parcel::GetObjectOffsets() const
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->GetObjectOffsets();
    }

    bool Parcel::WriteBuffer(const void *data, size_t size)
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->WriteBuffer(data, size);
    }

    bool Parcel::EnsureObjectsCapacity()
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->EnsureObjectsCapacity();
    }
}

void AppendFuzzTest001(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    MessageParcel data;
    std::string dataParcel = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    data.WriteBuffer(dataParcel.data(), dataParcel.size());
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, GetDataSize).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, WriteBuffer).WillOnce(Return(false));
    parcel.Append(data);

    EXPECT_CALL(mock, WriteBuffer).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, GetOffsetsSize).WillOnce(Return(0));
    parcel.Append(data);
}

void AppendFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    MessageParcel data;
    std::string dataParcel = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    data.WriteBuffer(dataParcel.data(), dataParcel.size());
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, GetDataSize).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, WriteBuffer).WillRepeatedly(testing::Return(true));
    binder_size_t offsetArray[2] = {0x400, 0x800};
    EXPECT_CALL(mock, GetOffsetsSize).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, GetObjectOffsets).WillRepeatedly(testing::Return(reinterpret_cast<binder_size_t>(offsetArray)));
    EXPECT_CALL(mock, EnsureObjectsCapacity).WillOnce(Return(false));
    parcel.Append(data);

    EXPECT_CALL(mock, EnsureObjectsCapacity).WillRepeatedly(testing::Return(true));
    parcel.Append(data);
}

void PrintBufferFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    std::string dataParcel = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    parcel.WriteBuffer(dataParcel.data(), dataParcel.size());
    size_t lineNum = provider.ConsumeIntegral<size_t>();
    parcel.PrintBuffer(nullptr, lineNum);

    std::string funcName = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    NiceMock<MessageParcelInstenceMock> mock;
    binder_size_t offsetArray[2] = {0x400, 0x800};
    EXPECT_CALL(mock, GetOffsetsSize).WillOnce(Return(1));
    EXPECT_CALL(mock, GetObjectOffsets).WillOnce(Return(reinterpret_cast<binder_size_t>(offsetArray)));
    parcel.PrintBuffer(funcName.c_str(), lineNum);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AppendFuzzTest001(provider);
    OHOS::AppendFuzzTest002(provider);
    OHOS::PrintBufferFuzzTest(provider);
    return 0;
}

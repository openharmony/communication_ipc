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
#include "ashmem.h"
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

    virtual bool WriteInt32(int32_t value) = 0;
    virtual bool WriteBuffer(const void *data, size_t size) = 0;
    virtual int32_t ReadInt32() = 0;
    virtual int AshmemCreate(const char *name, size_t size) = 0;
    virtual int AshmemSetProt(int fd, int prot);
    virtual int ReadFileDescriptor() = 0;
    virtual int AshmemGetSize(int fd) = 0;
    virtual int GetAshmemFd() = 0;
};

class MessageParcelInstenceMock : public MessageParcelInstence {
public:
    MessageParcelInstenceMock();
    ~MessageParcelInstenceMock() override;
    
    MOCK_METHOD1(WriteInt32, bool(int32_t value));
    MOCK_METHOD2(WriteBuffer, bool(const void *data, size_t size));
    MOCK_METHOD0(ReadInt32, int32_t());
    MOCK_METHOD2(AshmemCreate, int(const char *name, size_t size));
    MOCK_METHOD2(AshmemSetProt, int(int fd, int prot));
    MOCK_METHOD0(ReadFileDescriptor, int());
    MOCK_METHOD1(AshmemGetSize, int(int fd));
    MOCK_METHOD0(GetAshmemFd, int());
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

    int32_t Parcel::ReadInt32()
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->ReadInt32();
    }

    int MessageParcel::ReadFileDescriptor()
    {
        MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
        if (interface == nullptr) {
            return false;
        }
        return interface->ReadFileDescriptor();
    }
}

int AshmemCreate(const char *name, size_t size)
{
    MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
    if (interface == nullptr) {
        return -1;
    }
    return interface->AshmemCreate(name, size);
}

int AshmemSetProt(int fd, int prot)
{
    MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
    if (interface == nullptr) {
        return -1;
    }
    return interface->AshmemSetProt(fd, prot);
}

int AshmemGetSize(int fd)
{
    MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
    if (interface == nullptr) {
        return -1;
    }
    return interface->AshmemGetSize(fd);
}

int GetAshmemFd()
{
    MessageParcelInstenceMock* interface = GetMessageParcelInstenceMock();
    if (interface == nullptr) {
        return -1;
    }
    return interface->GetAshmemFd();
}

void WriteRawDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    std::string rawData = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    size_t bytesSize = rawData.size();
    if (bytesSize <= MessageParcel::MIN_RAWDATA_SIZE || bytesSize > MessageParcel::MAX_RAWDATA_SIZE) {
        return;
    }
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock, AshmemCreate).WillOnce(Return(-1));
    parcel.WriteRawData(static_cast<const void*>(rawData.c_str()), bytesSize);

    EXPECT_CALL(mock, AshmemCreate).WillOnce(Return(1));
    EXPECT_CALL(mock, AshmemSetProt).WillOnce(Return(-1));
    parcel.WriteRawData(static_cast<const void*>(rawData.c_str()), bytesSize);

    EXPECT_CALL(mock, AshmemCreate).WillOnce(Return(1));
    EXPECT_CALL(mock, AshmemSetProt).WillOnce(Return(1));
    parcel.WriteRawData(static_cast<const void*>(rawData.c_str()), bytesSize);
}

void ReadRawDataInnerFuzzTest001(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t size = provider.ConsumeIntegral<size_t>();
    parcel.ReadRawDataInner(size);
    
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, ReadFileDescriptor).WillOnce(Return(-1));
    parcel.ReadRawDataInner(size);

    EXPECT_CALL(mock, ReadFileDescriptor).WillOnce(Return(1));
    EXPECT_CALL(mock, AshmemGetSize).WillOnce(Return(0));
    parcel.ReadRawDataInner(size);

    EXPECT_CALL(mock, ReadFileDescriptor).WillOnce(Return(1));
    EXPECT_CALL(mock, AshmemGetSize).WillOnce(Return(size));
    parcel.ReadRawDataInner(size);
}

void ReadRawDataInnerFuzzTest002(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    size_t size = provider.ConsumeIntegral<size_t>();
    size_t rawDatasize = provider.ConsumeIntegral<size_t>();
    std::shared_ptr<char> rawData = std::make_shared<char>();
    parcel.RestoreRawData(rawData, rawDatasize);
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, ReadFileDescriptor).WillOnce(Return(-1));
    parcel.ReadRawDataInner(size);

    EXPECT_CALL(mock, ReadFileDescriptor).WillOnce(Return(1));
    parcel.ReadRawDataInner(rawDatasize);

    EXPECT_CALL(mock, ReadFileDescriptor).WillOnce(Return(1));
    parcel.ReadRawDataInner(size);
}

void ReadRawDataFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    std::string data = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    size_t size = provider.ConsumeIntegral<size_t>();
    size_t bytesSize =
        provider.ConsumeIntegralInRange<size_t>(MessageParcel::MIN_RAWDATA_SIZE + 1, MessageParcel::MAX_RAWDATA_SIZE);
    parcel.WriteBuffer(data.data(), data.size());
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, ReadInt32).WillOnce(Return(1));
    parcel.ReadRawData(size);

    EXPECT_CALL(mock, ReadInt32).WillOnce(Return(bytesSize));
    parcel.ReadRawData(bytesSize);
}

void WriteAshmemFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    std::string data = provider.ConsumeRandomLengthString(MAX_STRING_PARAM_LEN);
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(data.c_str(), data.size());
    if (ashmem == nullptr) {
        return;
    }
    NiceMock<MessageParcelInstenceMock> mock;
    EXPECT_CALL(mock, GetAshmemFd).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, AshmemGetSize).WillRepeatedly(testing::Return(0));
    parcel.WriteAshmem(ashmem);

    EXPECT_CALL(mock, AshmemGetSize).WillRepeatedly(testing::Return(1));
    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(false));
    parcel.WriteAshmem(ashmem);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::WriteRawDataFuzzTest(provider);
    OHOS::ReadRawDataInnerFuzzTest001(provider);
    OHOS::ReadRawDataInnerFuzzTest002(provider);
    OHOS::ReadRawDataFuzzTest(provider);
    OHOS::WriteAshmemFuzzTest(provider);
    return 0;
}

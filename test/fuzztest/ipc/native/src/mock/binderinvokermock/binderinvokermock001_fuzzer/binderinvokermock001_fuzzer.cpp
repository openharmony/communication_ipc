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

#include "binderinvokermock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class BinderInvokerInterface {
public:
    BinderInvokerInterface() {};
    virtual ~BinderInvokerInterface() {};

    virtual bool WriteUint32(uint32_t value) = 0;
    virtual bool WriteInt32(int32_t value) = 0;
    virtual bool RewindWrite(size_t newPosition) = 0;
    virtual bool WritePointer(uintptr_t value) = 0;
    virtual int FlushCommands(IRemoteObject *object) = 0;
};

class BinderInvokerInterfaceMock : public BinderInvokerInterface {
public:
    BinderInvokerInterfaceMock();
    ~BinderInvokerInterfaceMock() override;

    MOCK_METHOD(bool, WriteUint32, (uint32_t value), (override));
    MOCK_METHOD(bool, WriteInt32, (int32_t value), (override));
    MOCK_METHOD(bool, RewindWrite, (size_t newPosition), (override));
    MOCK_METHOD(bool, WritePointer, (uintptr_t value), (override));
    MOCK_METHOD(int, FlushCommands, (IRemoteObject * object), (override));
};

static void *g_interface = nullptr;

BinderInvokerInterfaceMock::BinderInvokerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

BinderInvokerInterfaceMock::~BinderInvokerInterfaceMock()
{
    g_interface = nullptr;
}

static BinderInvokerInterfaceMock *GetBinderInvokerInterfaceMock()
{
    return reinterpret_cast<BinderInvokerInterfaceMock *>(g_interface);
}

extern "C" {
bool Parcel::WriteUint32(uint32_t value)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->WriteUint32(value);
}

bool Parcel::WriteInt32(int32_t value)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->WriteInt32(value);
}

bool Parcel::RewindWrite(size_t newPosition)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->RewindWrite(newPosition);
}

bool Parcel::WritePointer(uintptr_t value)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->WritePointer(value);
}

int BinderInvoker::FlushCommands(IRemoteObject *object)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->FlushCommands(object);
}
}

static void AcquireHandleFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    BinderInvoker invoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteUint32(BC_ACQUIRE)).WillOnce(Return(false));
    invoker.AcquireHandle(handle);

    EXPECT_CALL(mock, WriteUint32(BC_ACQUIRE)).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteInt32(handle)).WillOnce(Return(false));
    EXPECT_CALL(mock, RewindWrite(_)).WillOnce(Return(false));
    invoker.AcquireHandle(handle);
}

static void ReleaseHandleFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    BinderInvoker invoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteUint32(BC_RELEASE)).WillOnce(Return(false));
    invoker.ReleaseHandle(handle);

    EXPECT_CALL(mock, WriteUint32(BC_RELEASE)).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteInt32(handle)).WillOnce(Return(false));
    EXPECT_CALL(mock, RewindWrite(_)).WillOnce(Return(false));
    invoker.ReleaseHandle(handle);
}

static void AddDeathRecipientFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    BinderInvoker invoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32(BC_REQUEST_DEATH_NOTIFICATION)).WillOnce(Return(false));
    invoker.AddDeathRecipient(handle, nullptr);

    EXPECT_CALL(mock, WriteInt32(BC_REQUEST_DEATH_NOTIFICATION)).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteInt32(handle)).WillOnce(Return(false));
    EXPECT_CALL(mock, RewindWrite(_)).WillOnce(Return(false));
    invoker.AddDeathRecipient(handle, nullptr);

    EXPECT_CALL(mock, WriteInt32(BC_REQUEST_DEATH_NOTIFICATION)).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteInt32(handle)).WillOnce(Return(true));
    EXPECT_CALL(mock, WritePointer(_)).WillOnce(Return(false));
    EXPECT_CALL(mock, RewindWrite(_)).WillOnce(Return(false));
    invoker.AddDeathRecipient(handle, nullptr);
}

static void RemoveDeathRecipientFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    BinderInvoker invoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32(BC_CLEAR_DEATH_NOTIFICATION)).WillOnce(Return(false));
    invoker.RemoveDeathRecipient(handle, nullptr);

    EXPECT_CALL(mock, WriteInt32(BC_CLEAR_DEATH_NOTIFICATION)).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteInt32(handle)).WillOnce(Return(false));
    EXPECT_CALL(mock, RewindWrite(_)).WillOnce(Return(false));
    invoker.RemoveDeathRecipient(handle, nullptr);

    EXPECT_CALL(mock, WriteInt32(BC_CLEAR_DEATH_NOTIFICATION)).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteInt32(handle)).WillOnce(Return(true));
    EXPECT_CALL(mock, WritePointer(_)).WillOnce(Return(false));
    EXPECT_CALL(mock, RewindWrite(_)).WillOnce(Return(false));
    invoker.RemoveDeathRecipient(handle, nullptr);

    EXPECT_CALL(mock, WriteInt32(BC_CLEAR_DEATH_NOTIFICATION)).WillOnce(Return(true));
    EXPECT_CALL(mock, WriteInt32(handle)).WillOnce(Return(true));
    EXPECT_CALL(mock, WritePointer(_)).WillOnce(Return(true));
    EXPECT_CALL(mock, FlushCommands(_)).WillOnce(Return(-1));
    invoker.RemoveDeathRecipient(handle, nullptr);
}

static void WriteTransactionFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel dataParcel;
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(MIN_BYTE_SIZE, MAX_BYTE_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    dataParcel.WriteBuffer(bytes.data(), bytes.size());
    int cmd = provider.ConsumeIntegral<int32_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    int32_t handle = provider.ConsumeIntegral<int32_t>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    size_t statusSize = provider.ConsumeIntegralInRange<size_t>(MIN_BYTE_SIZE, MAX_BYTE_SIZE);
    std::vector<uint8_t> statusBytes = provider.ConsumeBytes<uint8_t>(statusSize);
    int32_t *status = reinterpret_cast<int32_t *>(statusBytes.data());
    size_t totalDBinderBufSize = provider.ConsumeIntegralInRange<size_t>(MIN_BYTE_SIZE, MAX_BYTE_SIZE);

    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteInt32).WillOnce(Return(false));
    BinderInvoker invoker;
    invoker.WriteTransaction(cmd, flags, handle, code, dataParcel, status, totalDBinderBufSize);

    EXPECT_CALL(mock, WriteInt32).WillRepeatedly(testing::Return(true));
    invoker.WriteTransaction(cmd, flags, handle, code, dataParcel, status, totalDBinderBufSize);
    // Overwrite the special branch and call it twice.
    invoker.WriteTransaction(cmd, flags, handle, code, dataParcel, status, totalDBinderBufSize);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::AcquireHandleFuzzTest(provider);
    OHOS::ReleaseHandleFuzzTest(provider);
    OHOS::AddDeathRecipientFuzzTest(provider);
    OHOS::RemoveDeathRecipientFuzzTest(provider);
    OHOS::WriteTransactionFuzzTest(provider);
    return 0;
}
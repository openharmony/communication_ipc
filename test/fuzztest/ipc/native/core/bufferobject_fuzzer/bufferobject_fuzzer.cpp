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

#include "bufferobject_fuzzer.h"
#include "buffer_object.h"
#include "message_parcel.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
static constexpr size_t MAX_BYTES_SIZE = 50;

bool GetSendBufferAndLockTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t sendSize = provider.ConsumeIntegral<uint32_t>();
    char *sendBuffer = object.GetSendBufferAndLock(sendSize);
    if (sendBuffer == nullptr) {
        return false;
    }
    return true;
}

bool GetReceiveBufferAndLockTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t sendSize = provider.ConsumeIntegral<uint32_t>();
    char *sendBuffer = object.GetReceiveBufferAndLock(sendSize);
    if (sendBuffer == nullptr) {
        return false;
    }
    return true;
}

bool SetReceiveBufferWriteCursorTest(FuzzedDataProvider &provider)
{
    ssize_t cursor = provider.ConsumeIntegral<ssize_t>();
    BufferObject object;
    object.SetReceiveBufferWriteCursor(cursor);
    return true;
}

bool SetReceiveBufferReadCursorTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    ssize_t cursor = provider.ConsumeIntegral<ssize_t>();
    object.SetReceiveBufferReadCursor(cursor);
    return true;
}

bool SetSendBufferWriteCursorTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    ssize_t cursor = provider.ConsumeIntegral<ssize_t>();
    object.SetSendBufferWriteCursor(cursor);
    return true;
}

bool SetSendBufferReadCursorTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    ssize_t cursor = provider.ConsumeIntegral<ssize_t>();
    object.SetSendBufferReadCursor(cursor);
    return true;
}

bool GetNeedBufferSizeTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t sendSize = provider.ConsumeIntegral<uint32_t>();
    uint32_t ret = object.GetNeedBufferSize(sendSize);
    if (ret == 0) {
        return false;
    }
    return true;
}

bool UpdateSendBufferTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t sendSize = provider.ConsumeIntegral<uint32_t>();
    object.UpdateSendBuffer(sendSize);
    return true;
}

void GetNeedBufferSizeFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);

    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    size_t len = parcel.ReadUint64();

    BufferObject object;
    object.GetNeedBufferSize(len);
}

void GetReceiveBufferAndLockFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);

    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    size_t len = parcel.ReadUint64();

    BufferObject object;
    object.GetReceiveBufferAndLock(len);
}

void GetSendBufferAndLockFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);

    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    size_t len = parcel.ReadUint64();

    BufferObject object;
    object.GetSendBufferAndLock(len);
}

void SetReceiveBufferReadCursorFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);

    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    ssize_t cursor = parcel.ReadInt32();

    BufferObject object;
    object.SetReceiveBufferReadCursor(cursor);
}

void SetReceiveBufferWriteCursorFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);

    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    ssize_t cursor = parcel.ReadInt32();

    BufferObject object;
    object.SetReceiveBufferWriteCursor(cursor);
}

void SetSendBufferReadCursorFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);

    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    ssize_t cursor = parcel.ReadInt32();

    BufferObject object;
    object.SetSendBufferReadCursor(cursor);
}

void SetSendBufferWriteCursorFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);

    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    ssize_t cursor = parcel.ReadInt32();

    BufferObject object;
    object.SetSendBufferWriteCursor(cursor);
}

void UpdateSendBufferFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);

    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    size_t s = parcel.ReadUint64();

    BufferObject object;
    object.UpdateSendBuffer(s);
}

bool ReleaseSendBufferLockTest()
{
    BufferObject object;
    object.ReleaseSendBufferLock();
    return true;
}

bool ReleaseReceiveBufferLockTest()
{
    BufferObject object;
    object.ReleaseReceiveBufferLock();
    return true;
}

bool GetReceiveBufferWriteCursorTest()
{
    BufferObject object;
    ssize_t ret = object.GetReceiveBufferWriteCursor();
    if (ret == 0) {
        return false;
    }
    return true;
}

bool GetReceiveBufferReadCursorTest()
{
    BufferObject object;
    ssize_t ret = object.GetReceiveBufferReadCursor();
    if (ret == 0) {
        return false;
    }
    return true;
}

bool GetSendBufferWriteCursorTest()
{
    BufferObject object;
    ssize_t ret = object.GetSendBufferWriteCursor();
    if (ret == 0) {
        return false;
    }
    return true;
}

bool GetSendBufferReadCursorTest()
{
    BufferObject object;
    ssize_t ret = object.GetSendBufferReadCursor();
    if (ret == 0) {
        return false;
    }
    return true;
}

bool GetSendBufferSizeTest()
{
    BufferObject object;
    ssize_t ret = object.GetSendBufferSize();
    if (ret == 0) {
        return false;
    }
    return true;
}

bool GetRecvBufferSizeTest()
{
    BufferObject object;
    ssize_t ret = object.GetRecvBufferSize();
    if (ret == 0) {
        return false;
    }
    return true;
}

bool UpdateReceiveBufferTest()
{
    BufferObject object;
    object.UpdateReceiveBuffer();
    return true;
}

void FuzzerTestInner1(FuzzedDataProvider &provider)
{
    OHOS::UpdateSendBufferFuzzTest(provider);
    OHOS::ReleaseSendBufferLockTest();
    OHOS::GetReceiveBufferWriteCursorTest();
    OHOS::ReleaseReceiveBufferLockTest();
    OHOS::GetSendBufferSizeTest();
    OHOS::GetRecvBufferSizeTest();
    OHOS::UpdateReceiveBufferTest();
    OHOS::GetSendBufferReadCursorTest();
    OHOS::GetSendBufferWriteCursorTest();
    OHOS::GetReceiveBufferReadCursorTest();
}

void FuzzerTestInner2(FuzzedDataProvider &provider)
{
    OHOS::UpdateSendBufferTest(provider);
    OHOS::GetNeedBufferSizeFuzzTest(provider);
    OHOS::GetReceiveBufferAndLockFuzzTest(provider);
    OHOS::GetSendBufferAndLockFuzzTest(provider);
    OHOS::SetReceiveBufferReadCursorFuzzTest(provider);
    OHOS::SetReceiveBufferWriteCursorFuzzTest(provider);
    OHOS::SetSendBufferReadCursorFuzzTest(provider);
    OHOS::SetSendBufferWriteCursorFuzzTest(provider);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetSendBufferAndLockTest(provider);
    OHOS::GetReceiveBufferAndLockTest(provider);
    OHOS::SetReceiveBufferWriteCursorTest(provider);
    OHOS::SetReceiveBufferReadCursorTest(provider);
    OHOS::SetSendBufferWriteCursorTest(provider);
    OHOS::SetSendBufferReadCursorTest(provider);
    OHOS::GetNeedBufferSizeTest(provider);
    OHOS::FuzzerTestInner2(provider);
    OHOS::FuzzerTestInner1(provider);
    return 0;
}

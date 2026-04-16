/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <climits>

namespace OHOS {
static constexpr size_t MAX_BYTES_SIZE = 50;
static constexpr uint32_t HUGE_DATA_SIZE = 30 * 1024;

// ===== Old interface tests (deprecated, kept for compatibility) =====
// Note: These tests call deprecated interfaces, no changes needed

bool AcquireSendBufferTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t sendSize = provider.ConsumeIntegral<uint32_t>();
    SendBufferContext ctx = object.AcquireSendBuffer(sendSize);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ctx.lockGuard.Unlock();
    return true;
}

bool AcquireReceiveBufferTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t sendSize = provider.ConsumeIntegral<uint32_t>();
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(sendSize);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ctx.lockGuard.Unlock();
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

void AcquireReceiveBufferFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    size_t len = parcel.ReadUint64();
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(len);
    if (ctx.buffer != nullptr) {
        ctx.lockGuard.Unlock();
    }
}

void AcquireSendBufferFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    size_t len = parcel.ReadUint64();
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(len);
    if (ctx.buffer != nullptr) {
        ctx.lockGuard.Unlock();
    }
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

bool BufferLockGuardTest()
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    if (ctx.buffer != nullptr && ctx.lockGuard.IsLocked()) {
        ctx.lockGuard.Unlock();
        return true;
    }
    return false;
}

bool GetReceiveBufferWriteCursorTest()
{
    BufferObject object;
    ssize_t ret = object.GetReceiveBufferWriteCursor();
    return ret == 0;
}

bool GetReceiveBufferReadCursorTest()
{
    BufferObject object;
    ssize_t ret = object.GetReceiveBufferReadCursor();
    return ret == 0;
}

bool GetSendBufferWriteCursorTest()
{
    BufferObject object;
    ssize_t ret = object.GetSendBufferWriteCursor();
    return ret == 0;
}

bool GetSendBufferReadCursorTest()
{
    BufferObject object;
    ssize_t ret = object.GetSendBufferReadCursor();
    return ret == 0;
}

bool GetSendBufferSizeTest()
{
    BufferObject object;
    ssize_t ret = object.GetSendBufferSize();
    return ret == 0;
}

bool GetRecvBufferSizeTest()
{
    BufferObject object;
    ssize_t ret = object.GetRecvBufferSize();
    return ret == 0;
}

// ===== New interface tests (fixed issues) =====

// Fix 1: UpdateSendBufferLocked must be called with lock held via AcquireSendBuffer
bool UpdateSendBufferLockedTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t acquireSize = provider.ConsumeIntegral<uint32_t>();
    SendBufferContext ctx = object.AcquireSendBuffer(acquireSize);
    if (ctx.buffer == nullptr) {
        return false;
    }
    uint32_t userDataSize = provider.ConsumeIntegral<uint32_t>();
    char* result = object.UpdateSendBufferLocked(userDataSize);
    return result != nullptr;
}

bool UpdateReceiveBufferLockedTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t acquireSize = provider.ConsumeIntegral<uint32_t>();
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(acquireSize);
    if (ctx.buffer == nullptr) {
        return false;
    }
    uint32_t userDataSize = provider.ConsumeIntegral<uint32_t>();
    char* result = object.UpdateReceiveBufferLocked(userDataSize);
    return result != nullptr;
}

bool UpdateSendBufferLockedFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    size_t acquireSize = parcel.ReadUint64();
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(acquireSize);
    if (ctx.buffer == nullptr) {
        return false;
    }
    uint32_t userDataSize = parcel.ReadUint32();
    char* result = object.UpdateSendBufferLocked(userDataSize);
    return result != nullptr;
}

bool UpdateReceiveBufferLockedFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES_SIZE);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    MessageParcel parcel;
    parcel.WriteBuffer(bytes.data(), bytes.size());
    size_t acquireSize = parcel.ReadUint64();
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(acquireSize);
    if (ctx.buffer == nullptr) {
        return false;
    }
    uint32_t userDataSize = parcel.ReadUint32();
    char* result = object.UpdateReceiveBufferLocked(userDataSize);
    return result != nullptr;
}

bool ShrinkSendBufferIfNeededTest()
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_L);
    if (ctx.buffer == nullptr) {
        return false;
    }
    object.SetSendBufferWriteCursorEx(0);
    object.SetSendBufferReadCursorEx(0);
    object.ShrinkSendBufferIfNeeded();
    return object.GetSendBufferSizeEx() == static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S);
}

bool ShrinkReceiveBufferIfNeededTest()
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_L);
    if (ctx.buffer == nullptr) {
        return false;
    }
    object.SetReceiveBufferWriteCursorEx(0);
    object.SetReceiveBufferReadCursorEx(0);
    object.ShrinkReceiveBufferIfNeeded();
    return object.GetRecvBufferSizeEx() == static_cast<ssize_t>(SOCKET_BUFF_SIZE_USER_S);
}

// Fix 2: P0-3 vulnerability stress test - fragmented space + large write
// Simulate: writeCursor near end, readCursor not at start, request large userDataSize
// This triggers forced memmove when totalNeed > buffSize but not enough to expand
bool P03ForcedMemmoveStressTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_XL);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ssize_t buffSize = object.GetSendBufferSizeEx();
    ssize_t writeOffset = provider.ConsumeIntegralInRange<ssize_t>(0, buffSize - 8);
    ssize_t readOffset = provider.ConsumeIntegralInRange<ssize_t>(0, writeOffset);
    uint32_t userDataSize = provider.ConsumeIntegralInRange<uint32_t>(0, HUGE_DATA_SIZE);

    object.SetSendBufferWriteCursorEx(writeOffset);
    object.SetSendBufferReadCursorEx(readOffset);
    char* result = object.UpdateSendBufferLocked(userDataSize);
    return result != nullptr;
}

bool P03ReceiveBufferStressTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_XL);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ssize_t buffSize = object.GetRecvBufferSizeEx();
    ssize_t writeOffset = provider.ConsumeIntegralInRange<ssize_t>(0, buffSize - 8);
    ssize_t readOffset = provider.ConsumeIntegralInRange<ssize_t>(0, writeOffset);
    uint32_t userDataSize = provider.ConsumeIntegralInRange<uint32_t>(0, HUGE_DATA_SIZE);

    object.SetReceiveBufferWriteCursorEx(writeOffset);
    object.SetReceiveBufferReadCursorEx(readOffset);
    char* result = object.UpdateReceiveBufferLocked(userDataSize);
    return result != nullptr;
}

// Fix 3: Strict return value check - verify lock state on failure
bool AcquireSendBufferStrictTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t sendSize = provider.ConsumeIntegral<uint32_t>();
    SendBufferContext ctx = object.AcquireSendBuffer(sendSize);
    if (ctx.buffer == nullptr) {
        return !ctx.lockGuard.IsLocked();
    }
    ctx.lockGuard.Unlock();
    return true;
}

bool AcquireReceiveBufferStrictTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    uint32_t recvSize = provider.ConsumeIntegral<uint32_t>();
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(recvSize);
    if (ctx.buffer == nullptr) {
        return !ctx.lockGuard.IsLocked();
    }
    ctx.lockGuard.Unlock();
    return true;
}

// Fix 4: Cursor fuzz with buffer allocated first, then set extreme cursor
bool SetSendBufferWriteCursorExOutOfBoundsTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ssize_t cursor = provider.ConsumeIntegral<ssize_t>();
    bool result = object.SetSendBufferWriteCursorEx(cursor);
    return result;
}

bool SetSendBufferReadCursorExOutOfBoundsTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ssize_t cursor = provider.ConsumeIntegral<ssize_t>();
    bool result = object.SetSendBufferReadCursorEx(cursor);
    return result;
}

bool SetReceiveBufferWriteCursorExOutOfBoundsTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ssize_t cursor = provider.ConsumeIntegral<ssize_t>();
    bool result = object.SetReceiveBufferWriteCursorEx(cursor);
    return result;
}

bool SetReceiveBufferReadCursorExOutOfBoundsTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    ReceiveBufferContext ctx = object.AcquireReceiveBuffer(SOCKET_BUFF_SIZE_USER_S);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ssize_t cursor = provider.ConsumeIntegral<ssize_t>();
    bool result = object.SetReceiveBufferReadCursorEx(cursor);
    return result;
}

// Cursor overflow test - set cursor to INT64_MAX after allocating buffer
bool SetSendBufferCursorOverflowTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    if (ctx.buffer == nullptr) {
        return false;
    }
    ssize_t maxCursor = provider.ConsumeIntegral<ssize_t>();
    if (maxCursor < 0) {
        maxCursor = INT32_MAX;
    }
    bool writeResult = object.SetSendBufferWriteCursorEx(maxCursor);
    bool readResult = object.SetSendBufferReadCursorEx(maxCursor);
    return writeResult && readResult;
}

// RAII lock lifecycle test - simulate exception/early exit
bool RaiiLockLifecycleTest(FuzzedDataProvider &provider)
{
    BufferObject object;
    SendBufferContext ctx = object.AcquireSendBuffer(SOCKET_BUFF_SIZE_USER_S);
    if (ctx.buffer == nullptr) {
        return !ctx.lockGuard.IsLocked();
    }
    uint32_t userDataSize = provider.ConsumeIntegral<uint32_t>();
    char* result = object.UpdateSendBufferLocked(userDataSize);
    if (result == nullptr) {
        return !ctx.lockGuard.IsLocked();
    }
    return ctx.lockGuard.IsLocked();
}

void FuzzerTestInner1(FuzzedDataProvider &provider)
{
    OHOS::UpdateSendBufferLockedFuzzTest(provider);
    OHOS::BufferLockGuardTest();
    OHOS::GetReceiveBufferWriteCursorTest();
    OHOS::ShrinkSendBufferIfNeededTest();
    OHOS::ShrinkReceiveBufferIfNeededTest();
    OHOS::GetSendBufferSizeTest();
    OHOS::GetRecvBufferSizeTest();
    OHOS::UpdateReceiveBufferLockedTest(provider);
    OHOS::GetSendBufferReadCursorTest();
    OHOS::GetSendBufferWriteCursorTest();
    OHOS::GetReceiveBufferReadCursorTest();
}

void FuzzerTestInner2(FuzzedDataProvider &provider)
{
    OHOS::UpdateSendBufferLockedTest(provider);
    OHOS::GetNeedBufferSizeFuzzTest(provider);
    OHOS::AcquireReceiveBufferFuzzTest(provider);
    OHOS::AcquireSendBufferFuzzTest(provider);
    OHOS::SetReceiveBufferReadCursorFuzzTest(provider);
    OHOS::SetReceiveBufferWriteCursorFuzzTest(provider);
    OHOS::SetSendBufferReadCursorFuzzTest(provider);
    OHOS::SetSendBufferWriteCursorFuzzTest(provider);
}

void FuzzerTestInner3(FuzzedDataProvider &provider)
{
    OHOS::P03ForcedMemmoveStressTest(provider);
    OHOS::P03ReceiveBufferStressTest(provider);
    OHOS::AcquireSendBufferStrictTest(provider);
    OHOS::AcquireReceiveBufferStrictTest(provider);
    OHOS::SetSendBufferWriteCursorExOutOfBoundsTest(provider);
    OHOS::SetSendBufferReadCursorExOutOfBoundsTest(provider);
    OHOS::SetReceiveBufferWriteCursorExOutOfBoundsTest(provider);
    OHOS::SetReceiveBufferReadCursorExOutOfBoundsTest(provider);
    OHOS::SetSendBufferCursorOverflowTest(provider);
    OHOS::RaiiLockLifecycleTest(provider);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::AcquireSendBufferTest(provider);
    OHOS::AcquireReceiveBufferTest(provider);
    OHOS::SetReceiveBufferWriteCursorTest(provider);
    OHOS::SetReceiveBufferReadCursorTest(provider);
    OHOS::SetSendBufferWriteCursorTest(provider);
    OHOS::SetSendBufferReadCursorTest(provider);
    OHOS::GetNeedBufferSizeTest(provider);
    OHOS::FuzzerTestInner2(provider);
    OHOS::FuzzerTestInner1(provider);
    OHOS::FuzzerTestInner3(provider);
    return 0;
}
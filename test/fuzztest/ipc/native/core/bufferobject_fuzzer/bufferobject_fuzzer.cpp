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

namespace OHOS {
bool GetSendBufferAndLockTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return false;
    }

    BufferObject object;
    uint32_t sendSize = *(reinterpret_cast<const uint32_t*>(data));
    char *sendBuffer = object.GetSendBufferAndLock(sendSize);
    if (sendBuffer == nullptr) {
        return false;
    }
    return true;
}

bool GetReceiveBufferAndLockTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return false;
    }

    BufferObject object;
    uint32_t sendSize = *(reinterpret_cast<const uint32_t*>(data));
    char *sendBuffer = object.GetReceiveBufferAndLock(sendSize);
    if (sendBuffer == nullptr) {
        return false;
    }
    return true;
}

bool SetReceiveBufferWriteCursorTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(ssize_t)) {
        return false;
    }
    ssize_t cursor =  *(reinterpret_cast<const ssize_t*>(data));
    BufferObject object;
    object.SetReceiveBufferWriteCursor(cursor);
    return true;
}

bool SetReceiveBufferReadCursorTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(ssize_t)) {
        return false;
    }
    BufferObject object;
    ssize_t cursor =  *(reinterpret_cast<const ssize_t*>(data));
    object.SetReceiveBufferReadCursor(cursor);
    return true;
}

bool SetSendBufferWriteCursorTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(ssize_t)) {
        return false;
    }
    BufferObject object;
    ssize_t cursor =  *(reinterpret_cast<const ssize_t*>(data));
    object.SetSendBufferWriteCursor(cursor);
    return true;
}

bool SetSendBufferReadCursorTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(ssize_t)) {
        return false;
    }
    BufferObject object;
    ssize_t cursor =  *(reinterpret_cast<const ssize_t*>(data));
    object.SetSendBufferReadCursor(cursor);
    return true;
}

bool GetNeedBufferSizeTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return false;
    }
    BufferObject object;
    uint32_t sendSize = *(reinterpret_cast<const uint32_t*>(data));
    uint32_t ret = object.GetNeedBufferSize(sendSize);
    if (ret == 0) {
        return false;
    }
    return true;
}

bool UpdateSendBufferTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return false;
    }
    BufferObject object;
    uint32_t sendSize = *(reinterpret_cast<const uint32_t*>(data));
    object.UpdateSendBuffer(sendSize);
    return true;
}

void GetNeedBufferSizeFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    size_t len = parcel.ReadUint64();

    BufferObject object;
    object.GetNeedBufferSize(len);
}

void GetReceiveBufferAndLockFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    size_t len = parcel.ReadUint64();

    BufferObject object;
    object.GetReceiveBufferAndLock(len);
}

void GetSendBufferAndLockFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    size_t len = parcel.ReadUint64();

    BufferObject object;
    object.GetSendBufferAndLock(len);
}

void SetReceiveBufferReadCursorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    ssize_t cursor = parcel.ReadInt32();

    BufferObject object;
    object.SetReceiveBufferReadCursor(cursor);
}

void SetReceiveBufferWriteCursorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    ssize_t cursor = parcel.ReadInt32();

    BufferObject object;
    object.SetReceiveBufferWriteCursor(cursor);
}

void SetSendBufferReadCursorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    ssize_t cursor = parcel.ReadInt32();

    BufferObject object;
    object.SetSendBufferReadCursor(cursor);
}

void SetSendBufferWriteCursorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    ssize_t cursor = parcel.ReadInt32();

    BufferObject object;
    object.SetSendBufferWriteCursor(cursor);
}

void UpdateSendBufferFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
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

void FuzzerTestInner1(const uint8_t* data, size_t size)
{
    OHOS::UpdateSendBufferFuzzTest(data, size);
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
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::GetSendBufferAndLockTest(data, size);
    OHOS::GetReceiveBufferAndLockTest(data, size);
    OHOS::SetReceiveBufferWriteCursorTest(data, size);
    OHOS::SetReceiveBufferReadCursorTest(data, size);
    OHOS::SetSendBufferWriteCursorTest(data, size);
    OHOS::SetSendBufferReadCursorTest(data, size);
    OHOS::GetNeedBufferSizeTest(data, size);
    OHOS::UpdateSendBufferTest(data, size);
    OHOS::GetNeedBufferSizeFuzzTest(data, size);
    OHOS::GetReceiveBufferAndLockFuzzTest(data, size);
    OHOS::GetSendBufferAndLockFuzzTest(data, size);
    OHOS::SetReceiveBufferReadCursorFuzzTest(data, size);
    OHOS::SetReceiveBufferWriteCursorFuzzTest(data, size);
    OHOS::SetSendBufferReadCursorFuzzTest(data, size);
    OHOS::SetSendBufferWriteCursorFuzzTest(data, size);
    OHOS::FuzzerTestInner1(data, size);
    return 0;
}

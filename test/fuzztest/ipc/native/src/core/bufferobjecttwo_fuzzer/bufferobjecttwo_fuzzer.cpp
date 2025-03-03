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

#include "bufferobjecttwo_fuzzer.h"
#include "buffer_object.h"
#include "message_parcel.h"

namespace OHOS {
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
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::GetNeedBufferSizeFuzzTest(data, size);
    OHOS::GetReceiveBufferAndLockFuzzTest(data, size);
    OHOS::GetSendBufferAndLockFuzzTest(data, size);
    OHOS::SetReceiveBufferReadCursorFuzzTest(data, size);
    OHOS::SetReceiveBufferWriteCursorFuzzTest(data, size);
    OHOS::SetSendBufferReadCursorFuzzTest(data, size);
    OHOS::SetSendBufferWriteCursorFuzzTest(data, size);
    OHOS::UpdateSendBufferFuzzTest(data, size);
    return 0;
}

/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "buffer_object.h"

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

    bool ReleaseSendBufferLockTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        BufferObject object;
        object.ReleaseSendBufferLock();
        return true;
    }

    bool ReleaseReceiveBufferLockTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        BufferObject object;
        object.ReleaseReceiveBufferLock();
        return true;
    }

    bool GetReceiveBufferWriteCursorTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        BufferObject object;
        ssize_t ret = object.GetReceiveBufferWriteCursor();
        if (ret == 0) {
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

    bool GetReceiveBufferReadCursorTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        BufferObject object;
        ssize_t ret = object.GetReceiveBufferReadCursor();
        if (ret == 0) {
            return false;
        }
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

    bool GetSendBufferWriteCursorTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        BufferObject object;
        ssize_t ret = object.GetSendBufferWriteCursor();
        if (ret == 0) {
            return false;
        }
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

    bool GetSendBufferReadCursorTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        BufferObject object;
        ssize_t ret = object.GetSendBufferReadCursor();
        if (ret == 0) {
            return false;
        }
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

    bool GetSendBufferSizeTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        BufferObject object;
        ssize_t ret = object.GetSendBufferSize();
        if (ret == 0) {
            return false;
        }
        return true;
    }

    bool GetRecvBufferSizeTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }
        BufferObject object;
        ssize_t ret = object.GetRecvBufferSize();
        if (ret == 0) {
            return false;
        }
        return true;
    }

    bool UpdateReceiveBufferTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        BufferObject object;
        object.UpdateReceiveBuffer();
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
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetSendBufferAndLockTest(data, size);
    OHOS::GetReceiveBufferAndLockTest(data, size);
    OHOS::ReleaseSendBufferLockTest(data, size);
    OHOS::ReleaseReceiveBufferLockTest(data, size);
    OHOS::GetReceiveBufferWriteCursorTest(data, size);
    OHOS::SetReceiveBufferWriteCursorTest(data, size);
    OHOS::GetReceiveBufferReadCursorTest(data, size);
    OHOS::SetReceiveBufferReadCursorTest(data, size);
    OHOS::GetSendBufferWriteCursorTest(data, size);
    OHOS::SetSendBufferWriteCursorTest(data, size);
    OHOS::GetSendBufferReadCursorTest(data, size);
    OHOS::SetSendBufferReadCursorTest(data, size);
    OHOS::GetNeedBufferSizeTest(data, size);
    OHOS::GetSendBufferSizeTest(data, size);
    OHOS::GetRecvBufferSizeTest(data, size);
    OHOS::UpdateReceiveBufferTest(data, size);
    OHOS::UpdateSendBufferTest(data, size);
    return 0;
}

/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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


#include "serializer.h"
#include "serializer_inner.h"

#include <stdlib.h>
#include <string.h>
#include "rpc_log.h"
#include "securec.h"

#define ALIGN_SZ 4
#define IPC_IO_ALIGN(sz) (((sz) + ALIGN_SZ - 1) & (~(ALIGN_SZ - 1)))

#define IPC_IO_RETURN_IF_FAIL(value)                                             \
    do {                                                                         \
        if (!(value)) {                                                          \
            printf("IPC_CHECK failed: %s:%d\n", __FUNCTION__, __LINE__);        \
            if (io != NULL) {                                                    \
                io->flag |= IPC_IO_OVERFLOW;                                     \
            }                                                                    \
            return NULL;                                                         \
        }                                                                        \
    } while (0)


void IpcIoInit(IpcIo *io, void *buffer, size_t bufferSize, size_t maxobjects)
{
    if ((io == NULL) || (buffer == NULL) || (bufferSize == 0) ||
        (bufferSize > MAX_IO_SIZE) || (maxobjects > MAX_OBJ_NUM)) {
        return;
    }
    size_t objectsSize = maxobjects * sizeof(size_t);

    if (objectsSize > bufferSize) {
        io->flag = IPC_IO_OVERFLOW;
        io->bufferLeft = 0;
        io->offsetsLeft = 0;
        return;
    }

    io->bufferCur = io->bufferBase = (char *)buffer + objectsSize;
    io->offsetsCur = io->offsetsBase = (size_t *)buffer;
    io->bufferLeft = bufferSize - objectsSize;
    io->offsetsLeft = maxobjects;
    io->flag = IPC_IO_INITIALIZED;
}

static bool IpcIoAvailable(IpcIo *io)
{
    bool ret = false;
    if (io != NULL) {
        ret = (io->flag & IPC_IO_INITIALIZED) && !(io->flag & IPC_IO_OVERFLOW);
    }
    return ret;
}

void *IoPush(IpcIo *io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));
    size = IPC_IO_ALIGN(size);
    if (size > io->bufferLeft) {
        io->flag |= IPC_IO_OVERFLOW;
        RPC_LOG_ERROR("IoPush IPC_IO_OVERFLOW.");
        return NULL;
    } else {
        void *ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

void *IoPop(IpcIo *io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));
    size = IPC_IO_ALIGN(size);

    if (io->bufferLeft < size) {
        io->bufferLeft = 0;
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    } else {
        void *ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

static void *IoPushUnaligned(IpcIo *io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));
    if (size > io->bufferLeft) {
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    } else {
        void *ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

bool IpcIoAppend(IpcIo *dst, IpcIo *src)
{
    if (!IpcIoAvailable(dst) || !IpcIoAvailable(src)) {
        RPC_LOG_ERROR("IpcIo dst or src not available: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    size_t srcUsedBufferSize = src->bufferCur - src->bufferBase;
    size_t srcUsedOffsetsNum = src->offsetsCur - src->offsetsBase;
    if (srcUsedBufferSize == 0 && srcUsedOffsetsNum != 0) {
        RPC_LOG_ERROR("IpcIo src not available: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    if (dst->bufferLeft < srcUsedBufferSize || dst->offsetsLeft < srcUsedOffsetsNum) {
        RPC_LOG_ERROR("IpcIo dst buffer space is not enough: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    if (srcUsedBufferSize > 0) {
        char *ptr = (uint8_t *)IoPush(dst, srcUsedBufferSize);
        if (ptr == NULL) {
            return false;
        }
        size_t offsetAdjust = ptr - dst->bufferBase;
        if (memset_s(ptr, IPC_IO_ALIGN(srcUsedBufferSize), 0, IPC_IO_ALIGN(srcUsedBufferSize)) != EOK) {
            dst->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        if (memcpy_s(ptr, IPC_IO_ALIGN(srcUsedBufferSize), src->bufferBase, srcUsedBufferSize) != EOK) {
            dst->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        for (int i = 0; i < srcUsedOffsetsNum; i++) {
            dst->offsetsLeft--;
            *(dst->offsetsCur) = *(src->offsetsBase + i) + offsetAdjust;
            dst->offsetsCur++;
        }
    }
    return true;
}

bool WriteInt32(IpcIo *io, int32_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int32_t *ptr = (int32_t *)IoPush(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteUint32(IpcIo *io, uint32_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint32_t *ptr = (uint32_t *)IoPush(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteBool(IpcIo *io, bool value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    return WriteInt32(io, (int32_t)value);
}

bool WriteBoolUnaligned(IpcIo *io, bool value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    bool *ptr = (bool *)IoPushUnaligned(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WritePointer(IpcIo *io, uintptr_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uintptr_t *ptr = (uintptr_t *)IoPush(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteInt8(IpcIo *io, int8_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    return WriteInt32(io, (int32_t)value);
}

bool WriteInt8Unaligned(IpcIo *io, int8_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int8_t *ptr = (int8_t *)IoPushUnaligned(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteUint8(IpcIo *io, uint8_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    return WriteUint32(io, (uint32_t)value);
}

bool WriteUint8Unaligned(IpcIo *io,  uint8_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint8_t *ptr = (uint8_t *)IoPushUnaligned(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteInt16(IpcIo *io, int16_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    return WriteInt32(io, (int32_t)value);
}

bool WriteInt16Unaligned(IpcIo *io, int16_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int16_t *ptr = (int16_t *)IoPushUnaligned(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteUint16(IpcIo *io, uint16_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    return WriteUint32(io, (uint32_t)value);
}

bool WriteUint16Unaligned(IpcIo *io, uint16_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint16_t *ptr = (uint16_t *)IoPushUnaligned(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteInt64(IpcIo *io, int64_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int64_t *ptr = (int64_t *)IoPush(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteUint64(IpcIo *io, uint64_t value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint64_t *ptr = (uint64_t *)IoPush(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteFloat(IpcIo *io, float value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    float *ptr = (float *)IoPush(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteDouble(IpcIo *io, double value)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    double *ptr = (double *)IoPush(io, sizeof(value));
    if (ptr != NULL) {
        *ptr = value;
        return true;
    }
    return false;
}

bool WriteString(IpcIo *io, const char *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    unsigned char *str = (unsigned char *)value;
    size_t len;
    uint8_t *ptr = NULL;

    len = strnlen(value, MAX_IO_SIZE);
    if (len == MAX_IO_SIZE) {
        io->flag |= IPC_IO_OVERFLOW;
        return false;
    }
    /* Note: The payload will carry 32bit size instead of size_t */
    if (!WriteUint32(io, (uint32_t)len)) {
        return false;
    }

    ptr = (uint8_t *)IoPush(io, len + 1);
    if (ptr != NULL) {
        if (memset_s(ptr, IPC_IO_ALIGN(len + 1), 0, IPC_IO_ALIGN(len + 1)) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        if (memcpy_s(ptr, IPC_IO_ALIGN(len + 1), str, len + 1) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

static void *IoPopUnaligned(IpcIo *io, size_t size)
{
    IPC_IO_RETURN_IF_FAIL(io != NULL);
    IPC_IO_RETURN_IF_FAIL(IpcIoAvailable(io));

    if (io->bufferLeft < size) {
        io->bufferLeft = 0;
        io->flag |= IPC_IO_OVERFLOW;
        return NULL;
    } else {
        void *ptr = io->bufferCur;
        io->bufferCur += size;
        io->bufferLeft -= size;
        return ptr;
    }
}

bool ReadBool(IpcIo *io, bool *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    bool *ptr = (bool *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadBoolUnaligned(IpcIo *io, bool *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    bool *ptr = (bool *)IoPopUnaligned(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

uintptr_t ReadPointer(IpcIo *io)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uintptr_t *ptr = (uintptr_t *)IoPop(io, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

bool ReadInt8(IpcIo *io, int8_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int8_t *ptr = (int8_t *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadInt8Unaligned(IpcIo *io, int8_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int8_t *ptr = (int8_t *)IoPopUnaligned(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadUint8(IpcIo *io, uint8_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint8_t *ptr = (uint8_t *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadUInt8Unaligned(IpcIo *io, uint8_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint8_t *ptr = (uint8_t*)IoPopUnaligned(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadInt16(IpcIo *io, int16_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int16_t *ptr = (int16_t *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadInt16Unaligned(IpcIo *io, int16_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int16_t *ptr = (int16_t *)IoPopUnaligned(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadUint16(IpcIo *io, uint16_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint16_t *ptr = (uint16_t *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadUInt16Unaligned(IpcIo *io, uint16_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint16_t *ptr = (uint16_t *)IoPopUnaligned(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadInt32(IpcIo *io, int32_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int32_t *ptr = (int32_t *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadUint32(IpcIo *io, uint32_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint32_t *ptr = (uint32_t *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadInt64(IpcIo *io, int64_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    int64_t *ptr = (int64_t *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadUint64(IpcIo *io, uint64_t *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    uint64_t *ptr = (uint64_t*)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadFloat(IpcIo *io, float *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    float *ptr = (float *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

bool ReadDouble(IpcIo *io, double *value)
{
    if (io == NULL || value == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }
    double *ptr = (double *)IoPop(io, sizeof(*ptr));
    if (ptr != NULL) {
        *value = *ptr;
        return true;
    }
    return false;
}

uint8_t *ReadString(IpcIo *io, size_t *len)
{
    if (io == NULL) {
        RPC_LOG_ERROR("IPC io == NULL  failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    uint32_t value;
    bool ret = ReadUint32(io, &value);
    if (ret) {
        if (value > MAX_IO_SIZE) {
            return NULL;
        }
        if (len != NULL) {
            *len = value;
        }
    } else {
        RPC_LOG_ERROR("IPC ReadUint32 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    return (uint8_t *)IoPop(io, value + 1);
}

static bool WriteBufferAddTerminator(IpcIo *io, const void *value, size_t size, size_t sizeType)
{
    if (value == NULL || size < sizeType || io == NULL) {
        RPC_LOG_ERROR("IPC value == NULL || size < sizeType || io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    if (size > MAX_IO_SIZE) {
        RPC_LOG_ERROR("IPC size > MAX_IO_SIZE failed: %s:%d\n", __FUNCTION__, __LINE__);
        io->flag |= IPC_IO_OVERFLOW;
        return false;
    }

    size_t desireCapacity = IPC_IO_ALIGN(size);
    uint8_t *ptr = (uint8_t *)IoPush(io, desireCapacity);
    if (ptr != NULL) {
        if (memcpy_s(ptr, desireCapacity, value, size - sizeType) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        if (memset_s(ptr + (size - sizeType), desireCapacity - size + sizeType, 0,
            desireCapacity - size + sizeType) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }

        return true;
    }
    return false;
}

bool WriteString16(IpcIo *io, const uint16_t *value, size_t len)
{
    if (io == NULL || value == NULL || len <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || value == NULL || len <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    size_t typeSize = sizeof(uint16_t);
    size_t desireCapacity = (len + 1) * typeSize;

    if (desireCapacity > MAX_IO_SIZE) {
        io->flag |= IPC_IO_OVERFLOW;
        RPC_LOG_ERROR("IPC desireCapacity > MAX_IO_SIZE failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    /* Note: The payload will carry 32bit size instead of size_t */
    bool ret = WriteUint32(io, (uint32_t)len);
    if (ret) {
        ret = WriteBufferAddTerminator(io, value, desireCapacity, typeSize);
    }
    return ret;
}

bool WriteBuffer(IpcIo *io, const void *data, size_t size)
{
    if (data == NULL || size <= 0 || io == NULL) {
        RPC_LOG_ERROR("IPC data == NULL || size <= 0 || io == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    if (size > MAX_IO_SIZE) {
        RPC_LOG_ERROR("IPC size > MAX_IO_SIZE failed: %s:%d\n", __FUNCTION__, __LINE__);
        io->flag |= IPC_IO_OVERFLOW;
        return false;
    }

    size_t desireCapacity = IPC_IO_ALIGN(size);
    uint8_t *ptr = (uint8_t *)IoPush(io, desireCapacity);
    if (ptr != NULL) {
        if (memcpy_s(ptr, desireCapacity, data, size) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        if (memset_s(ptr + size, desireCapacity - size, 0, desireCapacity - size) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }

        return true;
    }
    return false;
}

bool WriteInterfaceToken(IpcIo *io, const uint16_t *name, size_t len)
{
    if (io == NULL || name == NULL || len <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || name == NULL || len <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    size_t typeSize = sizeof(uint16_t);
    size_t desireCapacity = (len + 1) * typeSize;

    if (desireCapacity > MAX_IO_SIZE) {
        io->flag |= IPC_IO_OVERFLOW;
        RPC_LOG_ERROR("IPC desireCapacity > MAX_IO_SIZE failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    return  WriteString16(io, name, len);
}

bool WriteRawData(IpcIo *io, const void *data, size_t size)
{
    if (io == NULL || data == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || data == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    if (size > MAX_IO_SIZE) {
        io->flag |= IPC_IO_OVERFLOW;
        RPC_LOG_ERROR("IPC size > MAX_IO_SIZE failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        ret = WriteBuffer(io, data, size);
    }
    return ret;
}

bool WriteBoolVector(IpcIo *io, const bool *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        for (int32_t i = 0; i != size; i++) {
            ret = WriteBool(io, val[i]);
            if (!ret) {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool WriteInt8Vector(IpcIo *io, const int8_t *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(int8_t);
        int8_t *ptr = (int8_t *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

bool WriteInt16Vector(IpcIo *io, const int16_t *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        for (int32_t i = 0; i != size; i++) {
            ret = WriteInt16(io, val[i]);
            if (!ret) {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool WriteInt32Vector(IpcIo *io, const int32_t *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(int32_t);
        int32_t *ptr = (int32_t *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

bool WriteInt64Vector(IpcIo *io, const int64_t *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(int64_t);
        int64_t *ptr = (int64_t *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

bool WriteUInt8Vector(IpcIo *io, const uint8_t *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(uint8_t);
        uint8_t *ptr = (uint8_t *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

bool WriteUInt16Vector(IpcIo *io, const uint16_t *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(uint16_t);
        uint16_t *ptr = (uint16_t *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

bool WriteUInt32Vector(IpcIo *io, const uint32_t *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(uint32_t);
        uint32_t *ptr = (uint32_t *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

bool WriteUInt64Vector(IpcIo *io, const uint64_t *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(uint64_t);
        uint64_t *ptr = (uint64_t *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

bool WriteFloatVector(IpcIo *io, const float *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(float);
        float *ptr = (float *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

bool WriteDoubleVector(IpcIo *io, const double *val, size_t size)
{
    if (io == NULL || val == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || val == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return false;
    }

    bool ret = WriteUint32(io, (uint32_t)size);
    if (ret) {
        size_t desireCapacity = size * sizeof(double);
        double *ptr = (double *)IoPushUnaligned(io, desireCapacity);
        if (ptr == NULL) {
            return false;
        }

        if (memcpy_s(ptr, desireCapacity, val, desireCapacity) != EOK) {
            io->flag |= IPC_IO_OVERFLOW;
            return false;
        }
        return true;
    }
    return false;
}

uint16_t *ReadString16(IpcIo *io, size_t *len)
{
    if (io == NULL || len == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || len == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)len);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = (*len + 1) * sizeof(uint16_t);
    uint16_t *ptr = (uint16_t *)IoPop(io, readCapacity);
    if (ptr[*len] == 0) {
        return ptr;
    } else {
        return NULL;
    }
}

uint16_t *ReadInterfaceToken(IpcIo *io, size_t *len)
{
    if (io == NULL || len == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || len == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)len);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = (*len + 1) * sizeof(uint16_t);
    uint16_t *ptr = (uint16_t *)IoPop(io, readCapacity);
    if (ptr != NULL && ptr[*len] == 0) {
        return ptr;
    } else {
        return NULL;
    }
}

const uint8_t *ReadBuffer(IpcIo *io, size_t size)
{
    if (io == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    return (uint8_t *)IoPop(io, size);
}

void *ReadRawData(IpcIo *io, size_t size)
{
    if (io == NULL || size <= 0) {
        RPC_LOG_ERROR("IPC io == NULL || size <= 0 failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    uint32_t len = 0;
    ReadUint32(io, &len);
    if (len != (uint32_t)size) {
        return NULL;
    }
    return (void *)ReadBuffer(io, (size_t)len);
}

bool *ReadBoolVector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    bool *val = (bool *)malloc((*size) * sizeof(bool));
    if (val == NULL) {
        RPC_LOG_ERROR("IPC malloc failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    int32_t *ptr = NULL;
    for (int32_t i = 0; i != *size; i++) {
        ptr = (int32_t *)IoPop(io, sizeof(int32_t));
        if (ptr == NULL) {
            free(val);
            return NULL;
        }
        val[i] = (bool)(*ptr);
    }
    return val;
}

int8_t *ReadInt8Vector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(int8_t);
    int8_t *ptr = (int8_t *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

int16_t *ReadInt16Vector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    int16_t *val = (int16_t *)calloc(1, (*size) * sizeof(int16_t));
    if (val == NULL) {
        RPC_LOG_ERROR("IPC  malloc failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    int32_t *ptr = NULL;
    for (int32_t i = 0; i != *size; i++) {
        ptr = (int32_t *)IoPop(io, sizeof(int32_t));
        if (ptr == NULL) {
            free(val);
            return NULL;
        }
        val[i] = (int16_t)(*ptr);
    }
    return val;
}

int32_t *ReadInt32Vector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(int32_t);
    int32_t *ptr = (int32_t *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

int64_t *ReadInt64Vector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(int64_t);
    int64_t *ptr = (int64_t *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

uint8_t *ReadUInt8Vector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(uint8_t);
    uint8_t *ptr = (uint8_t *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

uint16_t *ReadUInt16Vector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(uint16_t);
    uint16_t *ptr = (uint16_t *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

uint32_t *ReadUInt32Vector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(uint32_t);
    uint32_t *ptr = (uint32_t *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

uint64_t *ReadUInt64Vector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(uint64_t);
    uint64_t *ptr = (uint64_t *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

float *ReadFloatVector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(float);
    float *ptr = (float *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

double *ReadDoubleVector(IpcIo *io, size_t *size)
{
    if (io == NULL || size == NULL) {
        RPC_LOG_ERROR("IPC io == NULL || size == NULL failed: %s:%d\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    bool ret = ReadUint32(io, (uint32_t *)size);
    if (!ret) {
        return NULL;
    }

    size_t readCapacity = *size * sizeof(double);
    double *ptr = (double *)IoPopUnaligned(io, readCapacity);
    if (ptr == NULL) {
        return NULL;
    }

    return ptr;
}

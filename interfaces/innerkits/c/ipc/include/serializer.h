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

#ifndef OHOS_IPC_RPC_SERIALIZER_H
#define OHOS_IPC_RPC_SERIALIZER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    char *bufferBase;
    size_t *offsetsBase;
    char *bufferCur;
    size_t *offsetsCur;
    size_t bufferLeft;
    size_t offsetsLeft;
    uint32_t flag;
} IpcIo;

typedef struct {
    int32_t handle;
    uintptr_t token;
    uintptr_t cookie;
} SvcIdentity;

typedef enum {
    SERVICE_TYPE_ANONYMOUS,
    SERVICE_TYPE_NORMAL
} ServiceType;

#define IPC_INVALID_HANDLE (-1)
#define IPC_IO_INITIALIZED 0x01 /* ipc flag indicates whether io is initialized */
#define IPC_IO_OVERFLOW    0x02 /* ipc flag indicates whether io is running out of space */
#define MAX_IO_SIZE 8192UL
#define MAX_OBJ_NUM 32UL

void IpcIoInit(IpcIo* io, void* buffer, size_t bufferSize, size_t maxobjects);
bool IpcIoAppend(IpcIo *dst, IpcIo *src);

bool WriteRemoteObject(IpcIo *io, const SvcIdentity *svc);
bool WriteFileDescriptor(IpcIo *io, uint32_t fd);

bool ReadRemoteObject(IpcIo *io, SvcIdentity *svc);
int32_t ReadFileDescriptor(IpcIo *io);

bool WriteBool(IpcIo *io, bool value);
bool WriteInt8(IpcIo *io, int8_t value);
bool WriteInt16(IpcIo *io, int16_t value);
bool WriteInt32(IpcIo *io, int32_t value);
bool WriteInt64(IpcIo *io, int64_t value);
bool WriteUint8(IpcIo *io, uint8_t value);
bool WriteUint16(IpcIo *io, uint16_t value);
bool WriteUint32(IpcIo *io, uint32_t value);
bool WriteUint64(IpcIo *io, uint64_t value);
bool WriteBoolUnaligned(IpcIo *io, bool value);
bool WriteInt8Unaligned(IpcIo *io, int8_t value);
bool WriteInt16Unaligned(IpcIo *io, int16_t value);
bool WriteUint8Unaligned(IpcIo *io, uint8_t value);
bool WriteUint16Unaligned(IpcIo *io, uint16_t value);
bool WriteFloat(IpcIo *io, float value);
bool WriteDouble(IpcIo *io, double value);
bool WritePointer(IpcIo *io, uintptr_t value);
bool WriteString(IpcIo *io, const char *value);

bool ReadBool(IpcIo *io, bool *value);
bool ReadInt8(IpcIo *io, int8_t *value);
bool ReadInt16(IpcIo *io, int16_t *value);
bool ReadInt32(IpcIo *io, int32_t *value);
bool ReadInt64(IpcIo *io, int64_t *value);
bool ReadUint8(IpcIo *io, uint8_t *value);
bool ReadUint16(IpcIo *io, uint16_t *value);
bool ReadUint32(IpcIo *io, uint32_t *value);
bool ReadUint64(IpcIo *io, uint64_t *value);
bool ReadFloat(IpcIo *io, float *value);
bool ReadDouble(IpcIo *io, double *value);
uintptr_t ReadPointer(IpcIo *io);
bool ReadBoolUnaligned(IpcIo *io, bool *value);
bool ReadInt8Unaligned(IpcIo *io, int8_t *value);
bool ReadInt16Unaligned(IpcIo *io, int16_t *value);
bool ReadUInt8Unaligned(IpcIo *io, uint8_t *value);
bool ReadUInt16Unaligned(IpcIo *io, uint16_t *value);
uint8_t *ReadString(IpcIo *io, size_t *len);

bool WriteString16(IpcIo *io, const uint16_t *value, size_t len);
bool WriteBuffer(IpcIo *io, const void *data, size_t size);
bool WriteInterfaceToken(IpcIo *io, const uint16_t *name, size_t len);
bool WriteRawData(IpcIo *io, const void *data, size_t size);
bool WriteBoolVector(IpcIo *io, const bool *val, size_t size);
bool WriteInt8Vector(IpcIo *io, const int8_t *val, size_t size);
bool WriteInt16Vector(IpcIo *io, const int16_t *val, size_t size);
bool WriteInt32Vector(IpcIo *io, const int32_t *val, size_t size);
bool WriteInt64Vector(IpcIo *io, const int64_t *val, size_t size);
bool WriteUInt8Vector(IpcIo *io, const uint8_t *val, size_t size);
bool WriteUInt16Vector(IpcIo *io, const uint16_t *val, size_t size);
bool WriteUInt32Vector(IpcIo *io, const uint32_t *val, size_t size);
bool WriteUInt64Vector(IpcIo *io, const uint64_t *val, size_t size);
bool WriteFloatVector(IpcIo *io, const float *val, size_t size);
bool WriteDoubleVector(IpcIo *io, const double *val, size_t size);

uint16_t *ReadString16(IpcIo *io, size_t *size);
uint16_t *ReadInterfaceToken(IpcIo *io, size_t *size);
const uint8_t *ReadBuffer(IpcIo *io, size_t size);
void *ReadRawData(IpcIo *io, size_t size);
bool *ReadBoolVector(IpcIo *io, size_t *size);
int8_t *ReadInt8Vector(IpcIo *io, size_t *size);
int16_t *ReadInt16Vector(IpcIo *io, size_t *size);
int32_t *ReadInt32Vector(IpcIo *io, size_t *size);
int64_t *ReadInt64Vector(IpcIo *io, size_t *size);
uint8_t *ReadUInt8Vector(IpcIo *io, size_t *size);
uint16_t *ReadUInt16Vector(IpcIo *io, size_t *size);
uint32_t *ReadUInt32Vector(IpcIo *io, size_t *size);
uint64_t *ReadUInt64Vector(IpcIo *io, size_t *size);
float *ReadFloatVector(IpcIo *io, size_t *size);
double *ReadDoubleVector(IpcIo *io, size_t *size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_IPC_RPC_SERIALIZER_H */

/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
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
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef struct {
    char* bufferBase;
    size_t* offsetsBase;
    char* bufferCur;
    size_t* offsetsCur;
    size_t bufferLeft;
    size_t offsetsLeft;
    uint32_t flag;
} IpcIo;

typedef struct {
    int32_t handle;  // 是否按原ipc格式改成联合体
    uintptr_t token;
    uintptr_t cookie;
} SvcIdentity;

#define MIN_BINDER_HANDLE (-1)
#define IPC_IO_INITIALIZED 0x01 /* ipc flag indicates whether io is initialized */
#define IPC_IO_OVERFLOW    0x02 /* ipc flag indicates whether io is running out of space */

/* allocate a IpcIo, providing a stack-allocated working
 * buffer, size of the working buffer, and how many object
 * offset entries to reserve from the buffer
 */
void IpcIoInit(IpcIo* io, void* data, size_t maxdata, size_t maxobjects);
/* Must ensure all the input is valid */
void IpcIoPushChar(IpcIo* io, char c);
void IpcIoPushCharUnaligned(IpcIo* io, char c);
void IpcIoPushBool(IpcIo* io, bool b);
void IpcIoPushBoolUnaligned(IpcIo* io, bool b);
void IpcIoPushIntptr(IpcIo* io, intptr_t n);
void IpcIoPushUintptr(IpcIo* io, uintptr_t n);
void IpcIoPushInt8(IpcIo* io, int8_t n);
void IpcIoPushInt8Unaligned(IpcIo* io, int8_t n);
void IpcIoPushUint8(IpcIo* io, uint8_t n);
void IpcIoPushUint8Unaligned(IpcIo* io, uint8_t n);
void IpcIoPushInt16(IpcIo* io, int16_t n);
void IpcIoPushInt16Unaligned(IpcIo* io, int16_t n);
void IpcIoPushUint16(IpcIo* io, uint16_t n);
void IpcIoPushUint16Unaligned(IpcIo* io, uint16_t n);
void IpcIoPushInt32(IpcIo* io, int32_t n);
void IpcIoPushUint32(IpcIo* io, uint32_t n);
void IpcIoPushInt64(IpcIo* io, int64_t n);
void IpcIoPushUint64(IpcIo* io, uint64_t n);
void IpcIoPushFloat(IpcIo* io, float n);
void IpcIoPushDouble(IpcIo* io, double n);
void IpcIoPushString(IpcIo* io, const char* cstr);
void IpcIoPushFlatObj(IpcIo* io, const void* obj, uint32_t size);
bool IpcIoPushSvc(IpcIo* io, const SvcIdentity* svc);
bool IpcIoPushFd(IpcIo* io, uint32_t fd);

char IpcIoPopChar(IpcIo* io);
char IpcIoPopCharUnaligned(IpcIo* io);
bool IpcIoPopBool(IpcIo* io);
bool IpcIoPopBoolUnaligned(IpcIo* io);
intptr_t IpcIoPopIntptr(IpcIo* io);
uintptr_t IpcIoPopUintptr(IpcIo* io);
int8_t IpcIoPopInt8(IpcIo* io);
int8_t IpcIoPopInt8Unaligned(IpcIo* io);
uint8_t IpcIoPopUint8(IpcIo* io);
uint8_t IpcIoPopUint8Unaligned(IpcIo* io);
int16_t IpcIoPopInt16(IpcIo* io);
int16_t IpcIoPopInt16Unaligned(IpcIo* io);
uint16_t IpcIoPopUint16(IpcIo* io);
uint16_t IpcIoPopUint16Unaligned(IpcIo* io);
int32_t IpcIoPopInt32(IpcIo* io);
uint32_t IpcIoPopUint32(IpcIo* io);
int64_t IpcIoPopInt64(IpcIo* io);
uint64_t IpcIoPopUint64(IpcIo* io);
float IpcIoPopFloat(IpcIo* io);
double IpcIoPopDouble(IpcIo* io);
uint8_t* IpcIoPopString(IpcIo* io, size_t* sz);
void* IpcIoPopFlatObj(IpcIo* io, uint32_t* size);
bool IpcIoPopSvc(IpcIo* io, SvcIdentity* svc);
int32_t IpcIoPopFd(IpcIo* io);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* OHOS_IPC_RPC_SERIALIZER_H */

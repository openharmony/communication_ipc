/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef IPC_C_PARCEL_H
#define IPC_C_PARCEL_H

#include "c_ashmem.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

struct MessageParcelHolder;
typedef struct MessageParcelHolder CParcel;

struct CRemoteObjectHolder;
typedef struct CRemoteObjectHolder CRemoteObject;

typedef bool (*OnCParcelBytesAllocator)(void *stringData, char **buffer, int32_t len);
typedef bool (*OnCParcelBoolAllocator)(void *value, bool **buffer, int32_t len);
typedef bool (*OnCParcelInt8Allocator)(void *value, int8_t **buffer, int32_t len);
typedef bool (*OnCParcelInt16Allocator)(void *value, int16_t **buffer, int32_t len);
typedef bool (*OnCParcelInt32Allocator)(void *value, int32_t **buffer, int32_t len);
typedef bool (*OnCParcelInt64Allocator)(void *value, int64_t **buffer, int32_t len);
typedef bool (*OnCParcelFloatAllocator)(void *value, float **buffer, int32_t len);
typedef bool (*OnCParcelDoubleAllocator)(void *value, double **buffer, int32_t len);
typedef bool (*OnCParcelAllocator)(void *value, int32_t len);
typedef bool (*OnStringArrayWrite)(const void *array, const void *value, uint32_t len);
typedef bool (*OnStringArrayRead)(const void *array, const void *value, uint32_t len);
typedef bool (*OnCParcelWriteElement)(CParcel *value, const void *arr, unsigned long index);
typedef bool (*OnCParcelReadElement)(const CParcel *value, void *arr, unsigned long index);

CParcel *CParcelObtain(void);
void CParcelIncStrongRef(CParcel *parcel);
void CParcelDecStrongRef(CParcel *parcel);

bool CParcelWriteBool(CParcel *parcel, bool value);
bool CParcelReadBool(const CParcel *parcel, bool *value);
bool CParcelWriteInt8(CParcel *parcel, int8_t value);
bool CParcelReadInt8(const CParcel *parcel, int8_t *value);
bool CParcelWriteInt16(CParcel *parcel, int16_t value);
bool CParcelReadInt16(const CParcel *parcel, int16_t *value);
bool CParcelWriteInt32(CParcel *parcel, int32_t value);
bool CParcelReadInt32(const CParcel *parcel, int32_t *value);
bool CParcelWriteInt64(CParcel *parcel, int64_t value);
bool CParcelReadInt64(const CParcel *parcel, int64_t *value);
bool CParcelWriteFloat(CParcel *parcel, float value);
bool CParcelReadFloat(const CParcel *parcel, float *value);
bool CParcelWriteDouble(CParcel *parcel, double value);
bool CParcelReadDouble(const CParcel *parcel, double *value);
bool CParcelWriteString(CParcel *parcel, const char *stringData, int32_t length);
bool CParcelReadString(const CParcel *parcel, void *stringData, OnCParcelBytesAllocator allocator);
bool CParcelWriteString16(CParcel *parcel, const char *str, int32_t strLen);
bool CParcelReadString16(const CParcel *parcel, void *stringData, OnCParcelBytesAllocator allocator);
bool CParcelWriteInterfaceToken(CParcel *parcel, const char *token, int32_t tokenLen);
bool CParcelReadInterfaceToken(const CParcel *parcel, void *token, OnCParcelBytesAllocator allocator);
bool CParcelWriteRemoteObject(CParcel *parcel, const CRemoteObject *object);
CRemoteObject *CParcelReadRemoteObject(const CParcel *parcel);
bool CParcelWriteFileDescriptor(CParcel *parcel, int32_t fd);
bool CParcelReadFileDescriptor(const CParcel *parcel, int32_t *fd);
bool CParcelWriteBuffer(CParcel *parcel, const uint8_t *buffer, uint32_t len);
bool CParcelReadBuffer(const CParcel *parcel, uint8_t *value, uint32_t len);
bool CParcelWriteRawData(CParcel *parcel, const uint8_t *buffer, uint32_t len);
const uint8_t *CParcelReadRawData(const CParcel *parcel, uint32_t len);

bool CParcelWriteBoolArray(CParcel *parcel, const bool *array, int32_t len);
bool CParcelReadBoolArray(const CParcel *parcel, void *value, OnCParcelBoolAllocator allocator);
bool CParcelWriteInt8Array(CParcel *parcel, const int8_t *array, int32_t len);
bool CParcelReadInt8Array(const CParcel *parcel, void *value, OnCParcelInt8Allocator allocator);
bool CParcelWriteInt16Array(CParcel *parcel, const int16_t *array, int32_t len);
bool CParcelReadInt16Array(const CParcel *parcel, void *value, OnCParcelInt16Allocator allocator);
bool CParcelWriteInt32Array(CParcel *parcel, const int32_t *array, int32_t len);
bool CParcelReadInt32Array(const CParcel *parcel, void *value, OnCParcelInt32Allocator allocator);
bool CParcelWriteInt64Array(CParcel *parcel, const int64_t *array, int32_t len);
bool CParcelReadInt64Array(const CParcel *parcel, void *value, OnCParcelInt64Allocator allocator);
bool CParcelWriteFloatArray(CParcel *parcel, const float *array, int32_t len);
bool CParcelReadFloatArray(const CParcel *parcel, void *value, OnCParcelFloatAllocator allocator);
bool CParcelWriteDoubleArray(CParcel *parcel, const double *array, int32_t len);
bool CParcelReadDoubleArray(const CParcel *parcel, void *value, OnCParcelDoubleAllocator allocator);
bool CParcelWriteStringArray(CParcel *parcel, const void *value,
    int32_t len, OnStringArrayWrite writer);
bool CParcelWriteStringElement(void *data, const char *value, int32_t len);
bool CParcelReadStringArray(const CParcel *parcel, void *value, OnStringArrayRead reader);
bool CParcelReadStringElement(uint32_t index, const void *data, void *value,
    OnCParcelBytesAllocator allocator);

bool CParcelWriteParcelableArray(CParcel *parcel, const void *value, int32_t len,
    OnCParcelWriteElement elementWriter);
bool CParcelReadParcelableArray(const CParcel *parcel, void *value,
    OnCParcelAllocator allocator, OnCParcelReadElement elementReader);

uint32_t CParcelGetDataSize(const CParcel *parcel);
bool CParcelSetDataSize(CParcel *parcel, uint32_t new_size);
uint32_t CParcelGetDataCapacity(const CParcel *parcel);
bool CParcelSetDataCapacity(CParcel *parcel, uint32_t new_size);
uint32_t CParcelGetMaxCapacity(const CParcel *parcel);
bool CParcelSetMaxCapacity(CParcel *parcel, uint32_t new_size);
uint32_t CParcelGetWritableBytes(const CParcel *parcel);
uint32_t CParcelGetReadableBytes(const CParcel *parcel);
uint32_t CParcelGetReadPosition(const CParcel *parcel);
uint32_t CParcelGetWritePosition(const CParcel *parcel);
bool CParcelRewindRead(CParcel *parcel, uint32_t new_pos);
bool CParcelRewindWrite(CParcel *parcel, uint32_t new_pos);

bool CParcelWriteAshmem(CParcel *parcel, CAshmem *ashmem);
CAshmem *CParcelReadAshmem(const CParcel *parcel);

#ifdef __cplusplus
}
#endif
#endif /* IPC_C_PARCEL_H */

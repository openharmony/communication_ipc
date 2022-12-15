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

#ifdef __cplusplus
}
#endif
#endif /* IPC_C_PARCEL_H */
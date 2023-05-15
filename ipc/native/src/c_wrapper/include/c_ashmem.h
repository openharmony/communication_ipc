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

#ifndef IPC_C_ASHMEM_H
#define IPC_C_ASHMEM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct CAshmem;
typedef struct CAshmem CAshmem;

CAshmem *CreateCAshmem(const char *name, int32_t size);
void CAshmemIncStrongRef(CAshmem *ashmem);
void CAshmemDecStrongRef(CAshmem *ashmem);

void CloseCAshmem(CAshmem *ashmem);
bool MapCAshmem(CAshmem *ashmem, int32_t mapType);
bool MapReadAndWriteCAshmem(CAshmem *ashmem);
bool MapReadOnlyCAshmem(CAshmem *ashmem);
void UnmapCAshmem(CAshmem *ashmem);
bool SetCAshmemProtection(CAshmem *ashmem, int32_t protectionType);
int32_t GetCAshmemProtection(const CAshmem *ashmem);
int32_t GetCAshmemSize(const CAshmem *ashmem);
bool WriteToCAshmem(CAshmem *ashmem, const uint8_t *data, int32_t size, int32_t offset);
const uint8_t *ReadFromCAshmem(const CAshmem *ashmem, int32_t size, int32_t offset);
int32_t GetCAshmemFd(const CAshmem *ashmem);

#ifdef __cplusplus
}
#endif
#endif /* IPC_C_ASHMEM_H */

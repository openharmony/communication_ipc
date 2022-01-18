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

#ifndef OHOS_RPC_DBINDER_STUB_H
#define OHOS_RPC_DBINDER_STUB_H

#include <stdint.h>
#include <stdlib.h>

#include "dbinder_types.h"
#include "serializer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    UTILS_DL_LIST list;
    char serviceName[SERVICENAME_LENGTH + 1];
    char deviceID[DEVICEID_LENGTH + 1];
    uintptr_t binderObject;
    SvcIdentity svc;
} DBinderServiceStub;

int32_t GetDBinderStub(const char *serviceName, const char *deviceID,
    uintptr_t binderObject, DBinderServiceStub *dBinderServiceStub);

#ifdef __cplusplus
}
#endif
#endif // OHOS_RPC_DBINDER_STUB_H
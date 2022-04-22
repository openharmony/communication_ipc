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

#ifndef DBINDER_SERVICE_H
#define DBINDER_SERVICE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t StartDBinderService(void);
int32_t RegisterRemoteProxy(const void *name, uint32_t len, int32_t systemAbility);
int32_t MakeRemoteBinder(const void *serviceName, uint32_t nameLen, const char *deviceID, uint32_t idLen,
    uintptr_t binderObject, uint64_t pid, void *remoteObject);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* DBINDER_SERVICE_H */
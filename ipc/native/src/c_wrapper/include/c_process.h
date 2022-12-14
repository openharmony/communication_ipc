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

#ifndef IPC_C_PROCESS_H
#define IPC_C_PROCESS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "c_remote_object.h"

CRemoteObject *GetContextManager(void);
void JoinWorkThread(void);

void InitTokenId(void);

#ifdef __cplusplus
}
#endif
#endif /* IPC_C_PROCESS_H */
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef IPC_SKELETON_IMPL_H
#define IPC_SKELETON_IMPL_H

#include <cinttypes>

#include "cj_common_ffi.h"

namespace OHOS {
RetDataI64 GetContextObject();
uint32_t GetCallingTokenId();
char* GetCallingDeviceID();
char* GetLocalDeviceID();
bool IsLocalCalling();
void FlushCmdBuffer(int64_t object);
} // namespace OHOS
#endif
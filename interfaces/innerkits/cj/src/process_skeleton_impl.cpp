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

#include "process_skeleton_impl.h"

#include "iremote_invoker.h"

namespace OHOS {
int32_t GetCallingPid()
{
    pid_t pid = getpid();
    return static_cast<int32_t>(pid);
}

int32_t GetCallingUid()
{
    uint32_t uid = getuid();
    return static_cast<int32_t>(uid);
}
} // namespace OHOS
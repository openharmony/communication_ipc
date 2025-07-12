/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_TAIHE_IPC_SKELETON_H
#define OHOS_IPC_TAIHE_IPC_SKELETON_H

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <cinttypes>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "ipc_skeleton.h"

namespace OHOS {

class IPCSkeletonImpl {
public:
    static int32_t GetCallingPid();
    static int32_t GetCallingUid();
    static int64_t GetCallingTokenId();

    static ::ohos::rpc::rpc::IRemoteObjectUnion GetContextObject();
};

} // namespace

#endif // OHOS_IPC_TAIHE_IPC_SKELETON_H
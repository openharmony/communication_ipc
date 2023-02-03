/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <string>
#include <dlfcn.h>

#include "log_tags.h"
#include "ipc_debug.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC, "ipc_core_so_init" };

extern "C" __attribute__((constructor)) void init(void) {
    std::string path = std::string("libclang_rt.ubsan_standalone.so");
    void *handle = dlopen(path.c_str(), RTLD_NOW);
    if (handle == nullptr) {
        ZLOGE(LOG_LABEL, "ipc_core.so init fail");
    }
}
} // namespace OHOS
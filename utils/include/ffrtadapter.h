/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_UTIL_FFRTADAPTER_H
#define OHOS_IPC_UTIL_FFRTADAPTER_H
#include <dlfcn.h>
#include <string>
#include "log_tags.h"
#include "ipc_debug.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_BASE, "ipc_ffrt_object" }
void ffrt_this_task_set_legacy_mode(bool mode);
using FfrtTaskSetLegacyModeType = decltype(ffrt_this_task_set_legacy_mode)*;
#ifdef __aarch64__
static const std::string FFRT_LIB_PATH = "/system/lib64/chipset-sdk/libffrt.so";
#else
static const std::string FFRT_LIB_PATH = "/system/lib/chipset-sdk/libffrt.so";
#endif

class FFRTAdapter {
public:
    FFRTAdapter()
    {
        Load();
    }
    ~FFRTAdapter()
    {
    }
    static FFRTAdapter* Instance()
    {
        static FFRTAdapter instance;
        return &instance;
    }
    FfrtTaskSetLegacyModeType FfrtTaskSetLegacyMode = nullptr;
private:
    void Load()
    {
        if (handle != nullptr) {
            return;
        }

        handle = dlopen(FFRT_LIB_PATH.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (handle == nullptr) {
            ZLOGE(LOG_LABEL, "ffrt lib handle is null.");
            return;
        }

        FfrtTaskSetLegacyMode = reinterpret_cast<FfrtTaskSetLegacyModeType>(
            dlsym(handle, "ffrt_this_task_set_legacy_mode"));
        if (FfrtTaskSetLegacyMode == nullptr) {
            ZLOGE(LOG_LABEL, "get ffrt_this_task_set_legacy_mode symbol fail.");
            return;
        }
    }

    void* handle = nullptr;
};
} // namespace OHOS
#endif // OHOS_IPC_UTIL_FFRTADAPTER_H
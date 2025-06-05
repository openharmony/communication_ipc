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

#include <dlfcn.h>

#include "log_tags.h"
#include "ipc_debug.h"
#include "ipc_trace.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_COMMON, "IPC_TRACE" };
std::string IPCTrace::HITRACE_METER_SO_NAME = "libhitrace_meter.so";

bool IPCTrace::IsEnabled()
{
    auto &inst = GetInstance();
    if (inst.isTagEnabledFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "load hitrace so fail");
        return false;
    }
    return inst.isTagEnabledFunc_(HITRACE_TAG_RPC);
}

void IPCTrace::Start(const std::string &value)
{
    auto &inst = GetInstance();
    if (inst.startFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "load hitrace so fail");
        return;
    }
    inst.startFunc_(HITRACE_TAG_RPC, value);
}

void IPCTrace::Finish()
{
    auto &inst = GetInstance();
    if (inst.finishFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "load hitrace so fail");
        return;
    }
    inst.finishFunc_(HITRACE_TAG_RPC);
}

void IPCTrace::StartAsync(const std::string &value, int32_t taskId)
{
    auto &inst = GetInstance();
    if (inst.startAsyncFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "load hitrace so fail");
        return;
    }
    inst.startAsyncFunc_(HITRACE_TAG_RPC, value, taskId);
}

void IPCTrace::FinishAsync(const std::string &value, int32_t taskId)
{
    auto &inst = GetInstance();
    if (inst.finishAsyncFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "load hitrace so fail");
        return;
    }
    inst.finishAsyncFunc_(HITRACE_TAG_RPC, value, taskId);
}

IPCTrace &IPCTrace::GetInstance()
{
    static IPCTrace instance;
    return instance;
}

IPCTrace::IPCTrace()
{
    Load();
}

IPCTrace::~IPCTrace()
{
    Unload();
}

void IPCTrace::Load()
{
    traceSoHandler_ = dlopen(HITRACE_METER_SO_NAME.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (traceSoHandler_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlopen fail:%{public}s", dlerror());
        return;
    }

    isTagEnabledFunc_ = reinterpret_cast<IsTagEnabledFunc>(dlsym(traceSoHandler_, "IsTagEnabled"));
    if (isTagEnabledFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym IsTagEnabled fail:%{public}s", dlerror());
        Unload();
        return;
    }

    startFunc_ = reinterpret_cast<StartFunc>(dlsym(traceSoHandler_, "StartTrace"));
    if (startFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym StartTrace fail:%{public}s", dlerror());
        Unload();
        return;
    }

    finishFunc_ = reinterpret_cast<EndFunc>(dlsym(traceSoHandler_, "FinishTrace"));
    if (finishFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym FinishTrace fail:%{public}s", dlerror());
        Unload();
        return;
    }

    startAsyncFunc_ = reinterpret_cast<StartAsyncFunc>(dlsym(traceSoHandler_, "StartAsyncTrace"));
    if (startAsyncFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym StartAsyncTrace fail:%{public}s", dlerror());
        Unload();
        return;
    }

    finishAsyncFunc_ = reinterpret_cast<EndAsyncFunc>(dlsym(traceSoHandler_, "FinishAsyncTrace"));
    if (finishAsyncFunc_ == nullptr) {
        ZLOGE(LOG_LABEL, "dlsym FinishAsyncTrace fail:%{public}s", dlerror());
        Unload();
        return;
    }
    ZLOGD(LOG_LABEL, "load hitrace so success");
}

void IPCTrace::Unload()
{
    startFunc_ = nullptr;
    finishFunc_ = nullptr;
    startAsyncFunc_ = nullptr;
    finishAsyncFunc_ = nullptr;
    if (traceSoHandler_ != nullptr) {
        int32_t ret = dlclose(traceSoHandler_);
        if (ret != 0) {
            ZLOGE(LOG_LABEL, "dlclose error, %{public}s", dlerror());
        }
        traceSoHandler_ = nullptr;
    }
}
} // namespace OHOS

/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_IPC_DEBUG_H
#define OHOS_IPC_IPC_DEBUG_H

#include <map>
#include <string>
#include "hilog/log.h"
#include "string_ex.h"

namespace OHOS {
// if need enable ipc debug log, use '#define CONFIG_IPC_DEBUG'
#define ZLOGW(TAG, ...) (void)HiviewDFX::HiLog::Warn(TAG, __VA_ARGS__)
#define ZLOGE(TAG, ...) (void)HiviewDFX::HiLog::Error(TAG, __VA_ARGS__)

#if (defined CONFIG_IPC_DEBUG)
#define ZLOGI(TAG, ...) (void)HiviewDFX::HiLog::Info(TAG, __VA_ARGS__)
#else
#define ZLOGI(TAG, ...)
#endif /* CONFIG_IPC_DEBUG */

using ErrorMap = std::map<uint32_t, std::string>;
class ErrorBase {
public:
    virtual ~ErrorBase() = default;
    inline const std::string &GetErrorDesc(uint32_t error);
    virtual ErrorMap &GetErrorMap() = 0;
};

inline const std::string &ErrorBase::GetErrorDesc(uint32_t error)
{
    static const std::string unknowCommand = "UNKNOWN COMMAND";
    ErrorMap::iterator found = GetErrorMap().find(error);
    if (found == GetErrorMap().end()) {
        return unknowCommand;
    } else {
        return found->second;
    }
}

class IPCError : public ErrorBase {
public:
    IPCError() = default;
    ~IPCError() = default;
    static const std::string &ToString(int value);
    virtual ErrorMap &GetErrorMap() override;
};
} // namespace OHOS
#endif // OHOS_IPC_IPC_DEBUG_H

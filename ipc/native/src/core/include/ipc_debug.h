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
#define ZLOGF(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_FATAL, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)
#define ZLOGE(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_ERROR, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)
#define ZLOGW(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_WARN, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)
#define ZLOGI(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)
#define ZLOGD(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_DEBUG, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)

using ErrorMap = std::map<uint32_t, std::string>;
class ErrorBase {
public:
    virtual ~ErrorBase() = default;
    inline const std::string GetErrorDesc(uint32_t error);
    virtual ErrorMap &GetErrorMap() = 0;

    static constexpr const char *UNKNOWN_COMMAND = "UNKNOWN COMMAND";
};

inline const std::string ErrorBase::GetErrorDesc(uint32_t error)
{
    ErrorMap::iterator found = GetErrorMap().find(error);
    if (found == GetErrorMap().end()) {
        return UNKNOWN_COMMAND;
    } else {
        return found->second;
    }
}

class IPCError : public ErrorBase {
public:
    IPCError() = default;
    ~IPCError() = default;
    static const std::string ToString(uint32_t value);
    virtual ErrorMap &GetErrorMap() override;
};
} // namespace OHOS
#endif // OHOS_IPC_IPC_DEBUG_H

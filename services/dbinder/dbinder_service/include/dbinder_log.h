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

#ifndef OHOS_IPC_SERVICES_DBINDER_DBINDRR_LOG_H
#define OHOS_IPC_SERVICES_DBINDER_DBINDRR_LOG_H

#include "hilog/log.h"
#include "log_tags.h"

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_RPC_COMMON, LOG_TAG };

#define DBINDER_LOGF(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_FATAL, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)
#define DBINDER_LOGE(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_ERROR, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)
#define DBINDER_LOGW(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_WARN, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)
#define DBINDER_LOGI(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)
#define DBINDER_LOGD(LOG_LABEL, fmt, args...) \
    HILOG_IMPL(LOG_CORE, LOG_DEBUG, LOG_LABEL.domain, LOG_LABEL.tag, \
        "%{public}s %{public}d: " fmt, __FUNCTION__, __LINE__, ##args)


#endif // OHOS_IPC_SERVICES_DBINDER_DBINDRR_LOG_H

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

#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif
#include "hilog/log.h"
#include "log_tags.h"

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_RPC, LOG_TAG };

#define DBINDER_LOGF(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Fatal(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGW(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Warn(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGD(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Debug(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)


#endif // OHOS_IPC_SERVICES_DBINDER_DBINDRR_LOG_H
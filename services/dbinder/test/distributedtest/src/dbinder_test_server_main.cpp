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

#include "dbinder_test_service.h"
#include "ipc_skeleton.h"
#include "hilog/log.h"
#include "log_tags.h"

using namespace OHOS;
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LG_LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderTestService" };

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
    DBinderTestService::Instantiate();

    HiLog::Info(LG_LABEL, "DBinderTestService-main call StartThreadPool");

    while (1) {};
}

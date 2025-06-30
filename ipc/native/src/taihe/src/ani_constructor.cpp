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

#include "taihe/runtime.hpp"
#include "ohos.rpc.rpc.ani.hpp"

#include "ipc_debug.h"
#include "log_tags.h"

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_OTHER, "RpcTaiheImpl" };

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        return ANI_ERROR;
    }
    ani_status registerRes = ohos::rpc::rpc::ANIRegister(env);
    if (ANI_OK != registerRes) {
        ZLOGE(LOG_LABEL, "ohos::rpc::rpc::ANIRegister failed, errCode:%{public}d", registerRes);
        return ANI_ERROR;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}

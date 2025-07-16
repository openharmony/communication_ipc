/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_rpc_error.h"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = {LOG_CORE, LOG_ID_IPC_NAPI, "ani_rpc_error"};

static void ThrowBusinessError(ani_env *env, int errCode, const std::string &errMsg)
{
    static const char *errorClsName = "@ohos.base.BusinessError";
    ZLOGD(LOG_LABEL, "Begin ThrowBusinessError.");

    ani_class cls {};
    if (ANI_OK != env->FindClass(errorClsName, &cls)) {
        ZLOGE(LOG_LABEL, "find class BusinessError %{public}s failed", errorClsName);
        return;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) {
        ZLOGE(LOG_LABEL, "find method BusinessError.constructor failed");
        return;
    }

    ani_object errorObject;
    if (ANI_OK != env->Object_New(cls, ctor, &errorObject)) {
        ZLOGE(LOG_LABEL, "create BusinessError object failed");
        return;
    }

    ani_double aniErrCode = static_cast<ani_double>(errCode);
    ani_string errMsgStr;
    if (ANI_OK != env->String_NewUTF8(errMsg.c_str(), errMsg.size(), &errMsgStr)) {
        ZLOGE(LOG_LABEL, "convert errMsg to ani_string failed");
    }
    ZLOGD(LOG_LABEL, "ThrowBusinessError: errMsg: %{public}s.", errMsg.c_str());
    if (ANI_OK != env->Object_SetFieldByName_Double(errorObject, "code", aniErrCode)) {
        ZLOGE(LOG_LABEL, "set error code failed");
    }
    if (ANI_OK != env->Object_SetPropertyByName_Ref(errorObject, "message", errMsgStr)) {
        ZLOGE(LOG_LABEL, "set error message failed");
    }

    env->ThrowError(static_cast<ani_error>(errorObject));
}

void AniError::ThrowError(ani_env *env, int errCode)
{
    ThrowBusinessError(env, errCode, aniErrMap_.at(errCode));
}

} // namespace OHOS
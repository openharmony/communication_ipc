/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_process_skeleton.h"

#include "iremote_invoker.h"

namespace OHOS {
napi_value NAPI_getCallingPid(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    if (napiActiveStatus != nullptr) {
        int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
        napi_get_value_int32(env, napiActiveStatus, &activeStatus);
        if (activeStatus == IRemoteInvoker::ACTIVE_INVOKER) {
            napi_value callingPid = nullptr;
            napi_get_named_property(env, global, "callingPid_", &callingPid);
            return callingPid;
        }
    }
    pid_t pid = getpid();
    napi_value result = nullptr;
    napi_create_int32(env, static_cast<int32_t>(pid), &result);
    return result;
}

napi_value NAPI_getCallingUid(napi_env env, napi_callback_info info)
{
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value napiActiveStatus = nullptr;
    napi_get_named_property(env, global, "activeStatus_", &napiActiveStatus);
    if (napiActiveStatus != nullptr) {
        int32_t activeStatus = IRemoteInvoker::IDLE_INVOKER;
        napi_get_value_int32(env, napiActiveStatus, &activeStatus);
        if (activeStatus == IRemoteInvoker::ACTIVE_INVOKER) {
            napi_value callingUid = nullptr;
            napi_get_named_property(env, global, "callingUid_", &callingUid);
            return callingUid;
        }
    }
    uint32_t uid = getuid();
    napi_value result = nullptr;
    napi_create_int32(env, static_cast<int32_t>(uid), &result);
    return result;
}
} // namespace OHOS
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

#ifndef NAPI_PROCESS_SKELETON_H
#define NAPI_PROCESS_SKELETON_H

#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "message_option.h"
#include "napi/native_api.h"

namespace OHOS {
napi_value NAPI_getCallingPid(napi_env env, napi_callback_info info);
napi_value NAPI_getCallingUid(napi_env env, napi_callback_info info);
} // namespace OHOS
#endif // NAPI_PROCESS_SKELETON_H
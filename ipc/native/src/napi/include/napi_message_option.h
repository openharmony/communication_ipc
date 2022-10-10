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

#ifndef NAPI_IPC_OHOS_MESSAGE_OPTION_H
#define NAPI_IPC_OHOS_MESSAGE_OPTION_H

#include "message_option.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
/*
 * Get flags field from ohos.rpc.MessageOption.
 */
napi_value NapiOhosRpcMessageOptionGetFlags(napi_env env, napi_callback_info info);

/*
 * Set flags to ohos.rpc.MessageOption
 */
napi_value NapiOhosRpcMessageOptionSetFlags(napi_env env, napi_callback_info info);

/*
 * Get async to ohos.rpc.MessageOption
 */
napi_value NapiOhosRpcMessageOptionIsAsync(napi_env env, napi_callback_info info);

/*
 * Set async to ohos.rpc.MessageOption
 */
napi_value NapiOhosRpcMessageOptionSetAsync(napi_env env, napi_callback_info info);

/*
 * Get wait time field from ohos.rpc.MessageOption.
 */
napi_value NapiOhosRpcMessageOptionGetWaittime(napi_env env, napi_callback_info info);

/*
 * Set wait time to ohos.rpc.MessageOption
 */
napi_value NapiOhosRpcMessageOptionSetWaittime(napi_env env, napi_callback_info info);
} // namespace OHOS
#endif // NAPI_IPC_OHOS_MESSAGE_OPTION_H
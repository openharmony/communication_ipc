/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "napi_ashmem.h"
#include "napi_message_parcel.h"
#include "napi_message_sequence.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_remote_object.h"

namespace OHOS {
EXTERN_C_START
extern napi_value NAPIIPCSkeletonExport(napi_env env, napi_value exports);
extern napi_value NAPIRemoteProxyExport(napi_env env, napi_value exports);
extern napi_value NAPIMessageOptionExport(napi_env env, napi_value exports);

static napi_value RpcExport(napi_env env, napi_value exports)
{
    NAPI_MessageParcel::Export(env, exports);
    NAPI_MessageSequence::Export(env, exports);
    NAPIAshmem::AshmemExport(env, exports);
    NAPIIPCSkeletonExport(env, exports);
    NAPIRemoteObjectExport(env, exports);
    NAPIRemoteProxyExport(env, exports);
    NAPIMessageOptionExport(env, exports);
    NapiError::NAPIRpcErrorEnumExport(env, exports);
    return exports;
}
EXTERN_C_END

/*
 * Module register function
 */
NAPI_MODULE(rpc, RpcExport)
} // namesapce OHOS
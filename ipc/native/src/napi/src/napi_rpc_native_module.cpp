/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <unistd.h>
#include "hilog/log.h"
#include "log_tags.h"
#include "napi_message_parcel.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_remote_object.h"

extern const char _binary_rpc_js_start[];
extern const char _binary_rpc_js_end[];
extern const char _binary_rpc_abc_start[];
extern const char _binary_rpc_abc_end[];

namespace OHOS {
EXTERN_C_START
static napi_value rpcExport(napi_env env, napi_value exports)
{
    NAPI_MessageParcel::Export(env, exports);
    NAPIIPCSkeletonExport(env, exports);
    NAPIRemoteObjectExport(env, exports);
    NAPIRemoteProxyExport(env, exports);
    NAPIMessageOptionExport(env, exports);
    return exports;
}
EXTERN_C_END

extern "C" __attribute__((visibility("default"))) void NAPI_rpc_GetJSCode(const char **buf, int *bufLen)
{
    if (buf != nullptr) {
        *buf = _binary_rpc_js_start;
    }

    if (bufLen != nullptr) {
        *bufLen = _binary_rpc_js_end - _binary_rpc_js_start;
    }
}

// rpc JS register
extern "C" __attribute__((visibility("default"))) void NAPI_rpc_GetABCCode(const char **buf, int *buflen)
{
    if (buf != nullptr) {
        *buf = _binary_rpc_abc_start;
    }
    if (buflen != nullptr) {
        *buflen = _binary_rpc_abc_end - _binary_rpc_abc_start;
    }
}

static napi_module RPCModule_ = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = rpcExport,
    .nm_modname = "rpc",
    .nm_priv = ((void*)0),
    .reserved = { 0 }
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&RPCModule_);
}
} // namesapce OHOS

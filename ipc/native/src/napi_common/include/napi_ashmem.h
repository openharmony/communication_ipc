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

#ifndef NAPI_IPC_OHOS_ASHMEM_H
#define NAPI_IPC_OHOS_ASHMEM_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "ashmem.h"
#include "napi_rpc_error.h"

namespace OHOS {
class NAPIAshmem {
public:
    enum {
        PROT_EXEC = 4,
        PROT_NONE = 0,
        PROT_READ = 1,
        PROT_WRITE = 2,
    };
    explicit NAPIAshmem(sptr<Ashmem> &ashmem);
    NAPIAshmem() : ashmem_(nullptr) {}
    ~NAPIAshmem() = default;
    const sptr<Ashmem> &GetAshmem()
    {
        return ashmem_;
    }
    void SetAshmem(sptr<Ashmem> &ashmem)
    {
        ashmem_ = ashmem;
    }
    static napi_value AshmemExport(napi_env env, napi_value exports);
private:
    static napi_value Ashmem_JS_Constructor(napi_env env, napi_callback_info info);
    static napi_value CloseAshmem(napi_env env, napi_callback_info info);
    static napi_value CreateAshmem(napi_env env, napi_callback_info info);
    static napi_value Create(napi_env env, napi_callback_info info);
    static napi_value CreateAshmemFromExisting(napi_env env, napi_callback_info info);
    static napi_value GetAshmemSize(napi_env env, napi_callback_info info);
    static napi_value MapAshmem(napi_env env, napi_callback_info info);
    static napi_value MapTypedAshmem(napi_env env, napi_callback_info info);
    static napi_value MapReadAndWriteAshmem(napi_env env, napi_callback_info info);
    static napi_value MapReadWriteAshmem(napi_env env, napi_callback_info info);
    static napi_value MapReadOnlyAshmem(napi_env env, napi_callback_info info);
    static napi_value MapReadonlyAshmem(napi_env env, napi_callback_info info);
    static napi_value ReadFromAshmem(napi_env env, napi_callback_info info);
    static napi_value ReadAshmem(napi_env env, napi_callback_info info);
    static napi_value ReadDataFromAshmem(napi_env env, napi_callback_info info);
    static napi_value SetProtection(napi_env env, napi_callback_info info);
    static napi_value SetProtectionType(napi_env env, napi_callback_info info);
    static napi_value UnmapAshmem(napi_env env, napi_callback_info info);
    static napi_value WriteToAshmem(napi_env env, napi_callback_info info);
    static napi_value WriteAshmem(napi_env env, napi_callback_info info);
    static napi_value WriteDataToAshmem(napi_env env, napi_callback_info info);
    static napi_value GetAshmemFromExisting(napi_env env, napi_callback_info info);
    static napi_value GetAshmemConstructor(napi_env env, napi_value* argv);
    static napi_value getNewAshmemConstructor(napi_env env, napi_value &constructor, int32_t fd, uint32_t size);
    static napi_value CheckWriteAshmemParams(napi_env env, size_t argc, napi_value* argv);
    static napi_value CheckWriteToAshmemParams(napi_env env, size_t argc, napi_value* argv);
    static napi_value CheckReadFromAshmemParams(napi_env env, size_t argc, napi_value* argv);
    static napi_value TransferByteToJsData(napi_env env, uint32_t size, const void *result);
    sptr<Ashmem> ashmem_;

    static NapiError napiErr;
};
} // namespace OHOS
#endif

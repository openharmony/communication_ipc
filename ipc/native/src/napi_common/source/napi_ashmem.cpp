/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "napi_ashmem.h"
#include <cinttypes>
#include <limits>
#include <unistd.h>
#include "ipc_debug.h"
#include "log_tags.h"
#include "securec.h"
#include "napi_rpc_error.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "napi_ashmem" };

static constexpr int MMAP_PROT_MAX = NAPIAshmem::PROT_EXEC | NAPIAshmem::PROT_READ | NAPIAshmem::PROT_WRITE;
constexpr size_t BYTE_SIZE_32 = 4;

NapiError NAPIAshmem::napiErr;

static const size_t ARGV_INDEX_0 = 0;
static const size_t ARGV_INDEX_1 = 1;
static const size_t ARGV_INDEX_2 = 2;

static const size_t ARGV_LENGTH_1 = 1;
static const size_t ARGV_LENGTH_2 = 2;
static const size_t ARGV_LENGTH_3 = 3;
NAPIAshmem::NAPIAshmem(sptr<Ashmem> &ashmem) : ashmem_(ashmem)
{
    if (ashmem == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
    }
}

napi_value NAPIAshmem::CloseAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    napiAshmem->GetAshmem()->CloseAshmem();
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPIAshmem::CreateAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 2, "requires 2 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return nullptr;
    }
    size_t bufferSize = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize == 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem name");
        return nullptr;
    }
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return nullptr;
    }
    int32_t ashmemSize = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &ashmemSize);
    if (ashmemSize <= 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem size");
        return nullptr;
    }
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "AshmemConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get Ashmem constructor failed");
    napi_value jsAshmem;
    status = napi_new_instance(env, constructor, 2, argv, &jsAshmem);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js Ashmem");
    return jsAshmem;
}

napi_value NAPIAshmem::CreateAshmemFromExisting(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "AshmemConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get Ashmem constructor failed");
    bool isAshmem = false;
    napi_instanceof(env, argv[ARGV_INDEX_0], constructor, &isAshmem);
    NAPI_ASSERT(env, isAshmem == true, "parameter is not instanceof Ashmem");
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, argv[ARGV_INDEX_0], (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    int32_t fd = napiAshmem->GetAshmem()->GetAshmemFd();
    uint32_t size = (uint32_t)(napiAshmem->GetAshmem()->GetAshmemSize());
    NAPI_ASSERT(env,  (fd > 0) && (size > 0), "fd <= 0 or  size <= 0");
    sptr<Ashmem> newAshmem(new Ashmem(dup(fd), size));
    NAPI_ASSERT(env, newAshmem != nullptr, "napiAshmem is null");
    napi_value jsAshmem = nullptr;
    status = napi_new_instance(env, constructor, 0, nullptr, &jsAshmem);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js Ashmem");
    NAPIAshmem *newNapiAshmem = nullptr;
    napi_unwrap(env, jsAshmem, (void **)&newNapiAshmem);
    NAPI_ASSERT(env, newNapiAshmem != nullptr, "newNapiAshmem is null");
    newNapiAshmem->SetAshmem(newAshmem);
    return jsAshmem;
}

napi_value NAPIAshmem::Create(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    size_t argcExistingAshmem = 1;
    size_t argcAshmem = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != argcExistingAshmem) && (argc != argcAshmem)) {
        ZLOGE(LOG_LABEL, "requires 1 or 2 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    if (argc == argcExistingAshmem) {
        return GetAshmemFromExisting(env, info);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    size_t bufferSize = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize == 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem name");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t ashmemSize = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &ashmemSize);
    if (ashmemSize <= 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem size");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    return GetAshmemConstructor(env, argv);
}

napi_value NAPIAshmem::GetAshmemConstructor(napi_env env, napi_value* argv)
{
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get napi global failed");
        return nullptr;
    }
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "AshmemConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get Ashmem constructor failed");
        return nullptr;
    }
    napi_value jsAshmem;
    status = napi_new_instance(env, constructor, 2, argv, &jsAshmem);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to  construct js Ashmem");
        return nullptr;
    }
    return jsAshmem;
}

napi_value NAPIAshmem::GetAshmemFromExisting(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get napi global failed");
        return nullptr;
    }
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "AshmemConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get Ashmem constructor failed");
        return nullptr;
    }
    bool isAshmem = false;
    napi_instanceof(env, argv[ARGV_INDEX_0], constructor, &isAshmem);
    if (isAshmem == false) {
        ZLOGE(LOG_LABEL, "parameter is not instanceof Ashmem");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, argv[ARGV_INDEX_0], (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t fd = napiAshmem->GetAshmem()->GetAshmemFd();
    uint32_t size = (uint32_t)(napiAshmem->GetAshmem()->GetAshmemSize());
    if (fd <= 0 || size <= 0) {
        ZLOGE(LOG_LABEL, "fd <= 0 or  size <= 0");
        return nullptr;
    }

    return getNewAshmemConstructor(env, constructor, fd, size);
}

napi_value NAPIAshmem::getNewAshmemConstructor(napi_env env, napi_value& constructor, int32_t fd, uint32_t size)
{
    sptr<Ashmem> newAshmem(new Ashmem(dup(fd), size));
    if (newAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "newAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    napi_value jsAshmem = nullptr;
    napi_status status = napi_new_instance(env, constructor, 0, nullptr, &jsAshmem);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to  construct js Ashmem");
        return nullptr;
    }
    NAPIAshmem *newNapiAshmem = nullptr;
    napi_unwrap(env, jsAshmem, (void **)&newNapiAshmem);
    if (newNapiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "newNapiAshmem is null");
        return nullptr;
    }
    newNapiAshmem->SetAshmem(newAshmem);
    return jsAshmem;
}

napi_value NAPIAshmem::GetAshmemSize(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    uint32_t ashmemSize = (uint32_t)(napiAshmem->GetAshmem()->GetAshmemSize());
    napi_value napiValue;
    napi_create_uint32(env, ashmemSize, &napiValue);
    return napiValue;
}

napi_value NAPIAshmem::MapAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    uint32_t mapType = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &mapType);
    NAPI_ASSERT(env, mapType <= MMAP_PROT_MAX, "napiAshmem mapType error");
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->MapAshmem(mapType);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPIAshmem::MapTypedAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    uint32_t mapType = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &mapType);
    if (mapType > MMAP_PROT_MAX) {
        ZLOGE(LOG_LABEL, "napiAshmem mapType error");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::OS_MMAP_ERROR);
    }
    napiAshmem->GetAshmem()->MapAshmem(mapType);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPIAshmem::MapReadAndWriteAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->MapReadAndWriteAshmem();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPIAshmem::MapReadWriteAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::OS_MMAP_ERROR);
    }
    napiAshmem->GetAshmem()->MapReadAndWriteAshmem();
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPIAshmem::MapReadOnlyAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->MapReadOnlyAshmem();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPIAshmem::MapReadonlyAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::OS_MMAP_ERROR);
    }
    napiAshmem->GetAshmem()->MapReadOnlyAshmem();
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPIAshmem::ReadFromAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = {0};
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 2, "requires 2 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    int64_t size = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_0], &size);
    int64_t offset = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_1], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");

    uint32_t ashmemSize = (uint32_t)napiAshmem->GetAshmem()->GetAshmemSize();
    if (size < 0 || size > static_cast<int64_t>(std::numeric_limits<int32_t>::max() / BYTE_SIZE_32) ||
        offset < 0 || offset > static_cast<int64_t>(std::numeric_limits<int32_t>::max() / BYTE_SIZE_32) ||
        (size * BYTE_SIZE_32 + offset * BYTE_SIZE_32) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}jd offset:%{public}jd", size, offset);
        return nullptr;
    }
    size *= BYTE_SIZE_32;
    offset *= BYTE_SIZE_32;
    const void  *result = napiAshmem->GetAshmem()->ReadFromAshmem(size, offset);
    if (result == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem->ReadFromAshmem returns null");
        return nullptr;
    }
    // c++ byte[] to js []
    napi_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    napi_create_arraybuffer(env, size, &arrayBufferPtr, &arrayBuffer);
    napi_value typedArray = nullptr;
    napi_create_typedarray(env, napi_int32_array, size / BYTE_SIZE_32, arrayBuffer, 0, &typedArray);
    bool isTypedArray = false;
    napi_is_typedarray(env, typedArray, &isTypedArray);
    NAPI_ASSERT(env, isTypedArray == true, "create  TypedArray failed");
    if (size == 0) {
        return typedArray;
    }
    errno_t status = memcpy_s(arrayBufferPtr, size, result, size);
    NAPI_ASSERT(env, status == EOK, "memcpy_s is failed");
    return typedArray;
}

napi_value NAPIAshmem::ReadAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    size_t argNum = 2;
    napi_value argv[ARGV_LENGTH_2] = {0};
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != argNum) {
        ZLOGE(LOG_LABEL, "requires 2 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    int64_t size = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_0], &size);
    int64_t offset = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_1], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::READ_FROM_ASHMEM_ERROR);
    }
    uint32_t ashmemSize = (uint32_t)napiAshmem->GetAshmem()->GetAshmemSize();
    if (size < 0 || size > (int64_t)(std::numeric_limits<int32_t>::max() / BYTE_SIZE_32) ||
        offset < 0 || offset > (int64_t)(std::numeric_limits<int32_t>::max() / BYTE_SIZE_32) ||
        (size * BYTE_SIZE_32 + offset * BYTE_SIZE_32) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}jd offset:%{public}jd", size, offset);
        return nullptr;
    }
    size *= BYTE_SIZE_32;
    offset *= BYTE_SIZE_32;
    const void  *result = napiAshmem->GetAshmem()->ReadFromAshmem(size, offset);
    if (result == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem->ReadFromAshmem returns null");
        return nullptr;
    }
    // c++ byte[] to js []
    return TransferByteToJsData(env, size, result);
}

napi_value NAPIAshmem::TransferByteToJsData(napi_env env, uint32_t size, const void *result)
{
    napi_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    napi_create_arraybuffer(env, size, &arrayBufferPtr, &arrayBuffer);
    napi_value typedArray = nullptr;
    napi_create_typedarray(env, napi_int32_array, size / BYTE_SIZE_32, arrayBuffer, 0, &typedArray);
    bool isTypedArray = false;
    napi_is_typedarray(env, typedArray, &isTypedArray);
    NAPI_ASSERT(env, isTypedArray == true, "create  TypedArray failed");
    if (!isTypedArray) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::READ_FROM_ASHMEM_ERROR);
    }
    if (size == 0) {
        return typedArray;
    }
    errno_t status = memcpy_s(arrayBufferPtr, size, result, size);
    if (status != EOK) {
        ZLOGE(LOG_LABEL, "memcpy_s is failed");
        return napiErr.ThrowError(env, OHOS::errorDesc::READ_FROM_ASHMEM_ERROR);
    }
    return typedArray;
}

napi_value NAPIAshmem::SetProtection(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    uint32_t protectionType = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &protectionType);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->SetProtection(protectionType);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPIAshmem::SetProtectionType(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    size_t argNum = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != argNum) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    uint32_t protectionType = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &protectionType);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::OS_IOCTL_ERROR);
    }
    napiAshmem->GetAshmem()->SetProtection(protectionType);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPIAshmem::UnmapAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    napiAshmem->GetAshmem()->UnmapAshmem();
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPIAshmem::WriteToAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value argv[ARGV_LENGTH_3] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 3, "requires 3 parameter");
    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    napi_typeof(env, argv[ARGV_INDEX_2], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 3");

    std::vector<int32_t> array;
    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        array.push_back(value);
    }

    int64_t size = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_1], &size);
    int64_t offset = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_2], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");

    // need check size offset and capacity
    napi_value napiValue = nullptr;
    bool result = true;
    uint32_t ashmemSize = (uint32_t)napiAshmem->GetAshmem()->GetAshmemSize();
    if (size < 0 || size > (int64_t)(std::numeric_limits<int32_t>::max() / BYTE_SIZE_32) ||
        offset < 0 || offset > (int64_t)(std::numeric_limits<int32_t>::max() / BYTE_SIZE_32) ||
        (size * BYTE_SIZE_32 + offset * BYTE_SIZE_32) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}jd offset:%{public}jd", size, offset);
        result = false;
    } else {
        result = napiAshmem->GetAshmem()->WriteToAshmem(array.data(), size * BYTE_SIZE_32, offset * BYTE_SIZE_32);
    }
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPIAshmem::WriteAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value argv[ARGV_LENGTH_3] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = CheckWriteAshmemParams(env, argc, argv);
    if (checkArgsResult != nullptr) {
        return checkArgsResult;
    }

    std::vector<int32_t> array;
    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        array.push_back(value);
    }

    int64_t size = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_1], &size);
    int64_t offset = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_2], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::WRITE_TO_ASHMEM_ERROR);
    }

    // need check size offset and capacity
    uint32_t ashmemSize = (uint32_t)napiAshmem->GetAshmem()->GetAshmemSize();
    if (size < 0 || size > (int64_t)(std::numeric_limits<int32_t>::max() / BYTE_SIZE_32) ||
        offset < 0 || offset > (int64_t)(std::numeric_limits<int32_t>::max() / BYTE_SIZE_32) ||
        (size * BYTE_SIZE_32 + offset * BYTE_SIZE_32) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}jd offset:%{public}jd", size, offset);
        return napiErr.ThrowError(env, OHOS::errorDesc::WRITE_TO_ASHMEM_ERROR);
    }
    napiAshmem->GetAshmem()->WriteToAshmem(array.data(), size * BYTE_SIZE_32, offset * BYTE_SIZE_32);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPIAshmem::CheckWriteAshmemParams(napi_env env, size_t argc, napi_value* argv)
{
    size_t argNum = 3;
    if (argc != argNum) {
        ZLOGE(LOG_LABEL, "requires 3 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_2], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 4");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    return nullptr;
}

napi_value NAPIAshmem::CheckWriteToAshmemParams(napi_env env, size_t argc, napi_value* argv)
{
    if (argc != ARGV_LENGTH_3) {
        ZLOGE(LOG_LABEL, "requires 3 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    bool isArrayBuffer = false;
    napi_is_arraybuffer(env, argv[ARGV_INDEX_0], &isArrayBuffer);
    if (!isArrayBuffer) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1, not ArrayBuffer");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    napi_typeof(env, argv[ARGV_INDEX_2], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 3");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    return nullptr;
}

napi_value NAPIAshmem::WriteDataToAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = ARGV_LENGTH_3;
    napi_value argv[ARGV_LENGTH_3] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = CheckWriteToAshmemParams(env, argc, argv);
    if (checkArgsResult != nullptr) {
        return checkArgsResult;
    }

    void *data = nullptr;
    size_t byteLength = 0;
    napi_status isGet = napi_get_arraybuffer_info(env, argv[ARGV_INDEX_0], (void **)&data, &byteLength);
    if (isGet != napi_ok) {
        ZLOGE(LOG_LABEL, "arraybuffery get info failed");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int64_t size = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_1], &size);
    int64_t offset = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_2], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::WRITE_TO_ASHMEM_ERROR);
    }

    uint32_t ashmemSize = (uint32_t)napiAshmem->GetAshmem()->GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() ||
        offset < 0 || offset > std::numeric_limits<int32_t>::max() ||
        (size + offset) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}" PRId64 " offset:%{public}" PRId64, size, offset);
        return napiErr.ThrowError(env, OHOS::errorDesc::WRITE_TO_ASHMEM_ERROR);
    }

    if (!napiAshmem->GetAshmem()->WriteToAshmem(data, size, offset)) {
        ZLOGE(LOG_LABEL, "WriteToAshmem fail");
        return napiErr.ThrowError(env, OHOS::errorDesc::WRITE_TO_ASHMEM_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPIAshmem::CheckReadFromAshmemParams(napi_env env, size_t argc, napi_value* argv)
{
    if (argc != ARGV_LENGTH_2) {
        ZLOGE(LOG_LABEL, "requires 2 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    return nullptr;
}

napi_value NAPIAshmem::ReadDataFromAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = ARGV_LENGTH_2;
    napi_value argv[ARGV_LENGTH_2] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = CheckReadFromAshmemParams(env, argc, argv);
    if (checkArgsResult != nullptr) {
        return checkArgsResult;
    }

    int64_t size = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_0], &size);
    int64_t offset = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_1], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::READ_FROM_ASHMEM_ERROR);
    }
    uint32_t ashmemSize = (uint32_t)napiAshmem->GetAshmem()->GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() ||
        offset < 0 || offset > std::numeric_limits<int32_t>::max() ||
        (size + offset) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}" PRId64 " offset:%{public}" PRId64, size, offset);
        return napiErr.ThrowError(env, OHOS::errorDesc::READ_FROM_ASHMEM_ERROR);
    }

    const void *result = napiAshmem->GetAshmem()->ReadFromAshmem(size, offset);
    if (result == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem->ReadFromAshmem returns null");
        return napiErr.ThrowError(env, OHOS::errorDesc::READ_FROM_ASHMEM_ERROR);
    }
    
    napi_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    size_t bufferSize = static_cast<size_t>(size);
    napi_status isCreateBufferOk = napi_create_arraybuffer(env, size, &arrayBufferPtr, &arrayBuffer);
    if (isCreateBufferOk != napi_ok) {
        ZLOGE(LOG_LABEL, "ReadDataFromAshmem create arrayBuffer failed");
        return napiErr.ThrowError(env, errorDesc::READ_FROM_ASHMEM_ERROR);
    }
    errno_t status = memcpy_s(arrayBufferPtr, bufferSize, result, bufferSize);
    if (status != EOK) {
        ZLOGE(LOG_LABEL, "memcpy_s is failed");
        return napiErr.ThrowError(env, OHOS::errorDesc::READ_FROM_ASHMEM_ERROR);
    }
    return arrayBuffer;
}

napi_value NAPIAshmem::AshmemExport(napi_env env, napi_value exports)
{
    const std::string className = "Ashmem";
    napi_value exec = nullptr;
    napi_create_int32(env, NAPIAshmem::PROT_EXEC, &exec);
    napi_value none = nullptr;
    napi_create_int32(env, NAPIAshmem::PROT_NONE, &none);
    napi_value read = nullptr;
    napi_create_int32(env, NAPIAshmem::PROT_READ, &read);
    napi_value write = nullptr;
    napi_create_int32(env, NAPIAshmem::PROT_WRITE, &write);
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAshmem", NAPIAshmem::CreateAshmem),
        DECLARE_NAPI_STATIC_FUNCTION("create", NAPIAshmem::Create),
        DECLARE_NAPI_STATIC_FUNCTION("createAshmemFromExisting", NAPIAshmem::CreateAshmemFromExisting),
        DECLARE_NAPI_FUNCTION("closeAshmem", NAPIAshmem::CloseAshmem),
        DECLARE_NAPI_FUNCTION("getAshmemSize", NAPIAshmem::GetAshmemSize),
        DECLARE_NAPI_FUNCTION("mapAshmem", NAPIAshmem::MapAshmem),
        DECLARE_NAPI_FUNCTION("mapTypedAshmem", NAPIAshmem::MapTypedAshmem),
        DECLARE_NAPI_FUNCTION("mapReadAndWriteAshmem", NAPIAshmem::MapReadAndWriteAshmem),
        DECLARE_NAPI_FUNCTION("mapReadWriteAshmem", NAPIAshmem::MapReadWriteAshmem),
        DECLARE_NAPI_FUNCTION("mapReadOnlyAshmem", NAPIAshmem::MapReadOnlyAshmem),
        DECLARE_NAPI_FUNCTION("mapReadonlyAshmem", NAPIAshmem::MapReadonlyAshmem),
        DECLARE_NAPI_FUNCTION("readFromAshmem", NAPIAshmem::ReadFromAshmem),
        DECLARE_NAPI_FUNCTION("readAshmem", NAPIAshmem::ReadAshmem),
        DECLARE_NAPI_FUNCTION("setProtection", NAPIAshmem::SetProtection),
        DECLARE_NAPI_FUNCTION("setProtectionType", NAPIAshmem::SetProtectionType),
        DECLARE_NAPI_FUNCTION("unmapAshmem", NAPIAshmem::UnmapAshmem),
        DECLARE_NAPI_FUNCTION("writeToAshmem", NAPIAshmem::WriteToAshmem),
        DECLARE_NAPI_FUNCTION("writeAshmem", NAPIAshmem::WriteAshmem),
        DECLARE_NAPI_FUNCTION("writeDataToAshmem", NAPIAshmem::WriteDataToAshmem),
        DECLARE_NAPI_FUNCTION("readDataFromAshmem", NAPIAshmem::ReadDataFromAshmem),
        DECLARE_NAPI_STATIC_PROPERTY("PROT_EXEC", exec),
        DECLARE_NAPI_STATIC_PROPERTY("PROT_NONE", none),
        DECLARE_NAPI_STATIC_PROPERTY("PROT_READ", read),
        DECLARE_NAPI_STATIC_PROPERTY("PROT_WRITE", write),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), Ashmem_JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class Ashmem failed");
    napi_status status = napi_set_named_property(env, exports, "Ashmem", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property Ashmem failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "AshmemConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set Ashmem constructor failed");
    return exports;
}

napi_value NAPIAshmem::Ashmem_JS_Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    if (argc == 0) {
        napiAshmem = new NAPIAshmem();
    } else {
        NAPI_ASSERT(env, argc == 2, "requires 2 parameter");
        napi_valuetype valueType = napi_null;
        napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
        NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");
        napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
        size_t bufferSize = 0;
        size_t maxLen = 40960;
        napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
        NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");
        char stringValue[bufferSize + 1];
        size_t jsStringLength = 0;
        napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
        NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");
        std::string ashmemName = stringValue;
        uint32_t ashmemSize = 0;
        napi_get_value_uint32(env, argv[ARGV_INDEX_1], &ashmemSize);
        // new napi Ashmem
        sptr<Ashmem> nativeAshmem = Ashmem::CreateAshmem(ashmemName.c_str(), ashmemSize);
        NAPI_ASSERT(env, nativeAshmem != nullptr, "invalid parameters");
        napiAshmem = new NAPIAshmem(nativeAshmem);
    }
    // connect native object to js thisVar
    napi_status status = napi_wrap(
        env, thisVar, napiAshmem,
        [](napi_env env, void *data, void *hint) {
            ZLOGD(LOG_LABEL, "Ashmem destructed by js callback");
            delete (reinterpret_cast<NAPIAshmem *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js Ashmem and native holder failed");
    return thisVar;
}
} // namespace OHOS

/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "ani_ashmem.h"
#include <cinttypes>
#include <limits>
#include <unistd.h>
#include "ipc_debug.h"
#include "log_tags.h"
#include "securec.h"
#include "ani_rpc_error.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "ani_ashmem" };

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

ani_value NAPIAshmem::CloseAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    napiAshmem->GetAshmem()->CloseAshmem();
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value NAPIAshmem::CreateAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 2;
    ani_value argv[ARGV_LENGTH_2] = { 0 };
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 2, "requires 2 parameter");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return nullptr;
    }
    size_t bufferSize = 0;
    ani_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize == 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem name");
        return nullptr;
    }
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return nullptr;
    }
    int32_t ashmemSize = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_1], &ashmemSize);
    if (ashmemSize <= 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem size");
        return nullptr;
    }
    ani_value global = nullptr;
    ani_status status = ani_get_global(env, &global);
    ani_ASSERT(env, status == ani_ok, "get napi global failed");
    ani_value constructor = nullptr;
    status = ani_get_named_property(env, global, "AshmemConstructor_", &constructor);
    ani_ASSERT(env, status == ani_ok, "get Ashmem constructor failed");
    ani_value jsAshmem;
    status = ani_new_instance(env, constructor, 2, argv, &jsAshmem);
    ani_ASSERT(env, status == ani_ok, "failed to  construct js Ashmem");
    return jsAshmem;
}

ani_value NAPIAshmem::CreateAshmemFromExisting(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {nullptr};
    ani_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");
    ani_value global = nullptr;
    ani_status status = ani_get_global(env, &global);
    ani_ASSERT(env, status == ani_ok, "get napi global failed");
    ani_value constructor = nullptr;
    status = ani_get_named_property(env, global, "AshmemConstructor_", &constructor);
    ani_ASSERT(env, status == ani_ok, "get Ashmem constructor failed");
    bool isAshmem = false;
    ani_instanceof(env, argv[ARGV_INDEX_0], constructor, &isAshmem);
    ani_ASSERT(env, isAshmem == true, "parameter is not instanceof Ashmem");
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, argv[ARGV_INDEX_0], (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    int32_t fd = napiAshmem->GetAshmem()->GetAshmemFd();
    uint32_t size = (uint32_t)(napiAshmem->GetAshmem()->GetAshmemSize());
    ani_ASSERT(env,  (fd > 0) && (size > 0), "fd <= 0 or  size <= 0");
    int dupFd = dup(fd);
    ani_ASSERT(env, dupFd >= 0, "failed to dup fd");
    sptr<Ashmem> newAshmem(new Ashmem(dupFd, size));
    if (newAshmem == nullptr) {
        close(dupFd);
        ani_throw_error(env, nullptr, "failed to new Ashmem");
        return nullptr;
    }
    ani_value jsAshmem = nullptr;
    status = ani_new_instance(env, constructor, 0, nullptr, &jsAshmem);
    ani_ASSERT(env, status == ani_ok, "failed to  construct js Ashmem");
    NAPIAshmem *newNapiAshmem = nullptr;
    ani_unwrap(env, jsAshmem, (void **)&newNapiAshmem);
    ani_ASSERT(env, newNapiAshmem != nullptr, "newNapiAshmem is null");
    newNapiAshmem->SetAshmem(newAshmem);
    return jsAshmem;
}

ani_value NAPIAshmem::Create(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 2;
    size_t argcExistingAshmem = 1;
    size_t argcAshmem = 2;
    ani_value argv[ARGV_LENGTH_2] = { 0 };
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != argcExistingAshmem) && (argc != argcAshmem)) {
        ZLOGE(LOG_LABEL, "requires 1 or 2 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    if (argc == argcExistingAshmem) {
        return GetAshmemFromExisting(env, info);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    size_t bufferSize = 0;
    ani_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize == 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem name");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t ashmemSize = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_1], &ashmemSize);
    if (ashmemSize <= 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem size");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    return GetAshmemConstructor(env, argv);
}

ani_value NAPIAshmem::GetAshmemConstructor(ani_env env, ani_value* argv)
{
    ani_value global = nullptr;
    ani_status status = ani_get_global(env, &global);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "get napi global failed");
        return nullptr;
    }
    ani_value constructor = nullptr;
    status = ani_get_named_property(env, global, "AshmemConstructor_", &constructor);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "get Ashmem constructor failed");
        return nullptr;
    }
    ani_value jsAshmem;
    status = ani_new_instance(env, constructor, 2, argv, &jsAshmem);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "failed to  construct js Ashmem");
        return nullptr;
    }
    return jsAshmem;
}

ani_value NAPIAshmem::GetAshmemFromExisting(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {nullptr};
    ani_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    ani_value global = nullptr;
    ani_status status = ani_get_global(env, &global);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "get napi global failed");
        return nullptr;
    }
    ani_value constructor = nullptr;
    status = ani_get_named_property(env, global, "AshmemConstructor_", &constructor);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "get Ashmem constructor failed");
        return nullptr;
    }
    bool isAshmem = false;
    ani_instanceof(env, argv[ARGV_INDEX_0], constructor, &isAshmem);
    if (isAshmem == false) {
        ZLOGE(LOG_LABEL, "parameter is not instanceof Ashmem");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, argv[ARGV_INDEX_0], (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t fd = napiAshmem->GetAshmem()->GetAshmemFd();
    uint32_t size = (uint32_t)(napiAshmem->GetAshmem()->GetAshmemSize());
    if (fd <= 0 || size == 0) {
        ZLOGE(LOG_LABEL, "fd <= 0 or  size == 0");
        return nullptr;
    }

    return getNewAshmemConstructor(env, constructor, fd, size);
}

ani_value NAPIAshmem::getNewAshmemConstructor(ani_env env, ani_value& constructor, int32_t fd, uint32_t size)
{
    int dupFd = dup(fd);
    if (dupFd < 0) {
        ZLOGE(LOG_LABEL, "fail to dup fd:%{public}d", dupFd);
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    sptr<Ashmem> newAshmem(new Ashmem(dupFd, size));
    if (newAshmem == nullptr) {
        close(dupFd);
        ZLOGE(LOG_LABEL, "newAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    ani_value jsAshmem = nullptr;
    ani_status status = ani_new_instance(env, constructor, 0, nullptr, &jsAshmem);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "failed to  construct js Ashmem");
        return nullptr;
    }
    NAPIAshmem *newNapiAshmem = nullptr;
    ani_unwrap(env, jsAshmem, (void **)&newNapiAshmem);
    if (newNapiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "newNapiAshmem is null");
        return nullptr;
    }
    newNapiAshmem->SetAshmem(newAshmem);
    return jsAshmem;
}

ani_value NAPIAshmem::GetAshmemSize(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    uint32_t ashmemSize = (uint32_t)(napiAshmem->GetAshmem()->GetAshmemSize());
    ani_value napiValue;
    ani_create_uint32(env, ashmemSize, &napiValue);
    return napiValue;
}

ani_value NAPIAshmem::MapAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");
    uint32_t mapType = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &mapType);
    ani_ASSERT(env, mapType <= MMAP_PROT_MAX, "napiAshmem mapType error");
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->MapAshmem(mapType);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value NAPIAshmem::MapTypedAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    uint32_t mapType = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &mapType);
    if (mapType > MMAP_PROT_MAX) {
        ZLOGE(LOG_LABEL, "napiAshmem mapType error");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::OS_MMAP_ERROR);
    }
    napiAshmem->GetAshmem()->MapAshmem(mapType);
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value NAPIAshmem::MapReadAndWriteAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->MapReadAndWriteAshmem();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value NAPIAshmem::MapReadWriteAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::OS_MMAP_ERROR);
    }
    napiAshmem->GetAshmem()->MapReadAndWriteAshmem();
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value NAPIAshmem::MapReadOnlyAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->MapReadOnlyAshmem();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value NAPIAshmem::MapReadonlyAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::OS_MMAP_ERROR);
    }
    napiAshmem->GetAshmem()->MapReadOnlyAshmem();
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value NAPIAshmem::ReadFromAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 2;
    ani_value argv[ARGV_LENGTH_2] = {0};
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 2, "requires 2 parameter");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 2");
    int64_t size = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_0], &size);
    int64_t offset = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_1], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");

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
    ani_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    ani_create_arraybuffer(env, size, &arrayBufferPtr, &arrayBuffer);
    ani_value typedArray = nullptr;
    ani_create_typedarray(env, ani_int32_array, size / BYTE_SIZE_32, arrayBuffer, 0, &typedArray);
    bool isTypedArray = false;
    ani_is_typedarray(env, typedArray, &isTypedArray);
    ani_ASSERT(env, isTypedArray == true, "create  TypedArray failed");
    if (size == 0) {
        return typedArray;
    }
    errno_t status = memcpy_s(arrayBufferPtr, size, result, size);
    ani_ASSERT(env, status == EOK, "memcpy_s is failed");
    return typedArray;
}

ani_value NAPIAshmem::ReadAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 2;
    size_t argNum = 2;
    ani_value argv[ARGV_LENGTH_2] = {0};
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != argNum) {
        ZLOGE(LOG_LABEL, "requires 2 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    int64_t size = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_0], &size);
    int64_t offset = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_1], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
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

ani_value NAPIAshmem::TransferByteToJsData(ani_env env, uint32_t size, const void *result)
{
    ani_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    ani_create_arraybuffer(env, size, &arrayBufferPtr, &arrayBuffer);
    ani_value typedArray = nullptr;
    ani_create_typedarray(env, ani_int32_array, size / BYTE_SIZE_32, arrayBuffer, 0, &typedArray);
    bool isTypedArray = false;
    ani_is_typedarray(env, typedArray, &isTypedArray);
    ani_ASSERT(env, isTypedArray == true, "create  TypedArray failed");
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

ani_value NAPIAshmem::SetProtection(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");
    uint32_t protectionType = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &protectionType);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->SetProtection(protectionType);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value NAPIAshmem::SetProtectionType(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 1;
    size_t argNum = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != argNum) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    uint32_t protectionType = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &protectionType);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, OHOS::errorDesc::OS_IOCTL_ERROR);
    }
    napiAshmem->GetAshmem()->SetProtection(protectionType);
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value NAPIAshmem::UnmapAshmem(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    napiAshmem->GetAshmem()->UnmapAshmem();
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value NAPIAshmem::WriteToAshmem(ani_env env, ani_callback_info info)
{
    size_t argc = 3;
    ani_value argv[ARGV_LENGTH_3] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 3, "requires 3 parameter");
    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 2");
    ani_typeof(env, argv[ARGV_INDEX_2], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 3");

    std::vector<int32_t> array;
    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        array.push_back(value);
    }

    int64_t size = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_1], &size);
    int64_t offset = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_2], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");

    // need check size offset and capacity
    ani_value napiValue = nullptr;
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
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value NAPIAshmem::WriteAshmem(ani_env env, ani_callback_info info)
{
    size_t argc = 3;
    ani_value argv[ARGV_LENGTH_3] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_value checkArgsResult = CheckWriteAshmemParams(env, argc, argv);
    if (checkArgsResult != nullptr) {
        return checkArgsResult;
    }

    std::vector<int32_t> array;
    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        array.push_back(value);
    }

    int64_t size = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_1], &size);
    int64_t offset = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_2], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
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
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value NAPIAshmem::CheckWriteAshmemParams(ani_env env, size_t argc, ani_value* argv)
{
    size_t argNum = 3;
    if (argc != argNum) {
        ZLOGE(LOG_LABEL, "requires 3 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    ani_typeof(env, argv[ARGV_INDEX_2], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 4");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    return nullptr;
}

ani_value NAPIAshmem::CheckWriteToAshmemParams(ani_env env, size_t argc, ani_value* argv)
{
    if (argc != ARGV_LENGTH_3) {
        ZLOGE(LOG_LABEL, "requires 3 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    bool isArrayBuffer = false;
    ani_is_arraybuffer(env, argv[ARGV_INDEX_0], &isArrayBuffer);
    if (!isArrayBuffer) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1, not ArrayBuffer");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }

    ani_typeof(env, argv[ARGV_INDEX_2], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 3");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    return nullptr;
}

ani_value NAPIAshmem::WriteDataToAshmem(ani_env env, ani_callback_info info)
{
    size_t argc = ARGV_LENGTH_3;
    ani_value argv[ARGV_LENGTH_3] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_value checkArgsResult = CheckWriteToAshmemParams(env, argc, argv);
    if (checkArgsResult != nullptr) {
        return checkArgsResult;
    }

    void *data = nullptr;
    size_t byteLength = 0;
    ani_status isGet = ani_get_arraybuffer_info(env, argv[ARGV_INDEX_0], (void **)&data, &byteLength);
    if (isGet != ani_ok) {
        ZLOGE(LOG_LABEL, "arraybuffer get info failed");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int64_t size = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_1], &size);
    int64_t offset = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_2], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
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
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value NAPIAshmem::CheckReadFromAshmemParams(ani_env env, size_t argc, ani_value* argv)
{
    if (argc != ARGV_LENGTH_2) {
        ZLOGE(LOG_LABEL, "requires 2 parameter");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, OHOS::errorDesc::CHECK_PARAM_ERROR);
    }
    return nullptr;
}

ani_value NAPIAshmem::ReadDataFromAshmem(ani_env env, ani_callback_info info)
{
    size_t argc = ARGV_LENGTH_2;
    ani_value argv[ARGV_LENGTH_2] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_value checkArgsResult = CheckReadFromAshmemParams(env, argc, argv);
    if (checkArgsResult != nullptr) {
        return checkArgsResult;
    }

    int64_t size = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_0], &size);
    int64_t offset = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_1], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiAshmem);
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
    
    ani_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    size_t bufferSize = static_cast<size_t>(size);
    ani_status isCreateBufferOk = ani_create_arraybuffer(env, size, &arrayBufferPtr, &arrayBuffer);
    if (isCreateBufferOk != ani_ok) {
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

ani_value NAPIAshmem::AshmemExport(ani_env env, ani_value exports)
{
    const std::string className = "Ashmem";
    ani_value exec = nullptr;
    ani_create_int32(env, NAPIAshmem::PROT_EXEC, &exec);
    ani_value none = nullptr;
    ani_create_int32(env, NAPIAshmem::PROT_NONE, &none);
    ani_value read = nullptr;
    ani_create_int32(env, NAPIAshmem::PROT_READ, &read);
    ani_value write = nullptr;
    ani_create_int32(env, NAPIAshmem::PROT_WRITE, &write);
    ani_property_descriptor properties[] = {
        DECLARE_ani_STATIC_FUNCTION("createAshmem", NAPIAshmem::CreateAshmem),
        DECLARE_ani_STATIC_FUNCTION("create", NAPIAshmem::Create),
        DECLARE_ani_STATIC_FUNCTION("createAshmemFromExisting", NAPIAshmem::CreateAshmemFromExisting),
        DECLARE_ani_FUNCTION("closeAshmem", NAPIAshmem::CloseAshmem),
        DECLARE_ani_FUNCTION("getAshmemSize", NAPIAshmem::GetAshmemSize),
        DECLARE_ani_FUNCTION("mapAshmem", NAPIAshmem::MapAshmem),
        DECLARE_ani_FUNCTION("mapTypedAshmem", NAPIAshmem::MapTypedAshmem),
        DECLARE_ani_FUNCTION("mapReadAndWriteAshmem", NAPIAshmem::MapReadAndWriteAshmem),
        DECLARE_ani_FUNCTION("mapReadWriteAshmem", NAPIAshmem::MapReadWriteAshmem),
        DECLARE_ani_FUNCTION("mapReadOnlyAshmem", NAPIAshmem::MapReadOnlyAshmem),
        DECLARE_ani_FUNCTION("mapReadonlyAshmem", NAPIAshmem::MapReadonlyAshmem),
        DECLARE_ani_FUNCTION("readFromAshmem", NAPIAshmem::ReadFromAshmem),
        DECLARE_ani_FUNCTION("readAshmem", NAPIAshmem::ReadAshmem),
        DECLARE_ani_FUNCTION("setProtection", NAPIAshmem::SetProtection),
        DECLARE_ani_FUNCTION("setProtectionType", NAPIAshmem::SetProtectionType),
        DECLARE_ani_FUNCTION("unmapAshmem", NAPIAshmem::UnmapAshmem),
        DECLARE_ani_FUNCTION("writeToAshmem", NAPIAshmem::WriteToAshmem),
        DECLARE_ani_FUNCTION("writeAshmem", NAPIAshmem::WriteAshmem),
        DECLARE_ani_FUNCTION("writeDataToAshmem", NAPIAshmem::WriteDataToAshmem),
        DECLARE_ani_FUNCTION("readDataFromAshmem", NAPIAshmem::ReadDataFromAshmem),
        DECLARE_ani_STATIC_PROPERTY("PROT_EXEC", exec),
        DECLARE_ani_STATIC_PROPERTY("PROT_NONE", none),
        DECLARE_ani_STATIC_PROPERTY("PROT_READ", read),
        DECLARE_ani_STATIC_PROPERTY("PROT_WRITE", write),
    };
    ani_value constructor = nullptr;
    ani_define_class(env, className.c_str(), className.length(), Ashmem_JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    ani_ASSERT(env, constructor != nullptr, "define js class Ashmem failed");
    ani_status status = ani_set_named_property(env, exports, "Ashmem", constructor);
    ani_ASSERT(env, status == ani_ok, "set property Ashmem failed");
    ani_value global = nullptr;
    status = ani_get_global(env, &global);
    ani_ASSERT(env, status == ani_ok, "get napi global failed");
    status = ani_set_named_property(env, global, "AshmemConstructor_", constructor);
    ani_ASSERT(env, status == ani_ok, "set Ashmem constructor failed");
    return exports;
}

ani_value NAPIAshmem::Ashmem_JS_Constructor(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 2;
    ani_value argv[ARGV_LENGTH_2] = { 0 };
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    if (argc == 0) {
        napiAshmem = new (std::nothrow) NAPIAshmem();
    } else {
        ani_ASSERT(env, argc == 2, "requires 2 parameter");
        ani_valuetype valueType = ani_null;
        ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
        ani_ASSERT(env, valueType == ani_string, "type mismatch for parameter 1");
        ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
        ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 2");
        size_t bufferSize = 0;
        size_t maxLen = 40960;
        ani_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
        ani_ASSERT(env, bufferSize < maxLen, "string length too large");
        char stringValue[bufferSize + 1];
        size_t jsStringLength = 0;
        ani_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
        ani_ASSERT(env, jsStringLength == bufferSize, "string length wrong");
        std::string ashmemName = stringValue;
        uint32_t ashmemSize = 0;
        ani_get_value_uint32(env, argv[ARGV_INDEX_1], &ashmemSize);
        // new napi Ashmem
        sptr<Ashmem> nativeAshmem = Ashmem::CreateAshmem(ashmemName.c_str(), ashmemSize);
        ani_ASSERT(env, nativeAshmem != nullptr, "invalid parameters");
        napiAshmem = new (std::nothrow) NAPIAshmem(nativeAshmem);
    }
    ani_ASSERT(env, napiAshmem != nullptr, "new NAPIAshmem failed");
    // connect native object to js thisVar
    ani_status status = ani_wrap(
        env, thisVar, napiAshmem,
        [](ani_env env, void *data, void *hint) {
            ZLOGD(LOG_LABEL, "Ashmem destructed by js callback");
            delete (reinterpret_cast<NAPIAshmem *>(data));
        },
        nullptr, nullptr);
    if (status != ani_ok) {
        delete napiAshmem;
        ani_ASSERT(env, false, "wrap js Ashmem and native holder failed");
    }
    return thisVar;
}
} // namespace OHOS

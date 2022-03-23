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

#include "napi_ashmem.h"
#include <unistd.h>
#include "ipc_debug.h"
#include "log_tags.h"
#include "securec.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "napi_ashmem" };
#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
static constexpr int MMAP_PROT_MAX = 7;

NAPIAshmem::NAPIAshmem(sptr<Ashmem> &ashmem) : ashmem_(ashmem)
{
    if (ashmem == nullptr) {
        ZLOGE(LOG_LABEL, "%s: ashmem is null", __func__);
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
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 2, "requires 2 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return nullptr;
    }
    size_t bufferSize = 0;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &bufferSize);
    if (bufferSize <= 0) {
        ZLOGE(LOG_LABEL, "invalid ashmem name");
        return nullptr;
    }
    napi_typeof(env, argv[1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return nullptr;
    }
    int32_t ashmemSize = 0;
    napi_get_value_int32(env, argv[1], &ashmemSize);
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
    napi_value argv[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "AshmemConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get Ashmem constructor failed");
    bool isAshmem = false;
    napi_instanceof(env, argv[0], constructor, &isAshmem);
    NAPI_ASSERT(env, isAshmem == true, "parameter is not instanceof Ashmem");
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, argv[0], (void **)&napiAshmem);
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
    napi_value argv[1] = {0};
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    uint32_t mapType = 0;
    napi_get_value_uint32(env, argv[0], &mapType);
    NAPI_ASSERT(env, mapType <= MMAP_PROT_MAX, "napiAshmem mapType error");
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->MapAshmem(mapType);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
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

napi_value NAPIAshmem::ReadFromAshmem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 2, "requires 2 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    uint32_t size = 0;
    uint32_t offset = 0;
    napi_get_value_uint32(env, argv[0], &size);
    napi_get_value_uint32(env, argv[1], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    const void  *result = napiAshmem->GetAshmem()->ReadFromAshmem(size, offset);
    if (result == nullptr) {
        DBINDER_LOGE("ashmem->ReadFromAshmem returns null");
        return nullptr;
    }
    // c++ byte[] to js []
    napi_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    napi_create_arraybuffer(env, size, &arrayBufferPtr, &arrayBuffer);
    napi_value typedarray = nullptr;
    napi_create_typedarray(env, napi_int8_array, size, arrayBuffer, 0, &typedarray);
    bool isTypedArray = false;
    napi_is_typedarray(env, typedarray, &isTypedArray);
    NAPI_ASSERT(env, isTypedArray == true, "create  TypedArray failed");
    if (size == 0) {
        return typedarray;
    }
    errno_t status = memcpy_s(arrayBufferPtr, size, result, size);
    NAPI_ASSERT(env, status == EOK, "memcpy_s is failed");
    return typedarray;
}

napi_value NAPIAshmem::SetProtection(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    uint32_t protectionType = 0;
    napi_get_value_uint32(env, argv[0], &protectionType);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    bool result = napiAshmem->GetAshmem()->SetProtection(protectionType);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
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
    napi_value argv[3] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 3, "requires 1 parameter");
    bool isTypedArray = false;
    napi_is_typedarray(env, argv[0], &isTypedArray);
    NAPI_ASSERT(env, isTypedArray == true, "type mismatch for parameter 1");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    napi_typeof(env, argv[2], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 3");
    napi_typedarray_type typedarrayType = napi_uint8_array;
    size_t typedarrayLength = 0;
    void *typedarrayBufferPtr = nullptr;
    napi_value tmpArrayBuffer = nullptr;
    size_t byteOffset = 0;
    napi_get_typedarray_info(env, argv[0], &typedarrayType, &typedarrayLength, &typedarrayBufferPtr,
        &tmpArrayBuffer, &byteOffset);
    NAPI_ASSERT(env, typedarrayType == napi_int8_array, "array type mismatch for parameter 1");
    DBINDER_LOGI("ashmem WriteBuffer typedarrayLength = %{public}d", (int)(typedarrayLength));
    uint32_t size = 0;
    napi_get_value_uint32(env, argv[1], &size);
    uint32_t offset = 0;
    napi_get_value_uint32(env, argv[2], &offset);
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiAshmem);
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    // need check size offset and capacity
    bool result = napiAshmem->GetAshmem()->WriteToAshmem(typedarrayBufferPtr, size, offset);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
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
        DECLARE_NAPI_STATIC_FUNCTION("createAshmemFromExisting", NAPIAshmem::CreateAshmemFromExisting),
        DECLARE_NAPI_FUNCTION("closeAshmem", NAPIAshmem::CloseAshmem),
        DECLARE_NAPI_FUNCTION("getAshmemSize", NAPIAshmem::GetAshmemSize),
        DECLARE_NAPI_FUNCTION("mapAshmem", NAPIAshmem::MapAshmem),
        DECLARE_NAPI_FUNCTION("mapReadAndWriteAshmem", NAPIAshmem::MapReadAndWriteAshmem),
        DECLARE_NAPI_FUNCTION("mapReadOnlyAshmem", NAPIAshmem::MapReadOnlyAshmem),
        DECLARE_NAPI_FUNCTION("readFromAshmem", NAPIAshmem::ReadFromAshmem),
        DECLARE_NAPI_FUNCTION("setProtection", NAPIAshmem::SetProtection),
        DECLARE_NAPI_FUNCTION("unmapAshmem", NAPIAshmem::UnmapAshmem),
        DECLARE_NAPI_FUNCTION("writeToAshmem", NAPIAshmem::WriteToAshmem),
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
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPIAshmem *napiAshmem = nullptr;
    if (argc == 0) {
        napiAshmem = new NAPIAshmem();
    } else {
        NAPI_ASSERT(env, argc == 2, "requires 2 parameter");
        napi_valuetype valueType = napi_null;
        napi_typeof(env, argv[0], &valueType);
        NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");
        napi_typeof(env, argv[1], &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
        size_t bufferSize = 0;
        size_t maxLen = 40960;
        napi_get_value_string_utf8(env, argv[0], nullptr, 0, &bufferSize);
        NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");
        char stringValue[bufferSize + 1];
        size_t jsStringLength = 0;
        napi_get_value_string_utf8(env, argv[0], stringValue, bufferSize + 1, &jsStringLength);
        NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");
        std::string ashmemName = stringValue;
        uint32_t ashmemSize = 0;
        napi_get_value_uint32(env, argv[1], &ashmemSize);
        // new napi Ashmem
        sptr<Ashmem> nativeAshmem = Ashmem::CreateAshmem(ashmemName.c_str(), ashmemSize);
        NAPI_ASSERT(env, nativeAshmem != nullptr, "invalid parameters");
        napiAshmem = new NAPIAshmem(nativeAshmem);
    }
    // connect native object to js thisVar
    napi_status status = napi_wrap(
        env, thisVar, napiAshmem,
        [](napi_env env, void *data, void *hint) {
            DBINDER_LOGI("Ashmem destructed by js callback");
            delete (reinterpret_cast<NAPIAshmem *>(data));
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "wrap js Ashmem and native holder failed");
    return thisVar;
}
}

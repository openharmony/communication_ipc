/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "napi_message_parcel.h"
#include <cstring>
#include <unistd.h>
#include "hilog/log.h"
#include "log_tags.h"
#include "napi_ashmem.h"
#include "napi_remote_object.h"
#include "napi_rpc_common.h"
#include "string_ex.h"
#include "ipc_debug.h"


namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "Napi_MessageParcelRead" };

napi_value NAPI_MessageParcel::JS_readRemoteObject(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    sptr<IRemoteObject> value = napiParcel->nativeParcel_->ReadRemoteObject();
    napi_value napiValue = NAPI_ohos_rpc_CreateJsRemoteObject(env, value);
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readInterfaceToken(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    std::u16string parcelString = napiParcel->nativeParcel_->ReadInterfaceToken();
    std::string outString = Str16ToStr8(parcelString.c_str());
    napi_value napiValue = nullptr;
    napi_create_string_utf8(env, outString.c_str(), outString.length(), &napiValue);
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readException(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t code = napiParcel->nativeParcel_->ReadInt32();
    if (code == 0) {
        return result;
    }
    std::u16string str = napiParcel->nativeParcel_->ReadString16();
    napi_throw_error(env, nullptr, Str16ToStr8(str).c_str());
    return result;
}

napi_value NAPI_MessageParcel::JS_readByte(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int8_t value = napiParcel->nativeParcel_->ReadInt8();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readShort(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int16_t value = napiParcel->nativeParcel_->ReadInt16();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readInt(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int32_t value = napiParcel->nativeParcel_->ReadInt32();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readLong(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int64_t value = napiParcel->nativeParcel_->ReadInt64();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int64(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readFloat(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    double value = napiParcel->nativeParcel_->ReadDouble();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_double(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readDouble(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    double value = napiParcel->nativeParcel_->ReadDouble();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_double(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readBoolean(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int8_t value = napiParcel->nativeParcel_->ReadInt8();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readChar(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    uint8_t value = napiParcel->nativeParcel_->ReadUint8();
    napi_value result = nullptr;
    napi_create_uint32(env, static_cast<uint32_t>(value), &result);
    return result;
}

napi_value NAPI_MessageParcel::JS_readString(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    std::u16string parcelString = napiParcel->nativeParcel_->ReadString16();
    std::string outString = Str16ToStr8(parcelString.c_str());
    napi_value napiValue = nullptr;
    napi_create_string_utf8(env, outString.c_str(), outString.length(), &napiValue);
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readSequenceable(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int32_t len = napiParcel->nativeParcel_->ReadInt32();
    if (len > 0) {
        napi_value propKey = nullptr;
        const char *propKeyStr = "unmarshalling";
        napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
        napi_value prop = nullptr;
        napi_get_property(env, argv[ARGV_INDEX_0], propKey, &prop);

        napi_value funcArg[1] = {thisVar};
        napi_value callResult = nullptr;
        napi_call_function(env, argv[ARGV_INDEX_0], prop, 1, funcArg, &callResult);
        if (callResult != nullptr) {
            return callResult;
        }
        ZLOGI(LOG_LABEL, "call unmarshalling failed");
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, false, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readByteArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    uint32_t maxBytesLen = 40960;
    uint32_t arrayLength = napiParcel->nativeParcel_->ReadUint32();
    NAPI_ASSERT(env, arrayLength < maxBytesLen, "byte array length too large");

    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < arrayLength; i++) {
            int8_t val = napiParcel->nativeParcel_->ReadInt8();
            napi_value num = nullptr;
            napi_create_int32(env, val, &num);
            napi_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength == 0) {
        napi_value result = nullptr;
        napi_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiParcel);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int8_t val = napiParcel->nativeParcel_->ReadInt8();
        napi_value num = nullptr;
        napi_create_int32(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readShortArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int16_t val = napiParcel->nativeParcel_->ReadInt16();
            napi_value num = nullptr;
            napi_create_int32(env, val, &num);
            napi_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        napi_value result = nullptr;
        napi_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int16_t val = napiParcel->nativeParcel_->ReadInt16();
        napi_value num = nullptr;
        napi_create_int32(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readIntArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int32_t val = napiParcel->nativeParcel_->ReadInt32();
            napi_value num = nullptr;
            napi_create_int32(env, val, &num);
            napi_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        napi_value result = nullptr;
        napi_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int32_t val = napiParcel->nativeParcel_->ReadInt32();
        napi_value num = nullptr;
        napi_create_int32(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readLongArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_64, napiParcel);
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int64_t val = napiParcel->nativeParcel_->ReadInt64();
            napi_value num = nullptr;
            napi_create_int64(env, val, &num);
            napi_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        napi_value result = nullptr;
        napi_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_64, napiParcel);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int64_t val = napiParcel->nativeParcel_->ReadInt64();
        napi_value num = nullptr;
        napi_create_int64(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readFloatArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel);
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            double val = napiParcel->nativeParcel_->ReadDouble();
            napi_value num = nullptr;
            napi_create_double(env, val, &num);
            napi_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        napi_value result = nullptr;
        napi_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        double val = napiParcel->nativeParcel_->ReadDouble();
        napi_value num = nullptr;
        napi_create_double(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readDoubleArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel);
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            double val = napiParcel->nativeParcel_->ReadDouble();
            napi_value num = nullptr;
            napi_create_double(env, val, &num);
            napi_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        napi_value result = nullptr;
        napi_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        double val = napiParcel->nativeParcel_->ReadDouble();
        napi_value num = nullptr;
        napi_create_double(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readBooleanArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int8_t val = napiParcel->nativeParcel_->ReadInt8();
            napi_value boolean = nullptr;
            napi_get_boolean(env, val, &boolean);
            napi_set_element(env, argv[ARGV_INDEX_0], i, boolean);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        napi_value result = nullptr;
        napi_create_array(env, &result);
        return result;
    }

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int8_t val = napiParcel->nativeParcel_->ReadInt8();
        napi_value boolean = nullptr;
        napi_get_boolean(env, val, &boolean);
        napi_set_element(env, result, i, boolean);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readCharArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    uint32_t arrayLength = napiParcel->nativeParcel_->ReadUint32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            uint8_t val = napiParcel->nativeParcel_->ReadUint8();
            napi_value num = nullptr;
            napi_create_uint32(env, static_cast<uint32_t>(val), &num);
            napi_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength == 0) {
        napi_value result = nullptr;
        napi_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        uint8_t val = napiParcel->nativeParcel_->ReadUint8();
        napi_value num = nullptr;
        napi_create_uint32(env, static_cast<uint32_t>(val), &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readStringArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    uint32_t arrayLength = napiParcel->nativeParcel_->ReadUint32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        napi_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            if (napiParcel->nativeParcel_->GetReadableBytes() <= 0) {
                break;
            }
            std::u16string parcelString = napiParcel->nativeParcel_->ReadString16();
            std::string outString = Str16ToStr8(parcelString.c_str());
            napi_value val = nullptr;
            napi_create_string_utf8(env, outString.c_str(), outString.length(), &val);
            napi_set_element(env, argv[ARGV_INDEX_0], i, val);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    napi_value result = nullptr;
    napi_create_array(env, &result);
    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        if (napiParcel->nativeParcel_->GetReadableBytes() <= 0) {
            break;
        }
        std::u16string parcelString = napiParcel->nativeParcel_->ReadString16();
        std::string outString = Str16ToStr8(parcelString.c_str());
        napi_value val = nullptr;
        napi_create_string_utf8(env, outString.c_str(), outString.length(), &val);
        napi_set_element(env, result, i, val);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_readSequenceableArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value thisVar = nullptr;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    // checking here is not accurate, but we can defend some extreme attacking case.
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiParcel);

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");
    uint32_t length = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &length);
    if (static_cast<int32_t>(length) != arrayLength) {
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        napi_throw_error(env, nullptr, "Bad length while reading Sequenceable array");
        return result;
    }

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int32_t len = napiParcel->nativeParcel_->ReadInt32();
        if (len > 0) {
            bool hasElement = false;
            napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
            NAPI_ASSERT(env, hasElement == true, "parameter check error");
            napi_value element = nullptr;
            napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

            napi_value propKey = nullptr;
            const char *propKeyStr = "unmarshalling";
            napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
            napi_value prop = nullptr;
            napi_get_property(env, element, propKey, &prop);

            napi_value funcArg[1] = { thisVar };
            napi_value callResult = nullptr;
            napi_call_function(env, element, prop, 1, funcArg, &callResult);
            if (callResult == nullptr) {
                ZLOGE(LOG_LABEL, "call unmarshalling failed, element index:%{public}d", i);
                break;
            }
        }
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageParcel::JS_readRemoteObjectArray(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 0;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) { // uses passed in array
        NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
        napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        bool isArray = false;
        napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");
        uint32_t length = 0;
        napi_get_array_length(env, argv[ARGV_INDEX_0], &length);
        if (static_cast<int32_t>(length) != arrayLength) {
            return result;
        }
        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            sptr<IRemoteObject> value = napiParcel->nativeParcel_->ReadRemoteObject();
            napi_value napiValue = NAPI_ohos_rpc_CreateJsRemoteObject(env, value);
            napi_set_element(env, argv[ARGV_INDEX_0], i, napiValue);
        }
        return result;
    }

    if (arrayLength <= 0) {
        napi_get_null(env, &result);
        return result;
    }
    napi_create_array(env, &result);
    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        sptr<IRemoteObject> value = napiParcel->nativeParcel_->ReadRemoteObject();
        napi_value napiValue = NAPI_ohos_rpc_CreateJsRemoteObject(env, value);
        napi_set_element(env, result, i, napiValue);
    }
    return result;
}

napi_value NAPI_MessageParcel::JS_ReadFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    int32_t result = napiParcel->nativeParcel_->ReadFileDescriptor();
    napi_value napiValue;
    napi_create_int32(env, result, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_ReadAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    sptr<Ashmem> nativeAshmem = napiParcel->nativeParcel_->ReadAshmem();
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "AshmemConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get Ashmem constructor failed");
    napi_value jsAshmem;
    status = napi_new_instance(env, constructor, 0, nullptr, &jsAshmem);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js Ashmem");
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, jsAshmem, reinterpret_cast<void **>(&napiAshmem));
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    napiAshmem->SetAshmem(nativeAshmem);
    return jsAshmem;
}

napi_value NAPI_MessageParcel::JS_ReadRawData(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    int32_t arraySize = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &arraySize);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    const void *rawData = napiParcel->nativeParcel_->ReadRawData(arraySize * BYTE_SIZE_32);
    NAPI_ASSERT_BASE(env, rawData != nullptr, "rawData is null", nullptr);
    // [c++] rawData -> byteBuffer()[js]
    napi_value result = nullptr;
    if (arraySize <= 0) {
        napi_create_array(env, &result);
        return result;
    }
    napi_create_array_with_length(env, (size_t)arraySize, &result);
    const int32_t *ptr = static_cast<const int32_t *>(rawData);
    for (uint32_t i = 0; i < (uint32_t)arraySize; i++) {
        napi_value num = nullptr;
        napi_create_int32(env, ptr[i], &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}
} // namespace OHOS

/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "ani_message_parcel.h"
#include <cstring>
#include <unistd.h>
#include "hilog/log.h"
#include "log_tags.h"
#include "ani_ashmem.h"
#include "ani_remote_object.h"
#include "ani_rpc_common.h"
#include "string_ex.h"
#include "ipc_debug.h"


namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "ani_MessageParcelRead" };

ani_value ani_MessageParcel::JS_readRemoteObject(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    sptr<IRemoteObject> value = napiParcel->nativeParcel_->ReadRemoteObject();
    ani_value napiValue = ani_ohos_rpc_CreateJsRemoteObject(env, value);
    return napiValue;
}

ani_value ani_MessageParcel::JS_readInterfaceToken(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    std::u16string parcelString = napiParcel->nativeParcel_->ReadInterfaceToken();
    std::string outString = Str16ToStr8(parcelString.c_str());
    ani_value napiValue = nullptr;
    ani_create_string_utf8(env, outString.c_str(), outString.length(), &napiValue);
    return napiValue;
}

ani_value ani_MessageParcel::JS_readException(ani_env env, ani_callback_info info)
{
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t code = napiParcel->nativeParcel_->ReadInt32();
    if (code == 0) {
        return result;
    }
    std::u16string str = napiParcel->nativeParcel_->ReadString16();
    ani_throw_error(env, nullptr, Str16ToStr8(str).c_str());
    return result;
}

ani_value ani_MessageParcel::JS_readByte(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int8_t value = napiParcel->nativeParcel_->ReadInt8();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_int32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_readShort(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int16_t value = napiParcel->nativeParcel_->ReadInt16();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_int32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_readInt(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int32_t value = napiParcel->nativeParcel_->ReadInt32();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_int32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_readLong(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int64_t value = napiParcel->nativeParcel_->ReadInt64();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_int64(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_readFloat(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    double value = napiParcel->nativeParcel_->ReadDouble();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_double(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_readDouble(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    double value = napiParcel->nativeParcel_->ReadDouble();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_double(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_readBoolean(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int8_t value = napiParcel->nativeParcel_->ReadInt8();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_readChar(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    uint8_t value = napiParcel->nativeParcel_->ReadUint8();
    ani_value result = nullptr;
    ani_create_uint32(env, static_cast<uint32_t>(value), &result);
    return result;
}

ani_value ani_MessageParcel::JS_readString(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    std::u16string parcelString = napiParcel->nativeParcel_->ReadString16();
    std::string outString = Str16ToStr8(parcelString);
    ani_value napiValue = nullptr;
    ani_create_string_utf8(env, outString.c_str(), outString.length(), &napiValue);
    return napiValue;
}

ani_value ani_MessageParcel::JS_readSequenceable(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    int32_t len = napiParcel->nativeParcel_->ReadInt32();
    if (len > 0) {
        ani_value propKey = nullptr;
        const char *propKeyStr = "unmarshalling";
        ani_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
        ani_value prop = nullptr;
        ani_get_property(env, argv[ARGV_INDEX_0], propKey, &prop);

        ani_value funcArg[1] = {thisVar};
        ani_value callResult = nullptr;
        ani_call_function(env, argv[ARGV_INDEX_0], prop, 1, funcArg, &callResult);
        if (callResult != nullptr) {
            return callResult;
        }
        ZLOGI(LOG_LABEL, "call unmarshalling failed");
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, false, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_readByteArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    uint32_t maxBytesLen = 40960;
    uint32_t arrayLength = napiParcel->nativeParcel_->ReadUint32();
    ani_ASSERT(env, arrayLength < maxBytesLen, "byte array length too large");

    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < arrayLength; i++) {
            int8_t val = napiParcel->nativeParcel_->ReadInt8();
            ani_value num = nullptr;
            ani_create_int32(env, val, &num);
            ani_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength == 0) {
        ani_value result = nullptr;
        ani_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiParcel);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int8_t val = napiParcel->nativeParcel_->ReadInt8();
        ani_value num = nullptr;
        ani_create_int32(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readShortArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int16_t val = napiParcel->nativeParcel_->ReadInt16();
            ani_value num = nullptr;
            ani_create_int32(env, val, &num);
            ani_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        ani_value result = nullptr;
        ani_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int16_t val = napiParcel->nativeParcel_->ReadInt16();
        ani_value num = nullptr;
        ani_create_int32(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readIntArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int32_t val = napiParcel->nativeParcel_->ReadInt32();
            ani_value num = nullptr;
            ani_create_int32(env, val, &num);
            ani_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        ani_value result = nullptr;
        ani_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int32_t val = napiParcel->nativeParcel_->ReadInt32();
        ani_value num = nullptr;
        ani_create_int32(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readLongArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_64, napiParcel);
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int64_t val = napiParcel->nativeParcel_->ReadInt64();
            ani_value num = nullptr;
            ani_create_int64(env, val, &num);
            ani_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        ani_value result = nullptr;
        ani_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_64, napiParcel);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int64_t val = napiParcel->nativeParcel_->ReadInt64();
        ani_value num = nullptr;
        ani_create_int64(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readFloatArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel);
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            double val = napiParcel->nativeParcel_->ReadDouble();
            ani_value num = nullptr;
            ani_create_double(env, val, &num);
            ani_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        ani_value result = nullptr;
        ani_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        double val = napiParcel->nativeParcel_->ReadDouble();
        ani_value num = nullptr;
        ani_create_double(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readDoubleArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel);
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            double val = napiParcel->nativeParcel_->ReadDouble();
            ani_value num = nullptr;
            ani_create_double(env, val, &num);
            ani_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        ani_value result = nullptr;
        ani_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        double val = napiParcel->nativeParcel_->ReadDouble();
        ani_value num = nullptr;
        ani_create_double(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readBooleanArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int8_t val = napiParcel->nativeParcel_->ReadInt8();
            ani_value boolean = nullptr;
            ani_get_boolean(env, val, &boolean);
            ani_set_element(env, argv[ARGV_INDEX_0], i, boolean);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength <= 0) {
        ani_value result = nullptr;
        ani_create_array(env, &result);
        return result;
    }

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int8_t val = napiParcel->nativeParcel_->ReadInt8();
        ani_value boolean = nullptr;
        ani_get_boolean(env, val, &boolean);
        ani_set_element(env, result, i, boolean);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readCharArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    uint32_t arrayLength = napiParcel->nativeParcel_->ReadUint32();
    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            uint8_t val = napiParcel->nativeParcel_->ReadUint8();
            ani_value num = nullptr;
            ani_create_uint32(env, static_cast<uint32_t>(val), &num);
            ani_set_element(env, argv[ARGV_INDEX_0], i, num);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    if (arrayLength == 0) {
        ani_value result = nullptr;
        ani_create_array(env, &result);
        return result;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        uint8_t val = napiParcel->nativeParcel_->ReadUint8();
        ani_value num = nullptr;
        ani_create_uint32(env, static_cast<uint32_t>(val), &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readStringArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    uint32_t arrayLength = napiParcel->nativeParcel_->ReadUint32();
    if (argc > 0) {
        ani_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
        ani_value argv[ARGV_LENGTH_1] = {0};
        void *data = nullptr;
        ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            if (napiParcel->nativeParcel_->GetReadableBytes() <= 0) {
                break;
            }
            std::u16string parcelString = napiParcel->nativeParcel_->ReadString16();
            std::string outString = Str16ToStr8(parcelString);
            ani_value val = nullptr;
            ani_create_string_utf8(env, outString.c_str(), outString.length(), &val);
            ani_set_element(env, argv[ARGV_INDEX_0], i, val);
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel);
    ani_value result = nullptr;
    ani_create_array(env, &result);
    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        if (napiParcel->nativeParcel_->GetReadableBytes() <= 0) {
            break;
        }
        std::u16string parcelString = napiParcel->nativeParcel_->ReadString16();
        std::string outString = Str16ToStr8(parcelString);
        ani_value val = nullptr;
        ani_create_string_utf8(env, outString.c_str(), outString.length(), &val);
        ani_set_element(env, result, i, val);
    }
    return result;
}

ani_value ani_MessageParcel::JS_readSequenceableArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value thisVar = nullptr;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    // checking here is not accurate, but we can defend some extreme attacking case.
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiParcel);

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");
    uint32_t length = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &length);
    if (static_cast<int32_t>(length) != arrayLength) {
        ani_value result = nullptr;
        ani_get_undefined(env, &result);
        ani_throw_error(env, nullptr, "Bad length while reading Sequenceable array");
        return result;
    }

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int32_t len = napiParcel->nativeParcel_->ReadInt32();
        if (len > 0) {
            bool hasElement = false;
            ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
            ani_ASSERT(env, hasElement == true, "parameter check error");
            ani_value element = nullptr;
            ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

            ani_value propKey = nullptr;
            const char *propKeyStr = "unmarshalling";
            ani_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
            ani_value prop = nullptr;
            ani_get_property(env, element, propKey, &prop);

            ani_value funcArg[1] = { thisVar };
            ani_value callResult = nullptr;
            ani_call_function(env, element, prop, 1, funcArg, &callResult);
            if (callResult == nullptr) {
                ZLOGE(LOG_LABEL, "call unmarshalling failed, element index:%{public}d", i);
                break;
            }
        }
    }
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageParcel::JS_readRemoteObjectArray(ani_env env, ani_callback_info info)
{
    ani_value result = nullptr;
    ani_get_undefined(env, &result);

    size_t argc = 0;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) { // uses passed in array
        ani_ASSERT(env, argc == 1, "requires 1 parameter");
        ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        bool isArray = false;
        ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
        ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");
        uint32_t length = 0;
        ani_get_array_length(env, argv[ARGV_INDEX_0], &length);
        if (static_cast<int32_t>(length) != arrayLength) {
            return result;
        }
        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            sptr<IRemoteObject> value = napiParcel->nativeParcel_->ReadRemoteObject();
            CHECK_BREAK(value != nullptr);
            ani_value napiValue = ani_ohos_rpc_CreateJsRemoteObject(env, value);
            ani_set_element(env, argv[ARGV_INDEX_0], i, napiValue);
        }
        return result;
    }

    if (arrayLength <= 0) {
        ani_get_null(env, &result);
        return result;
    }
    ani_create_array(env, &result);
    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        sptr<IRemoteObject> value = napiParcel->nativeParcel_->ReadRemoteObject();
        CHECK_BREAK(value != nullptr);
        ani_value napiValue = ani_ohos_rpc_CreateJsRemoteObject(env, value);
        ani_set_element(env, result, i, napiValue);
    }
    return result;
}

ani_value ani_MessageParcel::JS_ReadFileDescriptor(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    int32_t result = napiParcel->nativeParcel_->ReadFileDescriptor();
    ani_value napiValue;
    ani_create_int32(env, result, &napiValue);
    return napiValue;
}

ani_value ani_MessageParcel::JS_ReadAshmem(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    sptr<Ashmem> nativeAshmem = napiParcel->nativeParcel_->ReadAshmem();
    ani_value global = nullptr;
    ani_status status = ani_get_global(env, &global);
    ani_ASSERT(env, status == ani_ok, "get napi global failed");
    ani_value constructor = nullptr;
    status = ani_get_named_property(env, global, "AshmemConstructor_", &constructor);
    ani_ASSERT(env, status == ani_ok, "get Ashmem constructor failed");
    ani_value jsAshmem;
    status = ani_new_instance(env, constructor, 0, nullptr, &jsAshmem);
    ani_ASSERT(env, status == ani_ok, "failed to  construct js Ashmem");
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, jsAshmem, reinterpret_cast<void **>(&napiAshmem));
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    napiAshmem->SetAshmem(nativeAshmem);
    return jsAshmem;
}

ani_value ani_MessageParcel::JS_ReadRawData(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameters");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");
    int32_t arraySize = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &arraySize);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    const void *rawData = napiParcel->nativeParcel_->ReadRawData(arraySize * BYTE_SIZE_32);
    ani_ASSERT_BASE(env, rawData != nullptr, "rawData is null", nullptr);
    // [c++] rawData -> byteBuffer()[js]
    ani_value result = nullptr;
    if (arraySize <= 0) {
        ani_create_array(env, &result);
        return result;
    }
    ani_create_array_with_length(env, (size_t)arraySize, &result);
    const int32_t *ptr = static_cast<const int32_t *>(rawData);
    for (uint32_t i = 0; i < (uint32_t)arraySize; i++) {
        ani_value num = nullptr;
        ani_create_int32(env, ptr[i], &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}
} // namespace OHOS

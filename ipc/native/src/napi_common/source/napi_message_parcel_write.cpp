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
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "Napi_MessageParcelWrite" };

NAPI_MessageParcel::NAPI_MessageParcel(napi_env env, napi_value thisVar, MessageParcel *parcel)
{
    env_ = env;
    maxCapacityToWrite_ = MAX_CAPACITY_TO_WRITE;
    // do NOT reference js parcel here
    if (parcel == nullptr) {
        nativeParcel_ = std::make_shared<MessageParcel>();
        owner = true;
    } else {
        nativeParcel_ = std::shared_ptr<MessageParcel>(parcel, release);
        owner = false;
    }
}

NAPI_MessageParcel::~NAPI_MessageParcel()
{
    ZLOGD(LOG_LABEL, "NAPI_MessageParcel::Destructor");
    nativeParcel_ = nullptr;
    env_ = nullptr;
}

void NAPI_MessageParcel::release(MessageParcel *parcel)
{
    ZLOGD(LOG_LABEL, "message parcel is created by others, do nothing");
}

std::shared_ptr<MessageParcel> NAPI_MessageParcel::GetMessageParcel()
{
    return nativeParcel_;
}

napi_value NAPI_MessageParcel::JS_writeByte(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    int32_t value = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeShort(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    int32_t value = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt16(static_cast<int16_t>(value));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeInt(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    int32_t value = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt32(value);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeLong(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    int64_t value = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_64, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt64(value);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeFloat(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    double value = 0;
    napi_get_value_double(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, sizeof(double), napiParcel);
    bool result = napiParcel->nativeParcel_->WriteDouble(value);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeDouble(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    double value = 0;
    napi_get_value_double(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, sizeof(double), napiParcel);
    bool result = napiParcel->nativeParcel_->WriteDouble(value);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeBoolean(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_boolean, "type mismatch for parameter 1");

    bool value = 0;
    napi_get_value_bool(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeChar(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t value = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteUint8(static_cast<uint8_t>(value));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeByteArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    uint32_t maxBytesLen = 40960;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);
    NAPI_ASSERT(env, arrayLength < maxBytesLen, "write byte array length too large");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_8 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        result = napiParcel->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeShortArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        result = napiParcel->nativeParcel_->WriteInt16(static_cast<int16_t>(value));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeIntArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        napi_valuetype valueType;
        napi_typeof(env, element, &valueType);
        NAPI_ASSERT(env, valueType == napi_number, "type mismatch element");

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        result = napiParcel->nativeParcel_->WriteInt32(value);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeLongArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);
    ZLOGI(LOG_LABEL, "messageparcel WriteBuffer typedarrayLength:%{public}d", (int)(arrayLength));

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + BYTE_SIZE_64 * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int64_t value = 0;
        napi_get_value_int64(env, element, &value);

        result = napiParcel->nativeParcel_->WriteInt64(value);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeFloatArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + sizeof(double) * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        double value = 0;
        napi_get_value_double(env, element, &value);

        result = napiParcel->nativeParcel_->WriteDouble(value);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeDoubleArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + sizeof(double) * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        double value = 0;
        napi_get_value_double(env, element, &value);

        result = napiParcel->nativeParcel_->WriteDouble(value);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeBooleanArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        bool value = 0;
        napi_get_value_bool(env, element, &value);

        result = napiParcel->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeCharArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        uint32_t value = 0;
        napi_get_value_uint32(env, element, &value);

        result = napiParcel->nativeParcel_->WriteUint8(static_cast<uint8_t>(value));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeString(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");

    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");

    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * bufferSize, napiParcel);
    std::string parcelString = stringValue;
    bool result = napiParcel->nativeParcel_->WriteString16(to_utf16(parcelString));

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeStringArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        size_t maxSize = 40960;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valuetype;
        napi_typeof(env, element, &valuetype);
        NAPI_ASSERT(env, valuetype == napi_string, "Parameter type error");

        size_t bufferSize = 0;
        napi_get_value_string_utf8(env, element, nullptr, 0, &bufferSize);
        NAPI_ASSERT(env, bufferSize < maxSize, "string length too large");

        char stringValue[bufferSize + 1];
        size_t jsStringLength = 0;
        napi_get_value_string_utf8(env, element, stringValue, bufferSize + 1, &jsStringLength);
        NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");

        REWIND_IF_WRITE_CHECK_FAIL(env, BYTE_SIZE_32 * bufferSize, pos, napiParcel);
        std::string parcelString = stringValue;
        result = napiParcel->nativeParcel_->WriteString16(to_utf16(parcelString));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeSequenceable(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_boolean(env, false, &result);

    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType == napi_null || valueType == napi_undefined) {
        napiParcel->nativeParcel_->WriteInt32(0);
        return result;
    }
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteInt32(1);
    napi_value propKey = nullptr;
    const char *propKeyStr = "marshalling";
    napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
    napi_value prop = nullptr;
    napi_get_property(env, argv[ARGV_INDEX_0], propKey, &prop);

    napi_value funcArg[1] = { thisVar };
    napi_value callResult = nullptr;
    napi_call_function(env, argv[ARGV_INDEX_0], prop, 1, funcArg, &callResult);
    napi_typeof(env, callResult, &valueType);
    if (callResult != nullptr && valueType != napi_undefined) {
        return callResult;
    }
    ZLOGE(LOG_LABEL, "call mashalling failed");
    napiParcel->nativeParcel_->RewindWrite(pos);
    return result;
}

napi_value NAPI_MessageParcel::JS_writeSequenceableArray(napi_env env, napi_callback_info info)
{
    napi_value retValue = nullptr;
    napi_get_boolean(env, false, &retValue);

    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT_BASE(env, argc == 1, "requires 1 parameter", retValue);

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT_BASE(env, isArray == true, "type mismatch for parameter 1", retValue);
    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", retValue);

    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    bool result = napiParcel->nativeParcel_->WriteUint32(arrayLength);
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT_BASE(env, hasElement == true, "parameter check error", retValue);

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valueType = napi_null;
        napi_typeof(env, element, &valueType);
        if (valueType == napi_null || valueType == napi_undefined) {
            napiParcel->nativeParcel_->WriteInt32(0);
            continue;
        } else {
            napiParcel->nativeParcel_->WriteInt32(1);
        }
        napi_value propKey = nullptr;
        const char *propKeyStr = "marshalling";
        napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
        napi_value prop = nullptr;
        napi_get_property(env, element, propKey, &prop);

        napi_value funcArg[1] = { thisVar };
        napi_value callResult = nullptr;
        napi_call_function(env, element, prop, 1, funcArg, &callResult);
        napi_typeof(env, callResult, &valueType);
        if (callResult == nullptr || valueType == napi_undefined) {
            ZLOGE(LOG_LABEL, "call mashalling failed, element index:%{public}zu", i);
            napiParcel->nativeParcel_->RewindWrite(pos);
            return retValue;
        }
    }

    napi_get_boolean(env, result, &retValue);
    return retValue;
}

napi_value NAPI_MessageParcel::JS_writeRemoteObjectArray(napi_env env, napi_callback_info info)
{
    napi_value retValue = nullptr;
    napi_get_boolean(env, false, &retValue);

    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT_BASE(env, argc == 1, "requires 1 parameter", retValue);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", retValue);
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType == napi_null || valueType == napi_undefined) {
        napiParcel->nativeParcel_->WriteInt32(-1);
        return retValue;
    }

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT_BASE(env, isArray == true, "type mismatch for parameter 1", retValue);

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    bool result =  napiParcel->nativeParcel_->WriteInt32(arrayLength);
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        NAPI_ASSERT_BASE(env, hasElement == true, "parameter check error", retValue);
        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        sptr<IRemoteObject> remoteObject = NAPI_ohos_rpc_getNativeRemoteObject(env, element);
        NAPI_ASSERT_BASE(env, remoteObject != nullptr, "parameter check error", retValue);
        result = napiParcel->nativeParcel_->WriteRemoteObject(remoteObject);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            return retValue;
        }
    }
    napi_get_boolean(env, result, &retValue);
    return retValue;
}

napi_value NAPI_MessageParcel::JS_getSize(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetDataSize();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_getCapacity(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetDataCapacity();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_setSize(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t value = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->SetDataSize(static_cast<size_t>(value));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_setCapacity(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t value = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->SetDataCapacity(static_cast<size_t>(value));
    if (result) {
        napiParcel->maxCapacityToWrite_ = value;
    }
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_getWritableBytes(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetWritableBytes();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_getReadableBytes(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetReadableBytes();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_getReadPosition(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetReadPosition();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_rewindRead(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t pos = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &pos);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->RewindRead(static_cast<size_t>(pos));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_getWritePosition(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetWritePosition();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_rewindWrite(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t pos = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &pos);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->RewindWrite(static_cast<size_t>(pos));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeNoException(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    napiParcel->nativeParcel_->WriteInt32(0);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageParcel::JS_create(napi_env env, napi_callback_info info)
{
    // new native parcel object
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "IPCParcelConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get message parcel constructor failed");
    napi_value jsMessageParcel;
    status = napi_new_instance(env, constructor, 0, nullptr, &jsMessageParcel);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js MessageParcel");
    return jsMessageParcel;
}

napi_value NAPI_MessageParcel::JS_reclaim(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_remove_wrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    delete napiParcel;

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageParcel::JS_writeRemoteObject(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    napi_value napiValue = nullptr;
    if (valueType != napi_object) {
        napi_get_boolean(env, false, &napiValue);
        return napiValue;
    }
    sptr<IRemoteObject> remoteObject = NAPI_ohos_rpc_getNativeRemoteObject(env, argv[ARGV_INDEX_0]);
    if (remoteObject == nullptr) {
        napi_get_boolean(env, false, &napiValue);
        return napiValue;
    }
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    bool result = napiParcel->nativeParcel_->WriteRemoteObject(remoteObject);
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeInterfaceToken(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter");

    size_t bufferSize = 0;
    size_t maxSize = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxSize, "string length too large");

    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    std::string parcelString = stringValue;
    bool result = napiParcel->nativeParcel_->WriteInterfaceToken(to_utf16(parcelString));

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_CloseFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    int32_t fd = -1;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    close(fd);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageParcel::JS_DupFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    int32_t fd = -1;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    int32_t dupResult = dup(fd);
    napi_value napiValue;
    napi_create_int32(env, dupResult, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_ContainFileDescriptors(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    bool result = napiParcel->nativeParcel_->ContainFileDescriptors();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_WriteFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameters");
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");
    int32_t fd = -1;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    bool result = napiParcel->nativeParcel_->WriteFileDescriptor(fd);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_WriteAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");
    // check type is Ashmem
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
    napi_unwrap(env, argv[ARGV_INDEX_0], reinterpret_cast<void **>(&napiAshmem));
    NAPI_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    sptr<Ashmem> nativeAshmem = napiAshmem->GetAshmem();
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    bool result = napiParcel->nativeParcel_->WriteAshmem(nativeAshmem);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_WriteRawData(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == ARGV_LENGTH_2, "requires 2 parameter");
    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

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

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");
    int32_t size = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &size);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    bool result = napiParcel->nativeParcel_->WriteRawData(array.data(), size * BYTE_SIZE_32);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_GetRawDataCapacity(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    uint32_t result = napiParcel->nativeParcel_->GetRawDataCapacity();
    napi_value napiValue;
    napi_create_uint32(env, result, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageParcel::Export(napi_env env, napi_value exports)
{
    const std::string className = "MessageParcel";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("create", NAPI_MessageParcel::JS_create),
        DECLARE_NAPI_FUNCTION("reclaim", NAPI_MessageParcel::JS_reclaim),
        DECLARE_NAPI_FUNCTION("writeRemoteObject", NAPI_MessageParcel::JS_writeRemoteObject),
        DECLARE_NAPI_FUNCTION("readRemoteObject", NAPI_MessageParcel::JS_readRemoteObject),
        DECLARE_NAPI_FUNCTION("writeInterfaceToken", NAPI_MessageParcel::JS_writeInterfaceToken),
        DECLARE_NAPI_FUNCTION("readInterfaceToken", NAPI_MessageParcel::JS_readInterfaceToken),
        DECLARE_NAPI_FUNCTION("getSize", NAPI_MessageParcel::JS_getSize),
        DECLARE_NAPI_FUNCTION("getCapacity", NAPI_MessageParcel::JS_getCapacity),
        DECLARE_NAPI_FUNCTION("setSize", NAPI_MessageParcel::JS_setSize),
        DECLARE_NAPI_FUNCTION("setCapacity", NAPI_MessageParcel::JS_setCapacity),
        DECLARE_NAPI_FUNCTION("getWritableBytes", NAPI_MessageParcel::JS_getWritableBytes),
        DECLARE_NAPI_FUNCTION("getReadableBytes", NAPI_MessageParcel::JS_getReadableBytes),
        DECLARE_NAPI_FUNCTION("getReadPosition", NAPI_MessageParcel::JS_getReadPosition),
        DECLARE_NAPI_FUNCTION("getWritePosition", NAPI_MessageParcel::JS_getWritePosition),
        DECLARE_NAPI_FUNCTION("rewindRead", NAPI_MessageParcel::JS_rewindRead),
        DECLARE_NAPI_FUNCTION("rewindWrite", NAPI_MessageParcel::JS_rewindWrite),
        DECLARE_NAPI_FUNCTION("writeNoException", NAPI_MessageParcel::JS_writeNoException),
        DECLARE_NAPI_FUNCTION("readException", NAPI_MessageParcel::JS_readException),
        DECLARE_NAPI_FUNCTION("writeByte", NAPI_MessageParcel::JS_writeByte),
        DECLARE_NAPI_FUNCTION("writeShort", NAPI_MessageParcel::JS_writeShort),
        DECLARE_NAPI_FUNCTION("writeInt", NAPI_MessageParcel::JS_writeInt),
        DECLARE_NAPI_FUNCTION("writeLong", NAPI_MessageParcel::JS_writeLong),
        DECLARE_NAPI_FUNCTION("writeFloat", NAPI_MessageParcel::JS_writeFloat),
        DECLARE_NAPI_FUNCTION("writeDouble", NAPI_MessageParcel::JS_writeDouble),
        DECLARE_NAPI_FUNCTION("writeBoolean", NAPI_MessageParcel::JS_writeBoolean),
        DECLARE_NAPI_FUNCTION("writeChar", NAPI_MessageParcel::JS_writeChar),
        DECLARE_NAPI_FUNCTION("writeString", NAPI_MessageParcel::JS_writeString),
        DECLARE_NAPI_FUNCTION("writeSequenceable", NAPI_MessageParcel::JS_writeSequenceable),
        DECLARE_NAPI_FUNCTION("writeByteArray", NAPI_MessageParcel::JS_writeByteArray),
        DECLARE_NAPI_FUNCTION("writeShortArray", NAPI_MessageParcel::JS_writeShortArray),
        DECLARE_NAPI_FUNCTION("writeIntArray", NAPI_MessageParcel::JS_writeIntArray),
        DECLARE_NAPI_FUNCTION("writeLongArray", NAPI_MessageParcel::JS_writeLongArray),
        DECLARE_NAPI_FUNCTION("writeFloatArray", NAPI_MessageParcel::JS_writeFloatArray),
        DECLARE_NAPI_FUNCTION("writeDoubleArray", NAPI_MessageParcel::JS_writeDoubleArray),
        DECLARE_NAPI_FUNCTION("writeBooleanArray", NAPI_MessageParcel::JS_writeBooleanArray),
        DECLARE_NAPI_FUNCTION("writeCharArray", NAPI_MessageParcel::JS_writeCharArray),
        DECLARE_NAPI_FUNCTION("writeStringArray", NAPI_MessageParcel::JS_writeStringArray),
        DECLARE_NAPI_FUNCTION("writeSequenceableArray", NAPI_MessageParcel::JS_writeSequenceableArray),
        DECLARE_NAPI_FUNCTION("writeRemoteObjectArray", NAPI_MessageParcel::JS_writeRemoteObjectArray),
        DECLARE_NAPI_FUNCTION("readByte", NAPI_MessageParcel::JS_readByte),
        DECLARE_NAPI_FUNCTION("readShort", NAPI_MessageParcel::JS_readShort),
        DECLARE_NAPI_FUNCTION("readInt", NAPI_MessageParcel::JS_readInt),
        DECLARE_NAPI_FUNCTION("readLong", NAPI_MessageParcel::JS_readLong),
        DECLARE_NAPI_FUNCTION("readFloat", NAPI_MessageParcel::JS_readFloat),
        DECLARE_NAPI_FUNCTION("readDouble", NAPI_MessageParcel::JS_readDouble),
        DECLARE_NAPI_FUNCTION("readBoolean", NAPI_MessageParcel::JS_readBoolean),
        DECLARE_NAPI_FUNCTION("readChar", NAPI_MessageParcel::JS_readChar),
        DECLARE_NAPI_FUNCTION("readString", NAPI_MessageParcel::JS_readString),
        DECLARE_NAPI_FUNCTION("readSequenceable", NAPI_MessageParcel::JS_readSequenceable),
        DECLARE_NAPI_FUNCTION("readByteArray", NAPI_MessageParcel::JS_readByteArray),
        DECLARE_NAPI_FUNCTION("readShortArray", NAPI_MessageParcel::JS_readShortArray),
        DECLARE_NAPI_FUNCTION("readIntArray", NAPI_MessageParcel::JS_readIntArray),
        DECLARE_NAPI_FUNCTION("readLongArray", NAPI_MessageParcel::JS_readLongArray),
        DECLARE_NAPI_FUNCTION("readFloatArray", NAPI_MessageParcel::JS_readFloatArray),
        DECLARE_NAPI_FUNCTION("readDoubleArray", NAPI_MessageParcel::JS_readDoubleArray),
        DECLARE_NAPI_FUNCTION("readBooleanArray", NAPI_MessageParcel::JS_readBooleanArray),
        DECLARE_NAPI_FUNCTION("readCharArray", NAPI_MessageParcel::JS_readCharArray),
        DECLARE_NAPI_FUNCTION("readStringArray", NAPI_MessageParcel::JS_readStringArray),
        DECLARE_NAPI_FUNCTION("readSequenceableArray", NAPI_MessageParcel::JS_readSequenceableArray),
        DECLARE_NAPI_FUNCTION("readRemoteObjectArray", NAPI_MessageParcel::JS_readRemoteObjectArray),
        DECLARE_NAPI_STATIC_FUNCTION("closeFileDescriptor", NAPI_MessageParcel::JS_CloseFileDescriptor),
        DECLARE_NAPI_STATIC_FUNCTION("dupFileDescriptor", NAPI_MessageParcel::JS_DupFileDescriptor),
        DECLARE_NAPI_FUNCTION("writeFileDescriptor", NAPI_MessageParcel::JS_WriteFileDescriptor),
        DECLARE_NAPI_FUNCTION("readFileDescriptor", NAPI_MessageParcel::JS_ReadFileDescriptor),
        DECLARE_NAPI_FUNCTION("containFileDescriptors", NAPI_MessageParcel::JS_ContainFileDescriptors),
        DECLARE_NAPI_FUNCTION("writeAshmem", NAPI_MessageParcel::JS_WriteAshmem),
        DECLARE_NAPI_FUNCTION("readAshmem", NAPI_MessageParcel::JS_ReadAshmem),
        DECLARE_NAPI_FUNCTION("getRawDataCapacity", NAPI_MessageParcel::JS_GetRawDataCapacity),
        DECLARE_NAPI_FUNCTION("writeRawData", NAPI_MessageParcel::JS_WriteRawData),
        DECLARE_NAPI_FUNCTION("readRawData", NAPI_MessageParcel::JS_ReadRawData),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), JS_constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class MessageParcel failed");
    napi_status status = napi_set_named_property(env, exports, "MessageParcel", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property MessageParcel failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "IPCParcelConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set message parcel constructor failed");
    return exports;
}

napi_value NAPI_MessageParcel::JS_constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { 0 };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi get callback info failed");
    MessageParcel *parcel = nullptr;
    if (argc > 0) {
        napi_unwrap(env, argv[ARGV_INDEX_0], reinterpret_cast<void **>(&parcel));
        NAPI_ASSERT(env, parcel != nullptr, "parcel is null");
    }
    // new native parcel object
    auto messageParcel = new NAPI_MessageParcel(env, thisVar, parcel);
    // connect native object to js thisVar
    status = napi_wrap(
        env, thisVar, messageParcel,
        [](napi_env env, void *data, void *hint) {
            NAPI_MessageParcel *messageParcel = reinterpret_cast<NAPI_MessageParcel *>(data);
            if (!messageParcel->owner) {
                delete messageParcel;
            }
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi wrap message parcel failed");
    return thisVar;
}
} // namespace OHOS

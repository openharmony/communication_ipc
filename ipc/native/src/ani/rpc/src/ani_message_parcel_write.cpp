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
using namespace OHOS::HiviewDFX;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "ani_MessageParcelWrite" };

ani_MessageParcel::ani_MessageParcel(ani_env env, ani_value thisVar, MessageParcel *parcel)
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

ani_MessageParcel::~ani_MessageParcel()
{
    ZLOGD(LOG_LABEL, "ani_MessageParcel::Destructor");
    nativeParcel_ = nullptr;
    env_ = nullptr;
}

void ani_MessageParcel::release(MessageParcel *parcel)
{
    ZLOGD(LOG_LABEL, "message parcel is created by others, do nothing");
}

std::shared_ptr<MessageParcel> ani_MessageParcel::GetMessageParcel()
{
    return nativeParcel_;
}

ani_value ani_MessageParcel::JS_writeByte(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    int32_t value = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeShort(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    int32_t value = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt16(static_cast<int16_t>(value));
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeInt(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    int32_t value = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt32(value);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeLong(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    int64_t value = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_64, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt64(value);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeFloat(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    double value = 0;
    ani_get_value_double(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, sizeof(double), napiParcel);
    bool result = napiParcel->nativeParcel_->WriteDouble(value);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeDouble(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    double value = 0;
    ani_get_value_double(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, sizeof(double), napiParcel);
    bool result = napiParcel->nativeParcel_->WriteDouble(value);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeBoolean(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_boolean, "type mismatch for parameter 1");

    bool value = 0;
    ani_get_value_bool(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeChar(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    uint32_t value = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    bool result = napiParcel->nativeParcel_->WriteUint8(static_cast<uint8_t>(value));
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeByteArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    uint32_t maxBytesLen = 40960;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);
    ani_ASSERT(env, arrayLength < maxBytesLen, "write byte array length too large");

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_8 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        result = napiParcel->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeShortArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        result = napiParcel->nativeParcel_->WriteInt16(static_cast<int16_t>(value));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeIntArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        ani_valuetype valueType;
        ani_typeof(env, element, &valueType);
        ani_ASSERT(env, valueType == ani_number, "type mismatch element");

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        result = napiParcel->nativeParcel_->WriteInt32(value);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeLongArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);
    ZLOGI(LOG_LABEL, "messageparcel WriteBuffer typedarrayLength:%{public}d", (int)(arrayLength));

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + BYTE_SIZE_64 * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int64_t value = 0;
        ani_get_value_int64(env, element, &value);

        result = napiParcel->nativeParcel_->WriteInt64(value);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeFloatArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + sizeof(double) * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        double value = 0;
        ani_get_value_double(env, element, &value);

        result = napiParcel->nativeParcel_->WriteDouble(value);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeDoubleArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + sizeof(double) * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        double value = 0;
        ani_get_value_double(env, element, &value);

        result = napiParcel->nativeParcel_->WriteDouble(value);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeBooleanArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        bool value = 0;
        ani_get_value_bool(env, element, &value);

        result = napiParcel->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeCharArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        uint32_t value = 0;
        ani_get_value_uint32(env, element, &value);

        result = napiParcel->nativeParcel_->WriteUint8(static_cast<uint8_t>(value));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeString(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_string, "type mismatch for parameter 1");

    size_t bufferSize = 0;
    size_t maxLen = 40960;
    ani_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    ani_ASSERT(env, bufferSize < maxLen, "string length too large");

    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    ani_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    ani_ASSERT(env, jsStringLength == bufferSize, "string length wrong");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * bufferSize, napiParcel);
    std::string parcelString = stringValue;
    bool result = napiParcel->nativeParcel_->WriteString16(to_utf16(parcelString));

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeStringArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        size_t maxSize = 40960;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT(env, hasElement == true, "parameter check error");

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valuetype;
        ani_typeof(env, element, &valuetype);
        ani_ASSERT(env, valuetype == ani_string, "Parameter type error");

        size_t bufferSize = 0;
        ani_get_value_string_utf8(env, element, nullptr, 0, &bufferSize);
        ani_ASSERT(env, bufferSize < maxSize, "string length too large");

        char stringValue[bufferSize + 1];
        size_t jsStringLength = 0;
        ani_get_value_string_utf8(env, element, stringValue, bufferSize + 1, &jsStringLength);
        ani_ASSERT(env, jsStringLength == bufferSize, "string length wrong");

        REWIND_IF_WRITE_CHECK_FAIL(env, BYTE_SIZE_32 * bufferSize, pos, napiParcel);
        std::string parcelString = stringValue;
        result = napiParcel->nativeParcel_->WriteString16(to_utf16(parcelString));
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeSequenceable(ani_env env, ani_callback_info info)
{
    ani_value result = nullptr;
    ani_get_boolean(env, false, &result);

    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType == ani_null || valueType == ani_undefined) {
        napiParcel->nativeParcel_->WriteInt32(0);
        return result;
    }
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteInt32(1);
    ani_value propKey = nullptr;
    const char *propKeyStr = "marshalling";
    ani_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
    ani_value prop = nullptr;
    ani_get_property(env, argv[ARGV_INDEX_0], propKey, &prop);

    ani_value funcArg[1] = { thisVar };
    ani_value callResult = nullptr;
    ani_call_function(env, argv[ARGV_INDEX_0], prop, 1, funcArg, &callResult);
    ani_typeof(env, callResult, &valueType);
    if (callResult != nullptr && valueType != ani_undefined) {
        return callResult;
    }
    ZLOGE(LOG_LABEL, "call marshalling failed");
    napiParcel->nativeParcel_->RewindWrite(pos);
    return result;
}

ani_value ani_MessageParcel::JS_writeSequenceableArray(ani_env env, ani_callback_info info)
{
    ani_value retValue = nullptr;
    ani_get_boolean(env, false, &retValue);

    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT_BASE(env, argc == 1, "requires 1 parameter", retValue);

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT_BASE(env, isArray == true, "type mismatch for parameter 1", retValue);
    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", retValue);

    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    bool result = napiParcel->nativeParcel_->WriteUint32(arrayLength);
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT_BASE(env, hasElement == true, "parameter check error", retValue);

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valueType = ani_null;
        ani_typeof(env, element, &valueType);
        if (valueType == ani_null || valueType == ani_undefined) {
            napiParcel->nativeParcel_->WriteInt32(0);
            continue;
        } else {
            napiParcel->nativeParcel_->WriteInt32(1);
        }
        ani_value propKey = nullptr;
        const char *propKeyStr = "marshalling";
        ani_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
        ani_value prop = nullptr;
        ani_get_property(env, element, propKey, &prop);

        ani_value funcArg[1] = { thisVar };
        ani_value callResult = nullptr;
        ani_call_function(env, element, prop, 1, funcArg, &callResult);
        ani_typeof(env, callResult, &valueType);
        if (callResult == nullptr || valueType == ani_undefined) {
            ZLOGE(LOG_LABEL, "call marshalling failed, element index:%{public}zu", i);
            napiParcel->nativeParcel_->RewindWrite(pos);
            return retValue;
        }
    }

    ani_get_boolean(env, result, &retValue);
    return retValue;
}

ani_value ani_MessageParcel::JS_writeRemoteObjectArray(ani_env env, ani_callback_info info)
{
    ani_value retValue = nullptr;
    ani_get_boolean(env, false, &retValue);

    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT_BASE(env, argc == 1, "requires 1 parameter", retValue);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", retValue);
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType == ani_null || valueType == ani_undefined) {
        napiParcel->nativeParcel_->WriteInt32(-1);
        return retValue;
    }

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT_BASE(env, isArray == true, "type mismatch for parameter 1", retValue);

    uint32_t arrayLength = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    bool result =  napiParcel->nativeParcel_->WriteInt32(arrayLength);
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        ani_ASSERT_BASE(env, hasElement == true, "parameter check error", retValue);
        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        sptr<IRemoteObject> remoteObject = ani_ohos_rpc_getNativeRemoteObject(env, element);
        ani_ASSERT_BASE(env, remoteObject != nullptr, "parameter check error", retValue);
        result = napiParcel->nativeParcel_->WriteRemoteObject(remoteObject);
        if (!result) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            return retValue;
        }
    }
    ani_get_boolean(env, result, &retValue);
    return retValue;
}

ani_value ani_MessageParcel::JS_getSize(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetDataSize();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_getCapacity(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetDataCapacity();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_setSize(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    uint32_t value = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->SetDataSize(static_cast<size_t>(value));
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_setCapacity(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    uint32_t value = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->SetDataCapacity(static_cast<size_t>(value));
    if (result) {
        napiParcel->maxCapacityToWrite_ = value;
    }
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_getWritableBytes(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetWritableBytes();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_getReadableBytes(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetReadableBytes();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_getReadPosition(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetReadPosition();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_rewindRead(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    uint32_t pos = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &pos);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->RewindRead(static_cast<size_t>(pos));
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_getWritePosition(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);

    size_t value = napiParcel->nativeParcel_->GetWritePosition();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_rewindWrite(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");

    uint32_t pos = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &pos);

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->RewindWrite(static_cast<size_t>(pos));
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeNoException(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    napiParcel->nativeParcel_->WriteInt32(0);
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageParcel::JS_create(ani_env env, ani_callback_info info)
{
    // new native parcel object
    ani_value global = nullptr;
    ani_status status = ani_get_global(env, &global);
    ani_ASSERT(env, status == ani_ok, "get napi global failed");
    ani_value constructor = nullptr;
    status = ani_get_named_property(env, global, "IPCParcelConstructor_", &constructor);
    ani_ASSERT(env, status == ani_ok, "get message parcel constructor failed");
    ani_value jsMessageParcel;
    status = ani_new_instance(env, constructor, 0, nullptr, &jsMessageParcel);
    ani_ASSERT(env, status == ani_ok, "failed to  construct js MessageParcel");
    return jsMessageParcel;
}

ani_value ani_MessageParcel::JS_reclaim(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageParcel *napiParcel = nullptr;
    ani_remove_wrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    delete napiParcel;

    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageParcel::JS_writeRemoteObject(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_value napiValue = nullptr;
    if (valueType != ani_object) {
        ani_get_boolean(env, false, &napiValue);
        return napiValue;
    }
    sptr<IRemoteObject> remoteObject = ani_ohos_rpc_getNativeRemoteObject(env, argv[ARGV_INDEX_0]);
    if (remoteObject == nullptr) {
        ani_get_boolean(env, false, &napiValue);
        return napiValue;
    }
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    bool result = napiParcel->nativeParcel_->WriteRemoteObject(remoteObject);
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_writeInterfaceToken(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_string, "type mismatch for parameter");

    size_t bufferSize = 0;
    size_t maxSize = 40960;
    ani_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    ani_ASSERT(env, bufferSize < maxSize, "string length too large");

    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    ani_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    ani_ASSERT(env, jsStringLength == bufferSize, "string length wrong");

    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    std::string parcelString = stringValue;
    bool result = napiParcel->nativeParcel_->WriteInterfaceToken(to_utf16(parcelString));

    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_CloseFileDescriptor(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameters");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");
    int32_t fd = -1;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    close(fd);
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageParcel::JS_DupFileDescriptor(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameters");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");
    int32_t fd = -1;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    int32_t dupResult = dup(fd);
    ani_ASSERT(env, dupResult >= 0, "invalid fd");
    ani_value napiValue;
    ani_create_int32(env, dupResult, &napiValue);
    return napiValue;
}

ani_value ani_MessageParcel::JS_ContainFileDescriptors(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    bool result = napiParcel->nativeParcel_->ContainFileDescriptors();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_WriteFileDescriptor(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == 1, "requires 1 parameters");
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 1");
    int32_t fd = -1;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    bool result = napiParcel->nativeParcel_->WriteFileDescriptor(fd);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_WriteAshmem(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    ani_ASSERT(env, argc == 1, "requires 1 parameter");
    // check type is Ashmem
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
    ani_unwrap(env, argv[ARGV_INDEX_0], reinterpret_cast<void **>(&napiAshmem));
    ani_ASSERT(env, napiAshmem != nullptr, "napiAshmem is null");
    sptr<Ashmem> nativeAshmem = napiAshmem->GetAshmem();
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    bool result = napiParcel->nativeParcel_->WriteAshmem(nativeAshmem);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_WriteRawData(ani_env env, ani_callback_info info)
{
    size_t argc = 2;
    ani_value argv[ARGV_LENGTH_2] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, argc == ARGV_LENGTH_2, "requires 2 parameter");
    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    ani_ASSERT(env, isArray == true, "type mismatch for parameter 1");

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

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    ani_ASSERT(env, valueType == ani_number, "type mismatch for parameter 2");
    int32_t size = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_1], &size);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    bool result = napiParcel->nativeParcel_->WriteRawData(array.data(), size * BYTE_SIZE_32);
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageParcel::JS_GetRawDataCapacity(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageParcel *napiParcel = nullptr;
    ani_unwrap(env, thisVar, reinterpret_cast<void **>(&napiParcel));
    ani_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", nullptr);
    uint32_t result = napiParcel->nativeParcel_->GetRawDataCapacity();
    ani_value napiValue;
    ani_create_uint32(env, result, &napiValue);
    return napiValue;
}

ani_value ani_MessageParcel::Export(ani_env env, ani_value exports)
{
    const std::string className = "MessageParcel";
    ani_property_descriptor properties[] = {
        DECLARE_ani_STATIC_FUNCTION("create", ani_MessageParcel::JS_create),
        DECLARE_ani_FUNCTION("reclaim", ani_MessageParcel::JS_reclaim),
        DECLARE_ani_FUNCTION("writeRemoteObject", ani_MessageParcel::JS_writeRemoteObject),
        DECLARE_ani_FUNCTION("readRemoteObject", ani_MessageParcel::JS_readRemoteObject),
        DECLARE_ani_FUNCTION("writeInterfaceToken", ani_MessageParcel::JS_writeInterfaceToken),
        DECLARE_ani_FUNCTION("readInterfaceToken", ani_MessageParcel::JS_readInterfaceToken),
        DECLARE_ani_FUNCTION("getSize", ani_MessageParcel::JS_getSize),
        DECLARE_ani_FUNCTION("getCapacity", ani_MessageParcel::JS_getCapacity),
        DECLARE_ani_FUNCTION("setSize", ani_MessageParcel::JS_setSize),
        DECLARE_ani_FUNCTION("setCapacity", ani_MessageParcel::JS_setCapacity),
        DECLARE_ani_FUNCTION("getWritableBytes", ani_MessageParcel::JS_getWritableBytes),
        DECLARE_ani_FUNCTION("getReadableBytes", ani_MessageParcel::JS_getReadableBytes),
        DECLARE_ani_FUNCTION("getReadPosition", ani_MessageParcel::JS_getReadPosition),
        DECLARE_ani_FUNCTION("getWritePosition", ani_MessageParcel::JS_getWritePosition),
        DECLARE_ani_FUNCTION("rewindRead", ani_MessageParcel::JS_rewindRead),
        DECLARE_ani_FUNCTION("rewindWrite", ani_MessageParcel::JS_rewindWrite),
        DECLARE_ani_FUNCTION("writeNoException", ani_MessageParcel::JS_writeNoException),
        DECLARE_ani_FUNCTION("readException", ani_MessageParcel::JS_readException),
        DECLARE_ani_FUNCTION("writeByte", ani_MessageParcel::JS_writeByte),
        DECLARE_ani_FUNCTION("writeShort", ani_MessageParcel::JS_writeShort),
        DECLARE_ani_FUNCTION("writeInt", ani_MessageParcel::JS_writeInt),
        DECLARE_ani_FUNCTION("writeLong", ani_MessageParcel::JS_writeLong),
        DECLARE_ani_FUNCTION("writeFloat", ani_MessageParcel::JS_writeFloat),
        DECLARE_ani_FUNCTION("writeDouble", ani_MessageParcel::JS_writeDouble),
        DECLARE_ani_FUNCTION("writeBoolean", ani_MessageParcel::JS_writeBoolean),
        DECLARE_ani_FUNCTION("writeChar", ani_MessageParcel::JS_writeChar),
        DECLARE_ani_FUNCTION("writeString", ani_MessageParcel::JS_writeString),
        DECLARE_ani_FUNCTION("writeSequenceable", ani_MessageParcel::JS_writeSequenceable),
        DECLARE_ani_FUNCTION("writeByteArray", ani_MessageParcel::JS_writeByteArray),
        DECLARE_ani_FUNCTION("writeShortArray", ani_MessageParcel::JS_writeShortArray),
        DECLARE_ani_FUNCTION("writeIntArray", ani_MessageParcel::JS_writeIntArray),
        DECLARE_ani_FUNCTION("writeLongArray", ani_MessageParcel::JS_writeLongArray),
        DECLARE_ani_FUNCTION("writeFloatArray", ani_MessageParcel::JS_writeFloatArray),
        DECLARE_ani_FUNCTION("writeDoubleArray", ani_MessageParcel::JS_writeDoubleArray),
        DECLARE_ani_FUNCTION("writeBooleanArray", ani_MessageParcel::JS_writeBooleanArray),
        DECLARE_ani_FUNCTION("writeCharArray", ani_MessageParcel::JS_writeCharArray),
        DECLARE_ani_FUNCTION("writeStringArray", ani_MessageParcel::JS_writeStringArray),
        DECLARE_ani_FUNCTION("writeSequenceableArray", ani_MessageParcel::JS_writeSequenceableArray),
        DECLARE_ani_FUNCTION("writeRemoteObjectArray", ani_MessageParcel::JS_writeRemoteObjectArray),
        DECLARE_ani_FUNCTION("readByte", ani_MessageParcel::JS_readByte),
        DECLARE_ani_FUNCTION("readShort", ani_MessageParcel::JS_readShort),
        DECLARE_ani_FUNCTION("readInt", ani_MessageParcel::JS_readInt),
        DECLARE_ani_FUNCTION("readLong", ani_MessageParcel::JS_readLong),
        DECLARE_ani_FUNCTION("readFloat", ani_MessageParcel::JS_readFloat),
        DECLARE_ani_FUNCTION("readDouble", ani_MessageParcel::JS_readDouble),
        DECLARE_ani_FUNCTION("readBoolean", ani_MessageParcel::JS_readBoolean),
        DECLARE_ani_FUNCTION("readChar", ani_MessageParcel::JS_readChar),
        DECLARE_ani_FUNCTION("readString", ani_MessageParcel::JS_readString),
        DECLARE_ani_FUNCTION("readSequenceable", ani_MessageParcel::JS_readSequenceable),
        DECLARE_ani_FUNCTION("readByteArray", ani_MessageParcel::JS_readByteArray),
        DECLARE_ani_FUNCTION("readShortArray", ani_MessageParcel::JS_readShortArray),
        DECLARE_ani_FUNCTION("readIntArray", ani_MessageParcel::JS_readIntArray),
        DECLARE_ani_FUNCTION("readLongArray", ani_MessageParcel::JS_readLongArray),
        DECLARE_ani_FUNCTION("readFloatArray", ani_MessageParcel::JS_readFloatArray),
        DECLARE_ani_FUNCTION("readDoubleArray", ani_MessageParcel::JS_readDoubleArray),
        DECLARE_ani_FUNCTION("readBooleanArray", ani_MessageParcel::JS_readBooleanArray),
        DECLARE_ani_FUNCTION("readCharArray", ani_MessageParcel::JS_readCharArray),
        DECLARE_ani_FUNCTION("readStringArray", ani_MessageParcel::JS_readStringArray),
        DECLARE_ani_FUNCTION("readSequenceableArray", ani_MessageParcel::JS_readSequenceableArray),
        DECLARE_ani_FUNCTION("readRemoteObjectArray", ani_MessageParcel::JS_readRemoteObjectArray),
        DECLARE_ani_STATIC_FUNCTION("closeFileDescriptor", ani_MessageParcel::JS_CloseFileDescriptor),
        DECLARE_ani_STATIC_FUNCTION("dupFileDescriptor", ani_MessageParcel::JS_DupFileDescriptor),
        DECLARE_ani_FUNCTION("writeFileDescriptor", ani_MessageParcel::JS_WriteFileDescriptor),
        DECLARE_ani_FUNCTION("readFileDescriptor", ani_MessageParcel::JS_ReadFileDescriptor),
        DECLARE_ani_FUNCTION("containFileDescriptors", ani_MessageParcel::JS_ContainFileDescriptors),
        DECLARE_ani_FUNCTION("writeAshmem", ani_MessageParcel::JS_WriteAshmem),
        DECLARE_ani_FUNCTION("readAshmem", ani_MessageParcel::JS_ReadAshmem),
        DECLARE_ani_FUNCTION("getRawDataCapacity", ani_MessageParcel::JS_GetRawDataCapacity),
        DECLARE_ani_FUNCTION("writeRawData", ani_MessageParcel::JS_WriteRawData),
        DECLARE_ani_FUNCTION("readRawData", ani_MessageParcel::JS_ReadRawData),
    };
    ani_value constructor = nullptr;
    ani_define_class(env, className.c_str(), className.length(), JS_constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    ani_ASSERT(env, constructor != nullptr, "define js class MessageParcel failed");
    ani_status status = ani_set_named_property(env, exports, "MessageParcel", constructor);
    ani_ASSERT(env, status == ani_ok, "set property MessageParcel failed");
    ani_value global = nullptr;
    status = ani_get_global(env, &global);
    ani_ASSERT(env, status == ani_ok, "get napi global failed");
    status = ani_set_named_property(env, global, "IPCParcelConstructor_", constructor);
    ani_ASSERT(env, status == ani_ok, "set message parcel constructor failed");
    return exports;
}

ani_value ani_MessageParcel::JS_constructor(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = { 0 };
    ani_status status = ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, status == ani_ok, "napi get callback info failed");
    MessageParcel *parcel = nullptr;
    if (argc > 0) {
        ani_unwrap(env, argv[ARGV_INDEX_0], reinterpret_cast<void **>(&parcel));
        ani_ASSERT(env, parcel != nullptr, "parcel is null");
    }
    // new native parcel object
    auto messageParcel = new (std::nothrow) ani_MessageParcel(env, thisVar, parcel);
    ani_ASSERT(env, messageParcel != nullptr, "new messageParcel failed");
    // connect native object to js thisVar
    status = ani_wrap(
        env, thisVar, messageParcel,
        [](ani_env env, void *data, void *hint) {
            ani_MessageParcel *messageParcel = reinterpret_cast<ani_MessageParcel *>(data);
            if (!messageParcel->owner) {
                delete messageParcel;
            }
        },
        nullptr, nullptr);
    if (status != ani_ok) {
        delete messageParcel;
        ani_ASSERT(env, false, "napi wrap message parcel failed");
    }
    return thisVar;
}
} // namespace OHOS

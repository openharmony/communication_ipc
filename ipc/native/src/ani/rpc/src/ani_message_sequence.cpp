/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ani_message_sequence.h"

#include <cinttypes>
#include <cstring>
#include <unistd.h>

#include "hilog/log.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "ani_ashmem.h"
#include "ani_remote_object.h"
#include "ani_rpc_common.h"
#include "string_ex.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;
NapiError ani_MessageSequence::napiErr;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "ani_MessageSequenceWrite" };

ani_MessageSequence::ani_MessageSequence(ani_env env, ani_value thisVar, MessageParcel *parcel)
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

ani_MessageSequence::~ani_MessageSequence()
{
    ZLOGD(LOG_LABEL, "ani_MessageSequence::Destructor");
    nativeParcel_ = nullptr;
    env_ = nullptr;
}

void ani_MessageSequence::release(MessageParcel *parcel)
{
    ZLOGD(LOG_LABEL, "message parcel is created by others, do nothing");
}

std::shared_ptr<MessageParcel> ani_MessageSequence::GetMessageParcel()
{
    return nativeParcel_;
}

ani_value CreateTypeCodeEnum(ani_env env)
{
    ani_value enumValues[ENUM_TYPECODE_COUNT] = {nullptr};
    ani_value enumObject = nullptr;
    ani_create_object(env, &enumObject);
    for (size_t i = 0; i < ENUM_TYPECODE_COUNT; i++) {
        ani_create_int32(env, i, &enumValues[i]);
    }

    ani_property_descriptor enumDesc[] = {
        DECLARE_ani_PROPERTY("INT8_ARRAY", enumValues[INT8_ARRAY]),
        DECLARE_ani_PROPERTY("UINT8_ARRAY", enumValues[UINT8_ARRAY]),
        DECLARE_ani_PROPERTY("INT16_ARRAY", enumValues[INT16_ARRAY]),
        DECLARE_ani_PROPERTY("UINT16_ARRAY", enumValues[UINT16_ARRAY]),
        DECLARE_ani_PROPERTY("INT32_ARRAY", enumValues[INT32_ARRAY]),
        DECLARE_ani_PROPERTY("UINT32_ARRAY", enumValues[UINT32_ARRAY]),
        DECLARE_ani_PROPERTY("FLOAT32_ARRAY", enumValues[FLOAT32_ARRAY]),
        DECLARE_ani_PROPERTY("FLOAT64_ARRAY", enumValues[FLOAT64_ARRAY]),
        DECLARE_ani_PROPERTY("BIGINT64_ARRAY", enumValues[BIGINT64_ARRAY]),
        DECLARE_ani_PROPERTY("BIGUINT64_ARRAY", enumValues[BIGUINT64_ARRAY]),
    };
    ani_define_properties(env, enumObject, sizeof(enumDesc) / sizeof(enumDesc[0]), enumDesc);
    return enumObject;
}

ani_value ani_MessageSequence::JS_writeByte(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t value = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiSequence);
    bool result = napiSequence->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
    if (!result) {
        ZLOGE(LOG_LABEL, "write int8 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeShort(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t value = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiSequence);
    bool result = napiSequence->nativeParcel_->WriteInt16(static_cast<int16_t>(value));
    if (!result) {
        ZLOGE(LOG_LABEL, "write int16 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeInt(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t value = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiSequence);
    bool result = napiSequence->nativeParcel_->WriteInt32(value);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeLong(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int64_t value = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_64, napiSequence);
    bool result = napiSequence->nativeParcel_->WriteInt64(value);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int64 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeFloat(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    double value = 0;
    ani_get_value_double(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    CHECK_WRITE_CAPACITY(env, sizeof(double), napiSequence);
    bool result = napiSequence->nativeParcel_->WriteDouble(value);
    if (!result) {
        ZLOGE(LOG_LABEL, "write double failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeDouble(ani_env env, ani_callback_info info)
{
    // This function implementation is the same as JS_writeFloat
    return ani_MessageSequence::JS_writeFloat(env, info);
}

ani_value ani_MessageSequence::JS_writeBoolean(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_boolean) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    bool value = false;
    ani_get_value_bool(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiSequence);
    bool result = napiSequence->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
    if (!result) {
        ZLOGE(LOG_LABEL, "write int8 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeChar(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    uint32_t value = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiSequence);
    bool result = napiSequence->nativeParcel_->WriteUint8(static_cast<uint8_t>(value));
    if (!result) {
        ZLOGE(LOG_LABEL, "write uint8 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeByteArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_8 * (arrayLength + 1), napiSequence);
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valueType;
        ani_typeof(env, element, &valueType);
        if (valueType != ani_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, ani_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int8 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_checkWriteArrayArgs(ani_env env,
                                                        size_t argc,
                                                        ani_value* argv,
                                                        uint32_t &arrayLength)
{
    if (argv == nullptr) {
        ZLOGE(LOG_LABEL, "argv is nullptr");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    ani_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeShortArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiSequence);
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valueType;
        ani_typeof(env, element, &valueType);
        if (valueType != ani_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, ani_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt16(static_cast<int16_t>(value));
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int16 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeIntArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiSequence);
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valueType;
        ani_typeof(env, element, &valueType);
        if (valueType != ani_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, ani_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt32(value);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int32 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeLongArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + BYTE_SIZE_64 * arrayLength, napiSequence);
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valueType;
        ani_typeof(env, element, &valueType);
        if (valueType != ani_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, ani_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        int64_t value = 0;
        ani_get_value_int64(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt64(value);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int64 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeFloatArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + sizeof(double) * arrayLength, napiSequence);
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valueType;
        ani_typeof(env, element, &valueType);
        if (valueType != ani_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, ani_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        double value = 0;
        ani_get_value_double(env, element, &value);
        result = napiSequence->nativeParcel_->WriteDouble(value);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write double failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeDoubleArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + sizeof(double) * arrayLength, napiSequence);
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valueType;
        ani_typeof(env, element, &valueType);
        if (valueType != ani_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, ani_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        double value = 0;
        ani_get_value_double(env, element, &value);
        result = napiSequence->nativeParcel_->WriteDouble(value);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write double failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeBooleanArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiSequence);
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        bool value = false;
        ani_get_value_bool(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int8 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeCharArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiSequence);
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);

        uint32_t value = 0;
        ani_get_value_uint32(env, element, &value);
        result = napiSequence->nativeParcel_->WriteUint8(static_cast<uint8_t>(value));
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write uint8 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeString(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t bufferSize = 0;
    size_t maxLen = MAX_BYTES_LENGTH;
    ani_get_value_string_utf16(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char16_t stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    ani_get_value_string_utf16(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    if (jsStringLength != bufferSize) {
        ZLOGE(LOG_LABEL, "string length wrong");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * bufferSize, napiSequence);
    bool result = napiSequence->nativeParcel_->WriteString16(stringValue);
    if (!result) {
        ZLOGE(LOG_LABEL, "write string16 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_checkWriteStringArrayElement(ani_env env,
                                                                 ani_value* argv,
                                                                 size_t &index,
                                                                 size_t &bufferSize,
                                                                 ani_value &element)
{
    if (argv == nullptr) {
        ZLOGE(LOG_LABEL, "argv is nullptr");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    bool hasElement = false;
    size_t maxSize = MAX_BYTES_LENGTH;
    ani_has_element(env, argv[ARGV_INDEX_0], index, &hasElement);
    if (!hasElement) {
        ZLOGE(LOG_LABEL, "parameter check error");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_get_element(env, argv[ARGV_INDEX_0], index, &element);
    ani_valuetype valuetype;
    ani_typeof(env, element, &valuetype);
    if (valuetype != ani_string) {
        ZLOGD(LOG_LABEL, "Parameter type error");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_get_value_string_utf16(env, element, nullptr, 0, &bufferSize);
    if (bufferSize >= maxSize) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeParcelableArrayCallJsFunc(ani_env env,
    ani_value &element, ani_value &thisVar)
{
    ani_value propKey = nullptr;
    const char *propKeyStr = "marshalling";
    ani_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
    ani_value prop = nullptr;
    ani_get_property(env, element, propKey, &prop);

    ani_value funcArg[1] = { thisVar };
    ani_value callResult = nullptr;
    ani_call_function(env, element, prop, 1, funcArg, &callResult);
    ani_valuetype valueType = ani_null;
    ani_typeof(env, callResult, &valueType);
    if (callResult == nullptr || valueType == ani_undefined) {
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    ani_value retValue = nullptr;
    ani_get_undefined(env, &retValue);
    return retValue;
}

ani_value ani_MessageSequence::JS_writeParcelableArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    if (!(napiSequence->nativeParcel_->WriteUint32(arrayLength))) {
        ZLOGE(LOG_LABEL, "write uint32 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        ani_valuetype valueType = ani_null;
        ani_typeof(env, element, &valueType);
        if (valueType == ani_null || valueType == ani_undefined) {
            napiSequence->nativeParcel_->WriteInt32(0);
            continue;
        } else {
            napiSequence->nativeParcel_->WriteInt32(1);
        }
        ani_value callResult = JS_writeParcelableArrayCallJsFunc(env, element, thisVar);
        if (callResult == nullptr) {
            ZLOGE(LOG_LABEL, "call marshalling failed, element index:%{public}zu", i);
            napiSequence->nativeParcel_->RewindWrite(pos);
            return callResult;
        }
    }
    ani_value retValue = nullptr;
    ani_get_undefined(env, &retValue);
    return retValue;
}

ani_value ani_MessageSequence::JS_writeRemoteObjectArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    ani_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType == ani_null || valueType == ani_undefined) {
        napiSequence->nativeParcel_->WriteInt32(-1);
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    bool result =  napiSequence->nativeParcel_->WriteInt32(arrayLength);
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }
        ani_value element = nullptr;
        ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
        sptr<IRemoteObject> remoteObject = ani_ohos_rpc_getNativeRemoteObject(env, element);
        if (remoteObject == nullptr) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }
        result = napiSequence->nativeParcel_->WriteRemoteObject(remoteObject);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write string16 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
    ani_value retValue = nullptr;
    ani_get_undefined(env, &retValue);
    return retValue;
}

ani_value ani_MessageSequence::JS_setSize(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    uint32_t value = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    bool result = napiSequence->nativeParcel_->SetDataSize(static_cast<size_t>(value));
    if (!result) {
        ZLOGE(LOG_LABEL, "set data size failed");
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_setCapacity(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    uint32_t value = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    bool result = napiSequence->nativeParcel_->SetDataCapacity(static_cast<size_t>(value));
    if (result) {
        napiSequence->maxCapacityToWrite_ = value;
    } else {
        ZLOGE(LOG_LABEL, "set data capacity failed");
        return napiErr.ThrowError(env, errorDesc::PARCEL_MEMORY_ALLOC_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_getWritableBytes(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    ani_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetWritableBytes();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_getWritePosition(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    ani_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetWritePosition();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_rewindWrite(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    uint32_t pos = 0;
    ani_get_value_uint32(env, argv[ARGV_INDEX_0], &pos);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    bool result = napiSequence->nativeParcel_->RewindWrite(static_cast<size_t>(pos));
    ani_ASSERT(env, result == true, "rewind write failed");
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_writeNoException(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    bool writeResult = napiSequence->nativeParcel_->WriteInt32(0);
    if (writeResult == false) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageSequence::JS_writeRemoteObject(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    sptr<IRemoteObject> remoteObject = ani_ohos_rpc_getNativeRemoteObject(env, argv[ARGV_INDEX_0]);
    if (remoteObject == nullptr) {
        ZLOGE(LOG_LABEL, "remote object is nullptr");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    bool writeResult = napiSequence->nativeParcel_->WriteRemoteObject(remoteObject);
    if (writeResult == false) {
        ZLOGE(LOG_LABEL, "write remote object failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageSequence::JS_writeInterfaceToken(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t bufferSize = 0;
    size_t maxSize = MAX_BYTES_LENGTH;
    ani_get_value_string_utf16(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize >= maxSize) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char16_t stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    ani_get_value_string_utf16(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    if (jsStringLength != bufferSize) {
        ZLOGE(LOG_LABEL, "string length wrong");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    bool writeResult = napiSequence->nativeParcel_->WriteInterfaceToken(stringValue);
    if (writeResult == false) {
        ZLOGE(LOG_LABEL, "write interface token failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageSequence::JS_CloseFileDescriptor(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t fd = -1;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    close(fd);
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageSequence::JS_DupFileDescriptor(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t fd = -1;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    int32_t dupResult = dup(fd);
    if (dupResult < 0) {
        ZLOGE(LOG_LABEL, "os dup function failed");
        return napiErr.ThrowError(env, errorDesc::OS_DUP_ERROR);
    }
    ani_value napiValue;
    if (ani_ok != ani_create_int32(env, dupResult, &napiValue)) {
        close(dupResult);
        ZLOGE(LOG_LABEL, "ani_create_int32 failed");
        return napiErr.ThrowError(env, errorDesc::CALL_JS_METHOD_ERROR);
    }
    return napiValue;
}

ani_value ani_MessageSequence::JS_ContainFileDescriptors(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    ani_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);
    bool result = napiSequence->nativeParcel_->ContainFileDescriptors();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, result, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_WriteFileDescriptor(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t fd = -1;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    bool result = napiSequence->nativeParcel_->WriteFileDescriptor(fd);
    if (!result) {
        ZLOGE(LOG_LABEL, "write file descriptor failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_WriteAshmem(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    void *data = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    // check type is Ashmem
    ani_value global = nullptr;
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    ani_status status = ani_get_global(env, &global);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "get napi global failed");
        return napiValue;
    }
    ani_value constructor = nullptr;
    status = ani_get_named_property(env, global, "AshmemConstructor_", &constructor);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "get Ashmem constructor failed");
        return napiValue;
    }
    bool isAshmem = false;
    ani_instanceof(env, argv[ARGV_INDEX_0], constructor, &isAshmem);
    if (!isAshmem) {
        ZLOGE(LOG_LABEL, "parameter is not instanceof Ashmem");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, argv[ARGV_INDEX_0], (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    sptr<Ashmem> nativeAshmem = napiAshmem->GetAshmem();
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    bool result = napiSequence->nativeParcel_->WriteAshmem(nativeAshmem);
    if (!result) {
        ZLOGE(LOG_LABEL, "write ashmem failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    return napiValue;
}

ani_value ani_MessageSequence::JS_checkWriteRawDataArgs(ani_env env, size_t argc, ani_value* argv)
{
    if (argv == nullptr) {
        ZLOGE(LOG_LABEL, "argv is nullptr");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t expectedArgc = 2;
    if (argc != expectedArgc) {
        ZLOGE(LOG_LABEL, "requires 2 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        bool isTypedArray = false;
        ani_is_typedarray(env, argv[ARGV_INDEX_0], &isTypedArray);
        if (!isTypedArray) {
            ZLOGE(LOG_LABEL, "type mismatch for parameter 1, not array, not typedarray");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

bool ani_MessageSequence::JS_WriteRawDataForArray(ani_env env, ani_value jsArray,
    uint32_t size, ani_MessageSequence *napiSequence)
{
    std::vector<int32_t> array;
    uint32_t length = 0;
    ani_get_array_length(env, jsArray, &length);
    for (uint32_t i = 0; i < length; i++) {
        bool hasElement = false;
        ani_has_element(env, jsArray, i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        ani_value element = nullptr;
        ani_get_element(env, jsArray, i, &element);

        int32_t value = 0;
        ani_get_value_int32(env, element, &value);
        array.push_back(value);
    }
    if (length < size) {
        uint32_t padSize = size - length;
        ZLOGW(LOG_LABEL, "array length:%{public}u less than parameter size:%{public}u"
            " need pad:%{public}u 0", length, size, padSize);
        for (uint32_t i = 0; i < padSize; i++) {
            array.push_back(0);
        }
    }
    return napiSequence->nativeParcel_->WriteRawData(array.data(), size * BYTE_SIZE_32);
}

bool ani_MessageSequence::JS_WriteRawDataForTypedArray(ani_env env, ani_value jsTypedArray,
    size_t size, ani_MessageSequence *napiSequence)
{
    ani_typedarray_type type;
    char *data = nullptr;
    size_t arrayLength = 0;
    ani_value arrayBuffer;
    size_t byteOffset = 0;
    ani_status isGet = ani_get_typedarray_info(env, jsTypedArray, &type,
        &arrayLength, (void **)&data, &arrayBuffer, &byteOffset);
    if (isGet != ani_ok || type != ani_int32_array) {
        ZLOGE(LOG_LABEL, "typedarray get info failed or not ani_int32_array");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    if (arrayLength < size) {
        ZLOGE(LOG_LABEL, "typedarray length:%{public}zu less than parameter size:%{public}zu",
            arrayLength, size);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    return napiSequence->nativeParcel_->WriteRawData(data - byteOffset, BYTE_SIZE_32 * size);
}

ani_value ani_MessageSequence::JS_WriteRawData(ani_env env, ani_callback_info info)
{
    size_t argc = 2;
    ani_value argv[ARGV_LENGTH_2] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_value checkArgsResult = JS_checkWriteRawDataArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t size = 0;
    ani_status isGetOk = ani_get_value_int32(env, argv[ARGV_INDEX_1], &size);
    if (isGetOk != ani_ok || size <= 0) {
        ZLOGE(LOG_LABEL, "error for parameter 2 size is %{public}d, get failed", size);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    bool result = false;
    bool isArray = false;
    ani_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (isArray) {
        result = JS_WriteRawDataForArray(env, argv[ARGV_INDEX_0], static_cast<uint32_t>(size), napiSequence);
    } else {
        result = JS_WriteRawDataForTypedArray(env, argv[ARGV_INDEX_0], static_cast<size_t>(size), napiSequence);
    }

    if (!result) {
        ZLOGE(LOG_LABEL, "write raw data failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_WriteRawDataBuffer(ani_env env, ani_callback_info info)
{
    size_t argc = ARGV_LENGTH_2;
    ani_value argv[ARGV_LENGTH_2] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGV_LENGTH_2) {
        ZLOGE(LOG_LABEL, "requires 2 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
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
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    void *data = nullptr;
    size_t byteLength = 0;
    ani_status isGet = ani_get_arraybuffer_info(env, argv[ARGV_INDEX_0], (void **)&data, &byteLength);
    if (isGet != ani_ok) {
        ZLOGE(LOG_LABEL, "arraybuffer get info failed");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int64_t size = 0;
    ani_status isGetOk = ani_get_value_int64(env, argv[ARGV_INDEX_1], &size);
    if (isGetOk != ani_ok || size <= 0 || static_cast<size_t>(size) > byteLength) {
        ZLOGE(LOG_LABEL, "error for parameter 2 size is %{public}" PRId64, size);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    if (!napiSequence->nativeParcel_->WriteRawData(data, size)) {
        ZLOGE(LOG_LABEL, "write raw data failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_GetRawDataCapacity(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    ani_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);
    uint32_t result = napiSequence->nativeParcel_->GetRawDataCapacity();
    ani_value napiValue;
    ani_create_uint32(env, result, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_checkWriteArrayBufferArgs(ani_env env, size_t argc, ani_value* argv)
{
    if (argv == nullptr) {
        ZLOGE(LOG_LABEL, "argv is nullptr");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    if (argc != ARGV_LENGTH_2) {
        ZLOGE(LOG_LABEL, "requires 2 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    bool isArrayBuffer = false;
    ani_status status = ani_is_arraybuffer(env, argv[ARGV_INDEX_0], &isArrayBuffer);
    if (!isArrayBuffer) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1, not ArrayBuffer. status:%{public}d", status);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valuetype = ani_null;
    status = ani_typeof(env, argv[ARGV_INDEX_1], &valuetype);
    if (valuetype != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2, not number. status:%{public}d", status);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t typeCode = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_1], &typeCode);
    if (typeCode < INT8_ARRAY || typeCode > BIGUINT64_ARRAY) {
        ZLOGE(LOG_LABEL, "the value of parameter 2 is out of range. typeCode:%{public}d", typeCode);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

template<typename T>
static std::vector<T> BufferToVector(void *data, size_t byteLength)
{
    const T* dataPtr = reinterpret_cast<const T*>(data);
    std::vector<T> vec;
    std::copy(dataPtr, dataPtr + byteLength / sizeof(T), std::back_inserter(vec));
    return vec;
}

ani_value ani_MessageSequence::JS_writeArrayBuffer(ani_env env, ani_callback_info info)
{
    size_t argc = ARGV_LENGTH_2;
    ani_value argv[ARGV_LENGTH_2] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_value checkArgsResult = JS_checkWriteArrayBufferArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    void *data = nullptr;
    size_t byteLength = 0;
    ani_status getStatus = ani_get_arraybuffer_info(env, argv[ARGV_INDEX_0], (void **)&data, &byteLength);
    if (getStatus != ani_ok) {
        ZLOGE(LOG_LABEL, "arraybuffer get info failed. getStatus:%{public}d", getStatus);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    if (data == nullptr) {
        ZLOGE(LOG_LABEL, "data is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, byteLength, napiSequence);

    int32_t typeCode = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_1], &typeCode);

    bool writeSuccess = JS_writeVectorByTypeCode(typeCode, data, byteLength, napiSequence);
    if (!writeSuccess) {
        ZLOGE(LOG_LABEL, "write buffer failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

bool ani_MessageSequence::JS_writeVectorByTypeCode(int32_t typeCode,
                                                    void *data,
                                                    size_t byteLength,
                                                    ani_MessageSequence *napiSequence)
{
    if (data == nullptr || napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "data or napiSequence is null");
        return false;
    }
    switch (typeCode) {
        case INT8_ARRAY: {
            return napiSequence->nativeParcel_->WriteInt8Vector(BufferToVector<int8_t>(data, byteLength));
        }
        case UINT8_ARRAY: {
            return napiSequence->nativeParcel_->WriteUInt8Vector(BufferToVector<uint8_t>(data, byteLength));
        }
        case INT16_ARRAY: {
            return napiSequence->nativeParcel_->WriteInt16Vector(BufferToVector<int16_t>(data, byteLength));
        }
        case UINT16_ARRAY: {
            return napiSequence->nativeParcel_->WriteUInt16Vector(BufferToVector<uint16_t>(data, byteLength));
        }
        case INT32_ARRAY: {
            return napiSequence->nativeParcel_->WriteInt32Vector(BufferToVector<int32_t>(data, byteLength));
        }
        case UINT32_ARRAY: {
            return napiSequence->nativeParcel_->WriteUInt32Vector(BufferToVector<uint32_t>(data, byteLength));
        }
        case FLOAT32_ARRAY: {
            return napiSequence->nativeParcel_->WriteFloatVector(BufferToVector<float>(data, byteLength));
        }
        case FLOAT64_ARRAY: {
            return napiSequence->nativeParcel_->WriteDoubleVector(BufferToVector<double>(data, byteLength));
        }
        case BIGINT64_ARRAY: {
            return napiSequence->nativeParcel_->WriteInt64Vector(BufferToVector<int64_t>(data, byteLength));
        }
        case BIGUINT64_ARRAY: {
            return napiSequence->nativeParcel_->WriteUInt64Vector(BufferToVector<uint64_t>(data, byteLength));
        }
        default:
            ZLOGE(LOG_LABEL, "unsupported typeCode:%{public}d", typeCode);
            return false;
    }
}

ani_value ani_MessageSequence::Export(ani_env env, ani_value exports)
{
    const std::string className = "MessageSequence";
    ani_value typeCode = CreateTypeCodeEnum(env);
    ani_property_descriptor properties[] = {
        DECLARE_ani_STATIC_FUNCTION("create", ani_MessageSequence::JS_create),
        DECLARE_ani_FUNCTION("reclaim", ani_MessageSequence::JS_reclaim),
        DECLARE_ani_FUNCTION("writeRemoteObject", ani_MessageSequence::JS_writeRemoteObject),
        DECLARE_ani_FUNCTION("readRemoteObject", ani_MessageSequence::JS_readRemoteObject),
        DECLARE_ani_FUNCTION("writeInterfaceToken", ani_MessageSequence::JS_writeInterfaceToken),
        DECLARE_ani_FUNCTION("readInterfaceToken", ani_MessageSequence::JS_readInterfaceToken),
        DECLARE_ani_FUNCTION("getSize", ani_MessageSequence::JS_getSize),
        DECLARE_ani_FUNCTION("getCapacity", ani_MessageSequence::JS_getCapacity),
        DECLARE_ani_FUNCTION("setSize", ani_MessageSequence::JS_setSize),
        DECLARE_ani_FUNCTION("setCapacity", ani_MessageSequence::JS_setCapacity),
        DECLARE_ani_FUNCTION("getWritableBytes", ani_MessageSequence::JS_getWritableBytes),
        DECLARE_ani_FUNCTION("getReadableBytes", ani_MessageSequence::JS_getReadableBytes),
        DECLARE_ani_FUNCTION("getReadPosition", ani_MessageSequence::JS_getReadPosition),
        DECLARE_ani_FUNCTION("getWritePosition", ani_MessageSequence::JS_getWritePosition),
        DECLARE_ani_FUNCTION("rewindRead", ani_MessageSequence::JS_rewindRead),
        DECLARE_ani_FUNCTION("rewindWrite", ani_MessageSequence::JS_rewindWrite),
        DECLARE_ani_FUNCTION("writeNoException", ani_MessageSequence::JS_writeNoException),
        DECLARE_ani_FUNCTION("readException", ani_MessageSequence::JS_readException),
        DECLARE_ani_FUNCTION("writeByte", ani_MessageSequence::JS_writeByte),
        DECLARE_ani_FUNCTION("writeShort", ani_MessageSequence::JS_writeShort),
        DECLARE_ani_FUNCTION("writeInt", ani_MessageSequence::JS_writeInt),
        DECLARE_ani_FUNCTION("writeLong", ani_MessageSequence::JS_writeLong),
        DECLARE_ani_FUNCTION("writeFloat", ani_MessageSequence::JS_writeFloat),
        DECLARE_ani_FUNCTION("writeDouble", ani_MessageSequence::JS_writeDouble),
        DECLARE_ani_FUNCTION("writeBoolean", ani_MessageSequence::JS_writeBoolean),
        DECLARE_ani_FUNCTION("writeChar", ani_MessageSequence::JS_writeChar),
        DECLARE_ani_FUNCTION("writeString", ani_MessageSequence::JS_writeString),
        DECLARE_ani_FUNCTION("writeParcelable", ani_MessageSequence::JS_writeParcelable),
        DECLARE_ani_FUNCTION("writeByteArray", ani_MessageSequence::JS_writeByteArray),
        DECLARE_ani_FUNCTION("writeShortArray", ani_MessageSequence::JS_writeShortArray),
        DECLARE_ani_FUNCTION("writeIntArray", ani_MessageSequence::JS_writeIntArray),
        DECLARE_ani_FUNCTION("writeLongArray", ani_MessageSequence::JS_writeLongArray),
        DECLARE_ani_FUNCTION("writeFloatArray", ani_MessageSequence::JS_writeFloatArray),
        DECLARE_ani_FUNCTION("writeDoubleArray", ani_MessageSequence::JS_writeDoubleArray),
        DECLARE_ani_FUNCTION("writeBooleanArray", ani_MessageSequence::JS_writeBooleanArray),
        DECLARE_ani_FUNCTION("writeCharArray", ani_MessageSequence::JS_writeCharArray),
        DECLARE_ani_FUNCTION("writeStringArray", ani_MessageSequence::JS_writeStringArray),
        DECLARE_ani_FUNCTION("writeParcelableArray", ani_MessageSequence::JS_writeParcelableArray),
        DECLARE_ani_FUNCTION("writeRemoteObjectArray", ani_MessageSequence::JS_writeRemoteObjectArray),
        DECLARE_ani_FUNCTION("readByte", ani_MessageSequence::JS_readByte),
        DECLARE_ani_FUNCTION("readShort", ani_MessageSequence::JS_readShort),
        DECLARE_ani_FUNCTION("readInt", ani_MessageSequence::JS_readInt),
        DECLARE_ani_FUNCTION("readLong", ani_MessageSequence::JS_readLong),
        DECLARE_ani_FUNCTION("readFloat", ani_MessageSequence::JS_readFloat),
        DECLARE_ani_FUNCTION("readDouble", ani_MessageSequence::JS_readDouble),
        DECLARE_ani_FUNCTION("readBoolean", ani_MessageSequence::JS_readBoolean),
        DECLARE_ani_FUNCTION("readChar", ani_MessageSequence::JS_readChar),
        DECLARE_ani_FUNCTION("readString", ani_MessageSequence::JS_readString),
        DECLARE_ani_FUNCTION("readParcelable", ani_MessageSequence::JS_readParcelable),
        DECLARE_ani_FUNCTION("readByteArray", ani_MessageSequence::JS_readByteArray),
        DECLARE_ani_FUNCTION("readShortArray", ani_MessageSequence::JS_readShortArray),
        DECLARE_ani_FUNCTION("readIntArray", ani_MessageSequence::JS_readIntArray),
        DECLARE_ani_FUNCTION("readLongArray", ani_MessageSequence::JS_readLongArray),
        DECLARE_ani_FUNCTION("readFloatArray", ani_MessageSequence::JS_readFloatArray),
        DECLARE_ani_FUNCTION("readDoubleArray", ani_MessageSequence::JS_readDoubleArray),
        DECLARE_ani_FUNCTION("readBooleanArray", ani_MessageSequence::JS_readBooleanArray),
        DECLARE_ani_FUNCTION("readCharArray", ani_MessageSequence::JS_readCharArray),
        DECLARE_ani_FUNCTION("readStringArray", ani_MessageSequence::JS_readStringArray),
        DECLARE_ani_FUNCTION("readParcelableArray", ani_MessageSequence::JS_readParcelableArray),
        DECLARE_ani_FUNCTION("readRemoteObjectArray", ani_MessageSequence::JS_readRemoteObjectArray),
        DECLARE_ani_STATIC_FUNCTION("closeFileDescriptor", ani_MessageSequence::JS_CloseFileDescriptor),
        DECLARE_ani_STATIC_FUNCTION("dupFileDescriptor", ani_MessageSequence::JS_DupFileDescriptor),
        DECLARE_ani_FUNCTION("writeFileDescriptor", ani_MessageSequence::JS_WriteFileDescriptor),
        DECLARE_ani_FUNCTION("readFileDescriptor", ani_MessageSequence::JS_ReadFileDescriptor),
        DECLARE_ani_FUNCTION("containFileDescriptors", ani_MessageSequence::JS_ContainFileDescriptors),
        DECLARE_ani_FUNCTION("writeAshmem", ani_MessageSequence::JS_WriteAshmem),
        DECLARE_ani_FUNCTION("readAshmem", ani_MessageSequence::JS_ReadAshmem),
        DECLARE_ani_FUNCTION("getRawDataCapacity", ani_MessageSequence::JS_GetRawDataCapacity),
        DECLARE_ani_FUNCTION("writeRawData", ani_MessageSequence::JS_WriteRawData),
        DECLARE_ani_FUNCTION("readRawData", ani_MessageSequence::JS_ReadRawData),
        DECLARE_ani_FUNCTION("writeRawDataBuffer", ani_MessageSequence::JS_WriteRawDataBuffer),
        DECLARE_ani_FUNCTION("readRawDataBuffer", ani_MessageSequence::JS_ReadRawDataBuffer),
        DECLARE_ani_FUNCTION("writeArrayBuffer", ani_MessageSequence::JS_writeArrayBuffer),
        DECLARE_ani_FUNCTION("readArrayBuffer", ani_MessageSequence::JS_readArrayBuffer),
    };
    ani_value constructor = nullptr;
    ani_define_class(env, className.c_str(), className.length(), JS_constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    ani_ASSERT(env, constructor != nullptr, "define js class MessageSequence failed");
    ani_status status = ani_set_named_property(env, exports, "MessageSequence", constructor);
    ani_ASSERT(env, status == ani_ok, "set property MessageSequence failed");
    status = ani_set_named_property(env, exports, "TypeCode", typeCode);
    ani_ASSERT(env, status == ani_ok, "set property TypeCode failed");
    ani_value global = nullptr;
    status = ani_get_global(env, &global);
    ani_ASSERT(env, status == ani_ok, "get napi global failed");
    status = ani_set_named_property(env, global, "IPCSequenceConstructor_", constructor);
    ani_ASSERT(env, status == ani_ok, "set message sequence constructor failed");
    return exports;
}

ani_value ani_MessageSequence::JS_constructor(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_status status = ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    ani_ASSERT(env, status == ani_ok, "napi get callback info failed");
    MessageParcel *parcel = nullptr;
    if (argc > 0) {
        ani_unwrap(env, argv[ARGV_INDEX_0], (void **)&parcel);
        ani_ASSERT(env, parcel != nullptr, "parcel is null");
    }
    // new native parcel object
    auto messageSequence = new (std::nothrow) ani_MessageSequence(env, thisVar, parcel);
    ani_ASSERT(env, messageSequence != nullptr, "new messageSequence failed");
    // connect native object to js thisVar
    status = ani_wrap(
        env, thisVar, messageSequence,
        [](ani_env env, void *data, void *hint) {
            ani_MessageSequence *messageSequence = reinterpret_cast<ani_MessageSequence *>(data);
            if (!messageSequence->owner) {
                delete messageSequence;
            }
        },
        nullptr, nullptr);
    if (status != ani_ok) {
        delete messageSequence;
        ani_ASSERT(env, false, "napi wrap message parcel failed");
    }
    return thisVar;
}
} // namespace OHOS

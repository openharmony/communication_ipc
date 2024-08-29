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

#include "napi_message_sequence.h"

#include <cinttypes>
#include <cstring>
#include <unistd.h>

#include "hilog/log.h"
#include "ipc_debug.h"
#include "log_tags.h"
#include "napi_ashmem.h"
#include "napi_remote_object.h"
#include "napi_rpc_common.h"
#include "string_ex.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;
NapiError NAPI_MessageSequence::napiErr;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "NAPI_MessageSequenceWrite" };

NAPI_MessageSequence::NAPI_MessageSequence(napi_env env, napi_value thisVar, MessageParcel *parcel)
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

NAPI_MessageSequence::~NAPI_MessageSequence()
{
    ZLOGD(LOG_LABEL, "NAPI_MessageSequence::Destructor");
    nativeParcel_ = nullptr;
    env_ = nullptr;
}

void NAPI_MessageSequence::release(MessageParcel *parcel)
{
    ZLOGD(LOG_LABEL, "message parcel is created by others, do nothing");
}

std::shared_ptr<MessageParcel> NAPI_MessageSequence::GetMessageParcel()
{
    return nativeParcel_;
}

napi_value CreateTypeCodeEnum(napi_env env)
{
    napi_value enumValues[ENUM_TYPECODE_COUNT] = {nullptr};
    napi_value enumObject = nullptr;
    napi_create_object(env, &enumObject);
    for (size_t i = 0; i < ENUM_TYPECODE_COUNT; i++) {
        napi_create_int32(env, i, &enumValues[i]);
    }

    napi_property_descriptor enumDesc[] = {
        DECLARE_NAPI_PROPERTY("INT8_ARRAY", enumValues[INT8_ARRAY]),
        DECLARE_NAPI_PROPERTY("UINT8_ARRAY", enumValues[UINT8_ARRAY]),
        DECLARE_NAPI_PROPERTY("INT16_ARRAY", enumValues[INT16_ARRAY]),
        DECLARE_NAPI_PROPERTY("UINT16_ARRAY", enumValues[UINT16_ARRAY]),
        DECLARE_NAPI_PROPERTY("INT32_ARRAY", enumValues[INT32_ARRAY]),
        DECLARE_NAPI_PROPERTY("UINT32_ARRAY", enumValues[UINT32_ARRAY]),
        DECLARE_NAPI_PROPERTY("FLOAT32_ARRAY", enumValues[FLOAT32_ARRAY]),
        DECLARE_NAPI_PROPERTY("FLOAT64_ARRAY", enumValues[FLOAT64_ARRAY]),
        DECLARE_NAPI_PROPERTY("BIGINT64_ARRAY", enumValues[BIGINT64_ARRAY]),
        DECLARE_NAPI_PROPERTY("BIGUINT64_ARRAY", enumValues[BIGUINT64_ARRAY]),
    };
    napi_define_properties(env, enumObject, sizeof(enumDesc) / sizeof(enumDesc[0]), enumDesc);
    return enumObject;
}

napi_value NAPI_MessageSequence::JS_writeByte(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t value = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeShort(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t value = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeInt(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t value = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeLong(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int64_t value = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeFloat(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    double value = 0;
    napi_get_value_double(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeDouble(napi_env env, napi_callback_info info)
{
    // This function implementation is the same as JS_writeFloat
    return NAPI_MessageSequence::JS_writeFloat(env, info);
}

napi_value NAPI_MessageSequence::JS_writeBoolean(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_boolean) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    bool value = false;
    napi_get_value_bool(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeChar(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    uint32_t value = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeByteArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valueType;
        napi_typeof(env, element, &valueType);
        if (valueType != napi_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, napi_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int8 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_checkWriteArrayArgs(napi_env env,
                                                        size_t argc,
                                                        napi_value* argv,
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
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeShortArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valueType;
        napi_typeof(env, element, &valueType);
        if (valueType != napi_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, napi_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt16(static_cast<int16_t>(value));
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int16 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeIntArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valueType;
        napi_typeof(env, element, &valueType);
        if (valueType != napi_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, napi_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt32(value);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int32 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeLongArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valueType;
        napi_typeof(env, element, &valueType);
        if (valueType != napi_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, napi_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        int64_t value = 0;
        napi_get_value_int64(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt64(value);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int64 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeFloatArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valueType;
        napi_typeof(env, element, &valueType);
        if (valueType != napi_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, napi_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        double value = 0;
        napi_get_value_double(env, element, &value);
        result = napiSequence->nativeParcel_->WriteDouble(value);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write double failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeDoubleArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valueType;
        napi_typeof(env, element, &valueType);
        if (valueType != napi_number) {
            ZLOGE(LOG_LABEL, "type mismatch. valueType %{public}d is not equal %{public}d", valueType, napi_number);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        double value = 0;
        napi_get_value_double(env, element, &value);
        result = napiSequence->nativeParcel_->WriteDouble(value);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write double failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeBooleanArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        bool value = false;
        napi_get_value_bool(env, element, &value);
        result = napiSequence->nativeParcel_->WriteInt8(static_cast<int8_t>(value));
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int8 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeCharArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        uint32_t value = 0;
        napi_get_value_uint32(env, element, &value);
        result = napiSequence->nativeParcel_->WriteUint8(static_cast<uint8_t>(value));
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write uint8 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeString(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t bufferSize = 0;
    size_t maxLen = MAX_BYTES_LENGTH;
    napi_get_value_string_utf16(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char16_t stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf16(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    if (jsStringLength != bufferSize) {
        ZLOGE(LOG_LABEL, "string length wrong");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_checkWriteStringArrayElement(napi_env env,
                                                                 napi_value* argv,
                                                                 size_t &index,
                                                                 size_t &bufferSize,
                                                                 napi_value &element)
{
    if (argv == nullptr) {
        ZLOGE(LOG_LABEL, "argv is nullptr");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    bool hasElement = false;
    size_t maxSize = MAX_BYTES_LENGTH;
    napi_has_element(env, argv[ARGV_INDEX_0], index, &hasElement);
    if (!hasElement) {
        ZLOGE(LOG_LABEL, "parameter check error");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_get_element(env, argv[ARGV_INDEX_0], index, &element);
    napi_valuetype valuetype;
    napi_typeof(env, element, &valuetype);
    if (valuetype != napi_string) {
        ZLOGE(LOG_LABEL, "Parameter type error");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_get_value_string_utf16(env, element, nullptr, 0, &bufferSize);
    if (bufferSize >= maxSize) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeStringArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        size_t bufferSize = 0;
        napi_value element = nullptr;
        napi_value checkElementResult = JS_checkWriteStringArrayElement(env, argv, i, bufferSize, element);
        if (checkElementResult == nullptr) {
            return checkElementResult;
        }
        char16_t stringValue[bufferSize + 1];
        size_t jsStringLength = 0;
        napi_get_value_string_utf16(env, element, stringValue, bufferSize + 1, &jsStringLength);
        if (jsStringLength != bufferSize) {
            ZLOGE(LOG_LABEL, "string length wrong");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        REWIND_IF_WRITE_CHECK_FAIL(env, BYTE_SIZE_32 * bufferSize, pos, napiSequence);
        result = napiSequence->nativeParcel_->WriteString16(stringValue);
        if (!result) {
            napiSequence->nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write string16 failed");
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeParcelable(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType == napi_null || valueType == napi_undefined) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    napiSequence->nativeParcel_->WriteInt32(1);
    napi_value propKey = nullptr;
    const char *propKeyStr = "marshalling";
    napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
    napi_value prop = nullptr;
    napi_get_property(env, argv[ARGV_INDEX_0], propKey, &prop);

    napi_value funcArg[1] = { thisVar };
    napi_value callResult = nullptr;
    napi_call_function(env, argv[ARGV_INDEX_0], prop, 1, funcArg, &callResult);
    bool isPendingException = false;
    napi_is_exception_pending(env, &isPendingException);
    if (isPendingException) {
        napi_value lastException = nullptr;
        ZLOGE(LOG_LABEL, "call mashalling failed");
        napi_get_and_clear_last_exception(env, &lastException);
        napiSequence->nativeParcel_->RewindWrite(pos);
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_typeof(env, callResult, &valueType);
    if (callResult != nullptr && valueType != napi_undefined) {
        return callResult;
    }
    ZLOGE(LOG_LABEL, "call mashalling failed");
    napiSequence->nativeParcel_->RewindWrite(pos);
    return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
}

napi_value NAPI_MessageSequence::JS_writeParcelableArrayCallJsFunc(napi_env env,
    napi_value &element, napi_value &thisVar)
{
    napi_value propKey = nullptr;
    const char *propKeyStr = "marshalling";
    napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
    napi_value prop = nullptr;
    napi_get_property(env, element, propKey, &prop);

    napi_value funcArg[1] = { thisVar };
    napi_value callResult = nullptr;
    napi_call_function(env, element, prop, 1, funcArg, &callResult);
    napi_valuetype valueType = napi_null;
    napi_typeof(env, callResult, &valueType);
    if (callResult == nullptr || valueType == napi_undefined) {
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    napi_value retValue = nullptr;
    napi_get_undefined(env, &retValue);
    return retValue;
}

napi_value NAPI_MessageSequence::JS_writeParcelableArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    bool result = napiSequence->nativeParcel_->WriteUint32(arrayLength);
    if (!result) {
        ZLOGE(LOG_LABEL, "write uint32 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        napi_valuetype valueType = napi_null;
        napi_typeof(env, element, &valueType);
        if (valueType == napi_null || valueType == napi_undefined) {
            napiSequence->nativeParcel_->WriteInt32(0);
            continue;
        } else {
            napiSequence->nativeParcel_->WriteInt32(1);
        }
        napi_value callResult = JS_writeParcelableArrayCallJsFunc(env, element, thisVar);
        if (callResult == nullptr) {
            ZLOGE(LOG_LABEL, "call mashalling failed, element index:%{public}zu", i);
            napiSequence->nativeParcel_->RewindWrite(pos);
            return callResult;
        }
    }
    napi_value retValue = nullptr;
    napi_get_undefined(env, &retValue);
    return retValue;
}

napi_value NAPI_MessageSequence::JS_writeRemoteObjectArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType == napi_null || valueType == napi_undefined) {
        napiSequence->nativeParcel_->WriteInt32(-1);
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t pos = napiSequence->nativeParcel_->GetWritePosition();
    bool result =  napiSequence->nativeParcel_->WriteInt32(arrayLength);
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }
        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
        sptr<IRemoteObject> remoteObject = NAPI_ohos_rpc_getNativeRemoteObject(env, element);
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
    napi_value retValue = nullptr;
    napi_get_undefined(env, &retValue);
    return retValue;
}

napi_value NAPI_MessageSequence::JS_setSize(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    uint32_t value = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    bool result = napiSequence->nativeParcel_->SetDataSize(static_cast<size_t>(value));
    if (!result) {
        ZLOGE(LOG_LABEL, "set data size failed");
    }
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_setCapacity(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    uint32_t value = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &value);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_getWritableBytes(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetWritableBytes();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_getWritePosition(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetWritePosition();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_rewindWrite(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    uint32_t pos = 0;
    napi_get_value_uint32(env, argv[ARGV_INDEX_0], &pos);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    bool result = napiSequence->nativeParcel_->RewindWrite(static_cast<size_t>(pos));
    NAPI_ASSERT(env, result == true, "rewind write failed");
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeNoException(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    bool writeResult = napiSequence->nativeParcel_->WriteInt32(0);
    if (writeResult == false) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_checkReadArrayArgs(napi_env env,
                                                       napi_callback_info info,
                                                       size_t &argc,
                                                       napi_value &thisVar,
                                                       napi_value* argv)
{
    if (argv == nullptr) {
        ZLOGE(LOG_LABEL, "argv is nullptr");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readParcelableArrayCallJsFunc(napi_env env,
    napi_value &element, napi_value &thisVar)
{
    napi_value propKey = nullptr;
    const char *propKeyStr = "unmarshalling";
    napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
    napi_value prop = nullptr;
    napi_get_property(env, element, propKey, &prop);

    napi_value funcArg[1] = { thisVar };
    napi_value callResult = nullptr;
    napi_call_function(env, element, prop, 1, funcArg, &callResult);
    if (callResult == nullptr) {
        return napiErr.ThrowError(env, errorDesc::CALL_JS_METHOD_ERROR);
    }

    napi_value retValue = nullptr;
    napi_get_undefined(env, &retValue);
    return retValue;
}

napi_value NAPI_MessageSequence::JS_create(napi_env env, napi_callback_info info)
{
    // new native sequence object
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "IPCSequenceConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get message sequence constructor failed");
    napi_value jsMessageSequence;
    status = napi_new_instance(env, constructor, 0, nullptr, &jsMessageSequence);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js MessageSequence");
    return jsMessageSequence;
}

napi_value NAPI_MessageSequence::JS_reclaim(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_remove_wrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT(env, napiSequence != nullptr, "napiSequence is null");
    delete napiSequence;

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_writeRemoteObject(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_object) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    sptr<IRemoteObject> remoteObject = NAPI_ohos_rpc_getNativeRemoteObject(env, argv[ARGV_INDEX_0]);
    if (remoteObject == nullptr) {
        ZLOGE(LOG_LABEL, "remote object is nullptr");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    bool writeResult = napiSequence->nativeParcel_->WriteRemoteObject(remoteObject);
    if (writeResult == false) {
        ZLOGE(LOG_LABEL, "write remote object failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_writeInterfaceToken(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_string) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    size_t bufferSize = 0;
    size_t maxSize = MAX_BYTES_LENGTH;
    napi_get_value_string_utf16(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize >= maxSize) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char16_t stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf16(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
    if (jsStringLength != bufferSize) {
        ZLOGE(LOG_LABEL, "string length wrong");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    bool writeResult = napiSequence->nativeParcel_->WriteInterfaceToken(stringValue);
    if (writeResult == false) {
        ZLOGE(LOG_LABEL, "write interface token failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_CloseFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t fd = -1;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    close(fd);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_DupFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t fd = -1;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    int32_t dupResult = dup(fd);
    if (dupResult < 0) {
        ZLOGE(LOG_LABEL, "os dup function failed");
        return napiErr.ThrowError(env, errorDesc::OS_DUP_ERROR);
    }
    napi_value napiValue;
    napi_create_int32(env, dupResult, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_ContainFileDescriptors(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);
    bool result = napiSequence->nativeParcel_->ContainFileDescriptors();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_WriteFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int32_t fd = -1;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &fd);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    bool result = napiSequence->nativeParcel_->WriteFileDescriptor(fd);
    if (!result) {
        ZLOGE(LOG_LABEL, "write file descriptor failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_WriteAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    // check type is Ashmem
    napi_value global = nullptr;
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    napi_status status = napi_get_global(env, &global);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get napi global failed");
        return napiValue;
    }
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "AshmemConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get Ashmem constructor failed");
        return napiValue;
    }
    bool isAshmem = false;
    napi_instanceof(env, argv[ARGV_INDEX_0], constructor, &isAshmem);
    if (!isAshmem) {
        ZLOGE(LOG_LABEL, "parameter is not instanceof Ashmem");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, argv[ARGV_INDEX_0], (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    sptr<Ashmem> nativeAshmem = napiAshmem->GetAshmem();
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
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

napi_value NAPI_MessageSequence::JS_checkWriteRawDataArgs(napi_env env, size_t argc, napi_value* argv)
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
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        bool isTypedArray = false;
        napi_is_typedarray(env, argv[ARGV_INDEX_0], &isTypedArray);
        if (!isTypedArray) {
            ZLOGE(LOG_LABEL, "type mismatch for parameter 1, not array, not typedarray");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_1], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

bool NAPI_MessageSequence::JS_WriteRawDataForArray(napi_env env, napi_value jsArray,
    uint32_t size, NAPI_MessageSequence *napiSequence)
{
    std::vector<int32_t> array;
    uint32_t length = 0;
    napi_get_array_length(env, jsArray, &length);
    for (uint32_t i = 0; i < length; i++) {
        bool hasElement = false;
        napi_has_element(env, jsArray, i, &hasElement);
        if (!hasElement) {
            ZLOGE(LOG_LABEL, "parameter check error");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, jsArray, i, &element);

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
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

bool NAPI_MessageSequence::JS_WriteRawDataForTypedArray(napi_env env, napi_value jsTypedArray,
    size_t size, NAPI_MessageSequence *napiSequence)
{
    napi_typedarray_type type;
    char *data = nullptr;
    size_t arrayLength = 0;
    napi_value arrayBuffer;
    size_t byteOffset = 0;
    napi_status isGet = napi_get_typedarray_info(env, jsTypedArray, &type,
        &arrayLength, (void **)&data, &arrayBuffer, &byteOffset);
    if (isGet != napi_ok || type != napi_int32_array) {
        ZLOGE(LOG_LABEL, "typedarray get info failed or not napi_int32_array");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    if (arrayLength < size) {
        ZLOGE(LOG_LABEL, "typedarray length:%{public}zu less than parameter size:%{public}zu",
            arrayLength, size);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    return napiSequence->nativeParcel_->WriteRawData(data - byteOffset, BYTE_SIZE_32 * size);
}

napi_value NAPI_MessageSequence::JS_WriteRawData(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[ARGV_LENGTH_2] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = JS_checkWriteRawDataArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t size = 0;
    napi_status isGetOk = napi_get_value_int32(env, argv[ARGV_INDEX_1], &size);
    if (isGetOk != napi_ok || size <= 0) {
        ZLOGE(LOG_LABEL, "error for parameter 2 size is %{public}d, get failed", size);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    bool result = false;
    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (isArray) {
        result = JS_WriteRawDataForArray(env, argv[ARGV_INDEX_0], static_cast<uint32_t>(size), napiSequence);
    } else {
        result = JS_WriteRawDataForTypedArray(env, argv[ARGV_INDEX_0], static_cast<size_t>(size), napiSequence);
    }

    if (!result) {
        ZLOGE(LOG_LABEL, "write raw data failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_WriteRawDataBuffer(napi_env env, napi_callback_info info)
{
    size_t argc = ARGV_LENGTH_2;
    napi_value argv[ARGV_LENGTH_2] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGV_LENGTH_2) {
        ZLOGE(LOG_LABEL, "requires 2 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
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
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    void *data = nullptr;
    size_t byteLength = 0;
    napi_status isGet = napi_get_arraybuffer_info(env, argv[ARGV_INDEX_0], (void **)&data, &byteLength);
    if (isGet != napi_ok) {
        ZLOGE(LOG_LABEL, "arraybuffery get info failed");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int64_t size = 0;
    napi_status isGetOk = napi_get_value_int64(env, argv[ARGV_INDEX_1], &size);
    if (isGetOk != napi_ok || size <= 0 || static_cast<size_t>(size) > byteLength) {
        ZLOGE(LOG_LABEL, "error for parameter 2 size is %{public}" PRId64, size);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    if (!napiSequence->nativeParcel_->WriteRawData(data, size)) {
        ZLOGE(LOG_LABEL, "write raw data failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_GetRawDataCapacity(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);
    uint32_t result = napiSequence->nativeParcel_->GetRawDataCapacity();
    napi_value napiValue;
    napi_create_uint32(env, result, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_checkWriteArrayBufferArgs(napi_env env, size_t argc, napi_value* argv)
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
    napi_status status = napi_is_arraybuffer(env, argv[ARGV_INDEX_0], &isArrayBuffer);
    if (!isArrayBuffer) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1, not ArrayBuffer. status:%{public}d", status);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valuetype = napi_null;
    status = napi_typeof(env, argv[ARGV_INDEX_1], &valuetype);
    if (valuetype != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 2, not number. status:%{public}d", status);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    int32_t typeCode = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &typeCode);
    if (typeCode < INT8_ARRAY || typeCode > BIGUINT64_ARRAY) {
        ZLOGE(LOG_LABEL, "the value of parameter 2 is out of range. typeCode:%{public}d", typeCode);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
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

napi_value NAPI_MessageSequence::JS_writeArrayBuffer(napi_env env, napi_callback_info info)
{
    size_t argc = ARGV_LENGTH_2;
    napi_value argv[ARGV_LENGTH_2] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = JS_checkWriteArrayBufferArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    void *data = nullptr;
    size_t byteLength = 0;
    napi_status getStatus = napi_get_arraybuffer_info(env, argv[ARGV_INDEX_0], (void **)&data, &byteLength);
    if (getStatus != napi_ok) {
        ZLOGE(LOG_LABEL, "arraybuffer get info failed. getStatus:%{public}d", getStatus);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    if (data == nullptr) {
        ZLOGE(LOG_LABEL, "data is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    CHECK_WRITE_CAPACITY(env, byteLength, napiSequence);

    int32_t typeCode = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &typeCode);

    bool writeSuccess = JS_writeVectorByTypeCode(typeCode, data, byteLength, napiSequence);
    if (!writeSuccess) {
        ZLOGE(LOG_LABEL, "write buffer failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }

    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

bool NAPI_MessageSequence::JS_writeVectorByTypeCode(int32_t typeCode,
                                                    void *data,
                                                    size_t byteLength,
                                                    NAPI_MessageSequence *napiSequence)
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

napi_value NAPI_MessageSequence::Export(napi_env env, napi_value exports)
{
    const std::string className = "MessageSequence";
    napi_value typeCode = CreateTypeCodeEnum(env);
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("create", NAPI_MessageSequence::JS_create),
        DECLARE_NAPI_FUNCTION("reclaim", NAPI_MessageSequence::JS_reclaim),
        DECLARE_NAPI_FUNCTION("writeRemoteObject", NAPI_MessageSequence::JS_writeRemoteObject),
        DECLARE_NAPI_FUNCTION("readRemoteObject", NAPI_MessageSequence::JS_readRemoteObject),
        DECLARE_NAPI_FUNCTION("writeInterfaceToken", NAPI_MessageSequence::JS_writeInterfaceToken),
        DECLARE_NAPI_FUNCTION("readInterfaceToken", NAPI_MessageSequence::JS_readInterfaceToken),
        DECLARE_NAPI_FUNCTION("getSize", NAPI_MessageSequence::JS_getSize),
        DECLARE_NAPI_FUNCTION("getCapacity", NAPI_MessageSequence::JS_getCapacity),
        DECLARE_NAPI_FUNCTION("setSize", NAPI_MessageSequence::JS_setSize),
        DECLARE_NAPI_FUNCTION("setCapacity", NAPI_MessageSequence::JS_setCapacity),
        DECLARE_NAPI_FUNCTION("getWritableBytes", NAPI_MessageSequence::JS_getWritableBytes),
        DECLARE_NAPI_FUNCTION("getReadableBytes", NAPI_MessageSequence::JS_getReadableBytes),
        DECLARE_NAPI_FUNCTION("getReadPosition", NAPI_MessageSequence::JS_getReadPosition),
        DECLARE_NAPI_FUNCTION("getWritePosition", NAPI_MessageSequence::JS_getWritePosition),
        DECLARE_NAPI_FUNCTION("rewindRead", NAPI_MessageSequence::JS_rewindRead),
        DECLARE_NAPI_FUNCTION("rewindWrite", NAPI_MessageSequence::JS_rewindWrite),
        DECLARE_NAPI_FUNCTION("writeNoException", NAPI_MessageSequence::JS_writeNoException),
        DECLARE_NAPI_FUNCTION("readException", NAPI_MessageSequence::JS_readException),
        DECLARE_NAPI_FUNCTION("writeByte", NAPI_MessageSequence::JS_writeByte),
        DECLARE_NAPI_FUNCTION("writeShort", NAPI_MessageSequence::JS_writeShort),
        DECLARE_NAPI_FUNCTION("writeInt", NAPI_MessageSequence::JS_writeInt),
        DECLARE_NAPI_FUNCTION("writeLong", NAPI_MessageSequence::JS_writeLong),
        DECLARE_NAPI_FUNCTION("writeFloat", NAPI_MessageSequence::JS_writeFloat),
        DECLARE_NAPI_FUNCTION("writeDouble", NAPI_MessageSequence::JS_writeDouble),
        DECLARE_NAPI_FUNCTION("writeBoolean", NAPI_MessageSequence::JS_writeBoolean),
        DECLARE_NAPI_FUNCTION("writeChar", NAPI_MessageSequence::JS_writeChar),
        DECLARE_NAPI_FUNCTION("writeString", NAPI_MessageSequence::JS_writeString),
        DECLARE_NAPI_FUNCTION("writeParcelable", NAPI_MessageSequence::JS_writeParcelable),
        DECLARE_NAPI_FUNCTION("writeByteArray", NAPI_MessageSequence::JS_writeByteArray),
        DECLARE_NAPI_FUNCTION("writeShortArray", NAPI_MessageSequence::JS_writeShortArray),
        DECLARE_NAPI_FUNCTION("writeIntArray", NAPI_MessageSequence::JS_writeIntArray),
        DECLARE_NAPI_FUNCTION("writeLongArray", NAPI_MessageSequence::JS_writeLongArray),
        DECLARE_NAPI_FUNCTION("writeFloatArray", NAPI_MessageSequence::JS_writeFloatArray),
        DECLARE_NAPI_FUNCTION("writeDoubleArray", NAPI_MessageSequence::JS_writeDoubleArray),
        DECLARE_NAPI_FUNCTION("writeBooleanArray", NAPI_MessageSequence::JS_writeBooleanArray),
        DECLARE_NAPI_FUNCTION("writeCharArray", NAPI_MessageSequence::JS_writeCharArray),
        DECLARE_NAPI_FUNCTION("writeStringArray", NAPI_MessageSequence::JS_writeStringArray),
        DECLARE_NAPI_FUNCTION("writeParcelableArray", NAPI_MessageSequence::JS_writeParcelableArray),
        DECLARE_NAPI_FUNCTION("writeRemoteObjectArray", NAPI_MessageSequence::JS_writeRemoteObjectArray),
        DECLARE_NAPI_FUNCTION("readByte", NAPI_MessageSequence::JS_readByte),
        DECLARE_NAPI_FUNCTION("readShort", NAPI_MessageSequence::JS_readShort),
        DECLARE_NAPI_FUNCTION("readInt", NAPI_MessageSequence::JS_readInt),
        DECLARE_NAPI_FUNCTION("readLong", NAPI_MessageSequence::JS_readLong),
        DECLARE_NAPI_FUNCTION("readFloat", NAPI_MessageSequence::JS_readFloat),
        DECLARE_NAPI_FUNCTION("readDouble", NAPI_MessageSequence::JS_readDouble),
        DECLARE_NAPI_FUNCTION("readBoolean", NAPI_MessageSequence::JS_readBoolean),
        DECLARE_NAPI_FUNCTION("readChar", NAPI_MessageSequence::JS_readChar),
        DECLARE_NAPI_FUNCTION("readString", NAPI_MessageSequence::JS_readString),
        DECLARE_NAPI_FUNCTION("readParcelable", NAPI_MessageSequence::JS_readParcelable),
        DECLARE_NAPI_FUNCTION("readByteArray", NAPI_MessageSequence::JS_readByteArray),
        DECLARE_NAPI_FUNCTION("readShortArray", NAPI_MessageSequence::JS_readShortArray),
        DECLARE_NAPI_FUNCTION("readIntArray", NAPI_MessageSequence::JS_readIntArray),
        DECLARE_NAPI_FUNCTION("readLongArray", NAPI_MessageSequence::JS_readLongArray),
        DECLARE_NAPI_FUNCTION("readFloatArray", NAPI_MessageSequence::JS_readFloatArray),
        DECLARE_NAPI_FUNCTION("readDoubleArray", NAPI_MessageSequence::JS_readDoubleArray),
        DECLARE_NAPI_FUNCTION("readBooleanArray", NAPI_MessageSequence::JS_readBooleanArray),
        DECLARE_NAPI_FUNCTION("readCharArray", NAPI_MessageSequence::JS_readCharArray),
        DECLARE_NAPI_FUNCTION("readStringArray", NAPI_MessageSequence::JS_readStringArray),
        DECLARE_NAPI_FUNCTION("readParcelableArray", NAPI_MessageSequence::JS_readParcelableArray),
        DECLARE_NAPI_FUNCTION("readRemoteObjectArray", NAPI_MessageSequence::JS_readRemoteObjectArray),
        DECLARE_NAPI_STATIC_FUNCTION("closeFileDescriptor", NAPI_MessageSequence::JS_CloseFileDescriptor),
        DECLARE_NAPI_STATIC_FUNCTION("dupFileDescriptor", NAPI_MessageSequence::JS_DupFileDescriptor),
        DECLARE_NAPI_FUNCTION("writeFileDescriptor", NAPI_MessageSequence::JS_WriteFileDescriptor),
        DECLARE_NAPI_FUNCTION("readFileDescriptor", NAPI_MessageSequence::JS_ReadFileDescriptor),
        DECLARE_NAPI_FUNCTION("containFileDescriptors", NAPI_MessageSequence::JS_ContainFileDescriptors),
        DECLARE_NAPI_FUNCTION("writeAshmem", NAPI_MessageSequence::JS_WriteAshmem),
        DECLARE_NAPI_FUNCTION("readAshmem", NAPI_MessageSequence::JS_ReadAshmem),
        DECLARE_NAPI_FUNCTION("getRawDataCapacity", NAPI_MessageSequence::JS_GetRawDataCapacity),
        DECLARE_NAPI_FUNCTION("writeRawData", NAPI_MessageSequence::JS_WriteRawData),
        DECLARE_NAPI_FUNCTION("readRawData", NAPI_MessageSequence::JS_ReadRawData),
        DECLARE_NAPI_FUNCTION("writeRawDataBuffer", NAPI_MessageSequence::JS_WriteRawDataBuffer),
        DECLARE_NAPI_FUNCTION("readRawDataBuffer", NAPI_MessageSequence::JS_ReadRawDataBuffer),
        DECLARE_NAPI_FUNCTION("writeArrayBuffer", NAPI_MessageSequence::JS_writeArrayBuffer),
        DECLARE_NAPI_FUNCTION("readArrayBuffer", NAPI_MessageSequence::JS_readArrayBuffer),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), JS_constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class MessageSequence failed");
    napi_status status = napi_set_named_property(env, exports, "MessageSequence", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property MessageSequence failed");
    status = napi_set_named_property(env, exports, "TypeCode", typeCode);
    NAPI_ASSERT(env, status == napi_ok, "set property TypeCode failed");
    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    status = napi_set_named_property(env, global, "IPCSequenceConstructor_", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set message sequence constructor failed");
    return exports;
}

napi_value NAPI_MessageSequence::JS_constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi get callback info failed");
    MessageParcel *parcel = nullptr;
    if (argc > 0) {
        napi_unwrap(env, argv[ARGV_INDEX_0], (void **)&parcel);
        NAPI_ASSERT(env, parcel != nullptr, "parcel is null");
    }
    // new native parcel object
    auto messageSequence = new NAPI_MessageSequence(env, thisVar, parcel);
    // connect native object to js thisVar
    status = napi_wrap(
        env, thisVar, messageSequence,
        [](napi_env env, void *data, void *hint) {
            NAPI_MessageSequence *messageSequence = reinterpret_cast<NAPI_MessageSequence *>(data);
            if (!messageSequence->owner) {
                delete messageSequence;
            }
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi wrap message parcel failed");
    return thisVar;
}
} // namespace OHOS

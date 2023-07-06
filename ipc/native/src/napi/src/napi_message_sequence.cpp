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
#include <cstring>
#include <unistd.h>
#include "hilog/log.h"
#include "log_tags.h"
#include "napi_ashmem.h"
#include "napi_remote_object.h"
#include "string_ex.h"
#include "ipc_debug.h"


namespace OHOS {
using namespace OHOS::HiviewDFX;
constexpr size_t MAX_CAPACITY_TO_WRITE = 200 * 1024;
constexpr size_t BYTE_SIZE_8 = 1;
constexpr size_t BYTE_SIZE_32 = 4;
constexpr size_t BYTE_SIZE_64 = 8;

NapiError NAPI_MessageSequence::napiErr;

static const size_t ARGV_INDEX_0 = 0;
static const size_t ARGV_INDEX_1 = 1;
static const size_t ARGV_INDEX_2 = 2;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "NAPI_MessageSequence" };

#define CHECK_WRITE_CAPACITY(env, lenToWrite, napiParcel)                                              \
    do {                                                                                               \
        size_t cap =  (napiParcel)->maxCapacityToWrite_ - (napiParcel)->nativeParcel_->GetWritePosition(); \
        if (cap < (lenToWrite)) {                                                                      \
            ZLOGI(LOG_LABEL, "No enough capacity to write");                                           \
            napi_throw_range_error(env, nullptr, "No enough capacity to write");                       \
        }                                                                                              \
    } while (0)

#define REWIND_IF_WRITE_CHECK_FAIL(env, lenToWrite, pos, napiParcel)                                  \
    do {                                                                                              \
        size_t cap = (napiParcel)->maxCapacityToWrite_ - (napiParcel)->nativeParcel_->GetWritePosition(); \
        if (cap < (lenToWrite)) {                                                                     \
            ZLOGI(LOG_LABEL, "No enough capacity to write");                                          \
            (napiParcel)->nativeParcel_->RewindWrite(pos);                                              \
            napi_throw_range_error(env, nullptr, "No enough capacity to write");                      \
        }                                                                                             \
    } while (0)

#define CHECK_READ_LENGTH(env, arrayLength, typeSize, napiParcel)                                                    \
    do {                                                                                                             \
        size_t remainSize = (napiParcel)->nativeParcel_->GetDataSize() -                                             \
            (napiParcel)->nativeParcel_->GetReadPosition();                                                          \
        if (((arrayLength) < 0) || ((arrayLength) > remainSize) || (((arrayLength) * (typeSize)) > remainSize)) {    \
            ZLOGI(LOG_LABEL, "No enough data to read");                                                              \
            napi_throw_range_error(env, nullptr, "No enough data to read");                                          \
        }                                                                                                            \
    } while (0)

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
    ZLOGI(LOG_LABEL, "NAPI_MessageSequence::Destructor");
    nativeParcel_ = nullptr;
    env_ = nullptr;
}

void NAPI_MessageSequence::release(MessageParcel *parcel)
{
    ZLOGI(LOG_LABEL, "message parcel is created by others, do nothing");
}

std::shared_ptr<MessageParcel> NAPI_MessageSequence::GetMessageParcel()
{
    return nativeParcel_;
}

napi_value NAPI_MessageSequence::JS_writeByte(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
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
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
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
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
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
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
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
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
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
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
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

napi_value NAPI_MessageSequence::JS_writeBoolean(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_boolean) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    bool value = 0;
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
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
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

napi_value NAPI_MessageSequence::JS_checkWriteByteArrayArgs(napi_env env,
                                                            size_t argc,
                                                            napi_value* argv,
                                                            uint32_t &arrayLength)
{
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    uint32_t maxBytesLen = 40960;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &arrayLength);
    if (arrayLength >= maxBytesLen) {
        ZLOGE(LOG_LABEL, "write byte array length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_writeByteArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteByteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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
    if (argc != 1) {
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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
            ZLOGE(LOG_LABEL, "type mismatch element");
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }
    ZLOGI(LOG_LABEL, "messageparcel WriteBuffer typedarrayLength = %{public}d", (int)(arrayLength));

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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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

        bool value = 0;
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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
    napi_value argv[ARGV_INDEX_1] = {0};
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
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
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
    std::string parcelString = stringValue;
    bool result = napiSequence->nativeParcel_->WriteString16(to_utf16(parcelString));
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
    bool hasElement = false;
    size_t maxSize = 40960;
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

    napi_get_value_string_utf8(env, element, nullptr, 0, &bufferSize);
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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
        char stringValue[bufferSize + 1];
        size_t jsStringLength = 0;
        napi_get_value_string_utf8(env, element, stringValue, bufferSize + 1, &jsStringLength);
        if (jsStringLength != bufferSize) {
            ZLOGE(LOG_LABEL, "string length wrong");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        REWIND_IF_WRITE_CHECK_FAIL(env, BYTE_SIZE_32 * bufferSize, pos, napiSequence);
        std::string parcelString = stringValue;
        result = napiSequence->nativeParcel_->WriteString16(to_utf16(parcelString));
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
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
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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
            ZLOGE(LOG_LABEL, "call mashalling failed, element index: %{public}zu", i);
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    uint32_t arrayLength = 0;
    napi_value checkArgsResult = JS_checkWriteArrayArgs(env, argc, argv, arrayLength);
    if (checkArgsResult == nullptr) {
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

napi_value NAPI_MessageSequence::JS_readByte(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int8_t value = napiSequence->nativeParcel_->ReadInt8();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readShort(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int16_t value = napiSequence->nativeParcel_->ReadInt16();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readInt(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t value = napiSequence->nativeParcel_->ReadInt32();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readLong(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int64_t value = napiSequence->nativeParcel_->ReadInt64();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_int64(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readFloat(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    double value = napiSequence->nativeParcel_->ReadDouble();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_double(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readDouble(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    double value = napiSequence->nativeParcel_->ReadDouble();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_double(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readBoolean(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int8_t value = napiSequence->nativeParcel_->ReadInt8();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readChar(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint8_t value = napiSequence->nativeParcel_->ReadUint8();
    napi_value result = nullptr;
    napi_create_uint32(env, static_cast<uint32_t>(value), &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_readString(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    std::u16string parcelString = napiSequence->nativeParcel_->ReadString16();
    std::string outString = Str16ToStr8(parcelString.c_str());
    napi_value napiValue = nullptr;
    napi_create_string_utf8(env, outString.c_str(), outString.length(), &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_getSize(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", 0);

    size_t value = napiSequence->nativeParcel_->GetDataSize();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_getCapacity(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", 0);

    size_t value = napiSequence->nativeParcel_->GetDataCapacity();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_setSize(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
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
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
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
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
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
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
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
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", 0);

    size_t value = napiSequence->nativeParcel_->GetWritableBytes();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_getReadableBytes(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", 0);

    size_t value = napiSequence->nativeParcel_->GetReadableBytes();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_getReadPosition(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", 0);

    size_t value = napiSequence->nativeParcel_->GetReadPosition();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_rewindRead(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = {0};
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
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    bool result = napiSequence->nativeParcel_->RewindRead(static_cast<size_t>(pos));
    if (!result) {
        ZLOGE(LOG_LABEL, "rewind write failed");
    }
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_getWritePosition(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", 0);

    size_t value = napiSequence->nativeParcel_->GetWritePosition();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_rewindWrite(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = {0};
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
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    bool result = napiSequence->nativeParcel_->RewindWrite(static_cast<size_t>(pos));
    if (!result) {
        ZLOGE(LOG_LABEL, "rewind write failed");
    }
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeNoException(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, 0, nullptr, &thisVar, nullptr);
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

napi_value NAPI_MessageSequence::JS_readException(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, 0, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t code = napiSequence->nativeParcel_->ReadInt32();
    if (code == 0) {
        return result;
    }
    std::u16string str = napiSequence->nativeParcel_->ReadString16();
    napi_throw_error(env, nullptr, Str16ToStr8(str).c_str());
    return result;
}

napi_value NAPI_MessageSequence::JS_checkReadArrayArgs(napi_env env,
                                                       napi_callback_info info,
                                                       size_t &argc,
                                                       napi_value &thisVar,
                                                       napi_value* argv)
{
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

napi_value NAPI_MessageSequence::JS_readByteArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    uint32_t maxBytesLen = 40960;
    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (arrayLength >= maxBytesLen) {
        ZLOGE(LOG_LABEL, "byte array length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    if (argc > 0) {
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < arrayLength; i++) {
            int8_t val = napiSequence->nativeParcel_->ReadInt8();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiSequence);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);
    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int8_t val = napiSequence->nativeParcel_->ReadInt8();
        napi_value num = nullptr;
        napi_create_int32(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readShortArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int16_t val = napiSequence->nativeParcel_->ReadInt16();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int16_t val = napiSequence->nativeParcel_->ReadInt16();
        napi_value num = nullptr;
        napi_create_int32(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readIntArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int32_t val = napiSequence->nativeParcel_->ReadInt32();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int32_t val = napiSequence->nativeParcel_->ReadInt32();
        napi_value num = nullptr;
        napi_create_int32(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readLongArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int64_t val = napiSequence->nativeParcel_->ReadInt64();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_64, napiSequence);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int64_t val = napiSequence->nativeParcel_->ReadInt64();
        napi_value num = nullptr;
        napi_create_int64(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readFloatArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            double val = napiSequence->nativeParcel_->ReadDouble();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiSequence);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        double val = napiSequence->nativeParcel_->ReadDouble();
        napi_value num = nullptr;
        napi_create_double(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readDoubleArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            double val = napiSequence->nativeParcel_->ReadDouble();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiSequence);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        double val = napiSequence->nativeParcel_->ReadDouble();
        napi_value num = nullptr;
        napi_create_double(env, val, &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readBooleanArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            int8_t val = napiSequence->nativeParcel_->ReadInt8();
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

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int8_t val = napiSequence->nativeParcel_->ReadInt8();
        napi_value boolean = nullptr;
        napi_get_boolean(env, val, &boolean);
        napi_set_element(env, result, i, boolean);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readCharArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            uint8_t val = napiSequence->nativeParcel_->ReadUint8();
            napi_value num = nullptr;
            napi_create_uint32(env, static_cast<uint32_t>(val), &num);
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    napi_value result = nullptr;
    napi_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        uint8_t val = napiSequence->nativeParcel_->ReadUint8();
        napi_value num = nullptr;
        napi_create_uint32(env, static_cast<uint32_t>(val), &num);
        napi_set_element(env, result, i, num);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readStringArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        napi_value argv[ARGV_INDEX_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            if (napiSequence->nativeParcel_->GetReadableBytes() <= 0) {
                break;
            }
            std::u16string parcelString = napiSequence->nativeParcel_->ReadString16();
            std::string outString = Str16ToStr8(parcelString.c_str());
            napi_value val = nullptr;
            napi_create_string_utf8(env, outString.c_str(), outString.length(), &val);
            napi_set_element(env, argv[ARGV_INDEX_0], i, val);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    napi_value result = nullptr;
    napi_create_array(env, &result);
    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        if (napiSequence->nativeParcel_->GetReadableBytes() <= 0) {
            break;
        }
        std::u16string parcelString = napiSequence->nativeParcel_->ReadString16();
        std::string outString = Str16ToStr8(parcelString.c_str());
        napi_value val = nullptr;
        napi_create_string_utf8(env, outString.c_str(), outString.length(), &val);
        napi_set_element(env, result, i, val);
    }
    return result;
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

napi_value NAPI_MessageSequence::JS_readParcelableArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value thisVar = nullptr;
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
    if (checkArgsResult == nullptr) {
        return checkArgsResult;
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    // checking here is not accurate, but we can defend some extreme attacking case.
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiSequence);

    uint32_t length = 0;
    napi_get_array_length(env, argv[ARGV_INDEX_0], &length);
    if (static_cast<int32_t>(length) != arrayLength) {
        ZLOGE(LOG_LABEL, "Bad length while reading Sequenceable array");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        int32_t len = napiSequence->nativeParcel_->ReadInt32();
        if (len > 0) {
            bool hasElement = false;
            napi_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
            if (!hasElement) {
                ZLOGE(LOG_LABEL, "parameter check error");
                return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
            }
            napi_value element = nullptr;
            napi_get_element(env, argv[ARGV_INDEX_0], i, &element);
            napi_value callJsFuncResult = JS_readParcelableArrayCallJsFunc(env, element, thisVar);
            if (callJsFuncResult == nullptr) {
                ZLOGE(LOG_LABEL, "call unmarshalling failed, element index: %{public}d", i);
                return callJsFuncResult;
            }
        }
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_readRemoteObjectArray(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argc = 0;
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) { // uses passed in array
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            return checkArgsResult;
        }
        uint32_t length = 0;
        napi_get_array_length(env, argv[ARGV_INDEX_0], &length);
        if (static_cast<int32_t>(length) != arrayLength) {
            ZLOGE(LOG_LABEL, "Bad length while reading RemoteObject array");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }
        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            sptr<IRemoteObject> value = napiSequence->nativeParcel_->ReadRemoteObject();
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
        sptr<IRemoteObject> value = napiSequence->nativeParcel_->ReadRemoteObject();
        napi_value napiValue = NAPI_ohos_rpc_CreateJsRemoteObject(env, value);
        napi_set_element(env, result, i, napiValue);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readParcelable(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t len = napiSequence->nativeParcel_->ReadInt32();
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

    return napiErr.ThrowError(env, errorDesc::CALL_JS_METHOD_ERROR);
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
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

napi_value NAPI_MessageSequence::JS_readRemoteObject(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    sptr<IRemoteObject> value = napiSequence->nativeParcel_->ReadRemoteObject();
    napi_value napiValue = NAPI_ohos_rpc_CreateJsRemoteObject(env, value);
    if (napiValue == nullptr) {
        ZLOGE(LOG_LABEL, "remote object is null");
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_writeInterfaceToken(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    if (argc != 1) {
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
    size_t maxSize = 40960;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], nullptr, 0, &bufferSize);
    if (bufferSize >= maxSize) {
        ZLOGE(LOG_LABEL, "string length too large");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[ARGV_INDEX_0], stringValue, bufferSize + 1, &jsStringLength);
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

    std::string parcelString = stringValue;
    bool writeResult = napiSequence->nativeParcel_->WriteInterfaceToken(to_utf16(parcelString));
    if (writeResult == false) {
        ZLOGE(LOG_LABEL, "write interface token failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageSequence::JS_readInterfaceToken(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    std::u16string parcelString = napiSequence->nativeParcel_->ReadInterfaceToken();
    std::string outString = Str16ToStr8(parcelString.c_str());
    napi_value napiValue = nullptr;
    napi_create_string_utf8(env, outString.c_str(), outString.length(), &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_CloseFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = { 0 };
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
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
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", 0);
    bool result = napiSequence->nativeParcel_->ContainFileDescriptors();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_WriteFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = { 0 };
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

napi_value NAPI_MessageSequence::JS_ReadFileDescriptor(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    int32_t result = napiSequence->nativeParcel_->ReadFileDescriptor();
    if (result == -1) {
        ZLOGE(LOG_LABEL, "read file descriptor failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    napi_value napiValue;
    napi_create_int32(env, result, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_WriteAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = { 0 };
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
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
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

napi_value NAPI_MessageSequence::JS_ReadAshmem(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    sptr<Ashmem> nativeAshmem = napiSequence->nativeParcel_->ReadAshmem();
    if (nativeAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "nativeAshmem is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
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
    napi_value jsAshmem;
    status = napi_new_instance(env, constructor, 0, nullptr, &jsAshmem);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "failed to  construct js Ashmem");
        return napiValue;
    }
    NAPIAshmem *napiAshmem = nullptr;
    napi_unwrap(env, jsAshmem, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    napiAshmem->SetAshmem(nativeAshmem);
    return jsAshmem;
}

napi_value NAPI_MessageSequence::JS_checkWriteRawDataArgs(napi_env env, size_t argc, napi_value* argv)
{
    size_t expectedArgc = 2;
    if (argc != expectedArgc) {
        ZLOGE(LOG_LABEL, "requires 2 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    bool isArray = false;
    napi_is_array(env, argv[ARGV_INDEX_0], &isArray);
    if (!isArray) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
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
napi_value NAPI_MessageSequence::JS_WriteRawData(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[ARGV_INDEX_2] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value checkArgsResult = JS_checkWriteRawDataArgs(env, argc, argv);
    if (checkArgsResult == nullptr) {
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
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGV_INDEX_0], i, &element);

        int32_t value = 0;
        napi_get_value_int32(env, element, &value);
        array.push_back(value);
    }

    int32_t size = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_1], &size);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    bool result = napiSequence->nativeParcel_->WriteRawData(array.data(), size * BYTE_SIZE_32);
    if (!result) {
        ZLOGE(LOG_LABEL, "write raw data failed");
        return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_ReadRawData(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_INDEX_1] = { 0 };
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
    int32_t arraySize = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &arraySize);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    const void *rawData = napiSequence->nativeParcel_->ReadRawData(arraySize * BYTE_SIZE_32);
    if (rawData == nullptr) {
        ZLOGE(LOG_LABEL, "rawData is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
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

napi_value NAPI_MessageSequence::JS_GetRawDataCapacity(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", 0);
    uint32_t result = napiSequence->nativeParcel_->GetRawDataCapacity();
    napi_value napiValue;
    napi_create_uint32(env, result, &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::Export(napi_env env, napi_value exports)
{
    const std::string className = "MessageSequence";
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
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), className.length(), JS_constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class MessageSequence failed");
    napi_status status = napi_set_named_property(env, exports, "MessageSequence", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property MessageSequence failed");
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
    napi_value argv[ARGV_INDEX_1] = { 0 };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi get callback info failed");
    MessageParcel *parcel = nullptr;
    if (argv[ARGV_INDEX_0] != nullptr) {
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

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
#include "hilog/log.h"
#include "log_tags.h"
#include "napi_remote_object.h"
#include "string_ex.h"

namespace OHOS {
using namespace OHOS::HiviewDFX;
constexpr size_t MAX_CAPACITY_TO_WRITE = 200 * 1024;
constexpr size_t BYTE_SIZE_32 = 4;
constexpr size_t BYTE_SIZE_64 = 8;

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "napi_messageParcel" };
#ifndef TITLE
#define TITLE __PRETTY_FUNCTION__
#endif
#define DBINDER_LOGE(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Error(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)
#define DBINDER_LOGI(fmt, args...) \
    (void)OHOS::HiviewDFX::HiLog::Info(LOG_LABEL, "%{public}s %{public}d: " fmt, TITLE, __LINE__, ##args)

#define CHECK_WRITE_CAPACITY(env, lenToWrite, napiParcel)                                          \
    size_t cap =  napiParcel->maxCapacityToWrite_ - napiParcel->nativeParcel_->GetWritePosition(); \
    if (cap < lenToWrite) {                                                                        \
        DBINDER_LOGI("No enough capacity to write");                                               \
        napi_throw_range_error(env, nullptr, "No enough capacity to write");                       \
    }

#define REWIND_IF_WRITE_CHECK_FAIL(env, lenToWrite, pos, napiParcel)                              \
    size_t cap = napiParcel->maxCapacityToWrite_ - napiParcel->nativeParcel_->GetWritePosition(); \
    if (cap < lenToWrite) {                                                                       \
        DBINDER_LOGI("No enough capacity to write");                                              \
        napiParcel->nativeParcel_->RewindWrite(pos);                                              \
        napi_throw_range_error(env, nullptr, "No enough capacity to write");                      \
    }

#define CHECK_READ_LENGTH(env, arrayLength, typeSize, napiParcel)                                                \
    size_t remainSize = napiParcel->nativeParcel_->GetDataSize() - napiParcel->nativeParcel_->GetReadPosition(); \
    if ((arrayLength < 0) || (arrayLength > remainSize) || ((arrayLength * typeSize) > remainSize)) {            \
        DBINDER_LOGI("No enough data to read");                                                                  \
        napi_throw_range_error(env, nullptr, "No enough data to read");                                          \
    }

NAPI_MessageParcel::NAPI_MessageParcel(napi_env env, napi_value thisVar, MessageParcel *parcel)
{
    DBINDER_LOGI("NAPI_MessageParcel::constructor");
    env_ = env;
    maxCapacityToWrite_ = MAX_CAPACITY_TO_WRITE;
    // do NOT reference js parcel here
    if (parcel == nullptr) {
        nativeParcel_ = std::shared_ptr<MessageParcel>(new MessageParcel());
        owner = true;
    } else {
        nativeParcel_ = std::shared_ptr<MessageParcel>(parcel, release);
        owner = false;
    }
}

NAPI_MessageParcel::~NAPI_MessageParcel()
{
    DBINDER_LOGI("NAPI_MessageParcel::Destructor");
    nativeParcel_ = nullptr;
    env_ = nullptr;
}

void NAPI_MessageParcel::release(MessageParcel *parcel)
{
    DBINDER_LOGI("message parcel is created by others, do nothing");
}

std::shared_ptr<MessageParcel> NAPI_MessageParcel::GetMessageParcel()
{
    return nativeParcel_;
}

napi_value NAPI_MessageParcel::JS_writeByte(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    int32_t value = 0;
    napi_get_value_int32(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    int32_t value = 0;
    napi_get_value_int32(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    int32_t value = 0;
    napi_get_value_int32(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    int64_t value = 0;
    napi_get_value_int64(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    double value = 0;
    napi_get_value_double(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    double value = 0;
    napi_get_value_double(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_boolean, "type mismatch for parameter 1");

    bool value = 0;
    napi_get_value_bool(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");

    size_t bufferSize = 0;
    size_t strLength = 0;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &bufferSize);
    DBINDER_LOGI("messageparcel writeChar bufferSize = %{public}d", (int)bufferSize);
    char buffer[bufferSize + 1];
    napi_get_value_string_utf8(env, argv[0], buffer, bufferSize + 1, &strLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32, napiParcel);
    std::string parcelString = buffer;
    auto value = reinterpret_cast<uint16_t *>(to_utf16(parcelString).data());
    bool result = napiParcel->nativeParcel_->WriteUint16(*value);

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeStringWithLength(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    size_t expectedArgc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == expectedArgc, "requires 2 parameter");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");

    napi_typeof(env, argv[1], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 2");

    uint32_t maxStrLen = 40960;
    uint32_t stringLength = 0;
    napi_get_value_uint32(env, argv[1], &stringLength);
    NAPI_ASSERT(env, stringLength < maxStrLen, "string length too large");

    char stringValue[stringLength + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, stringLength + 1, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == stringLength, "string length wrong");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * stringLength, napiParcel);
    std::string parcelString = stringValue;
    bool result = napiParcel->nativeParcel_->WriteString16(to_utf16(parcelString));

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeByteArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isTypedArray;
    napi_is_typedarray(env, argv[0], &isTypedArray);
    NAPI_ASSERT(env, isTypedArray == true, "type mismatch for parameter 1");

    napi_typedarray_type typedarrayType;
    size_t typedarrayLength = 0;
    void *typedarrayBufferPtr = nullptr;
    napi_value tmpArrayBuffer = nullptr;
    size_t byteOffset = 0;
    napi_get_typedarray_info(env, argv[0], &typedarrayType, &typedarrayLength, &typedarrayBufferPtr,
        &tmpArrayBuffer, &byteOffset);

    NAPI_ASSERT(env, typedarrayType == napi_int8_array, "array type mismatch for parameter 1");
    DBINDER_LOGI("messageparcel WriteBuffer typedarrayLength = %{public}d", (int)(typedarrayLength));

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    size_t len = (typedarrayLength / BYTE_SIZE_32) + (typedarrayLength % BYTE_SIZE_32 == 0 ? 0 : 1);
    DBINDER_LOGI("messageparcel WriteBuffer len = %{public}d", (int)(len));
    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32  * (len + 1), napiParcel);
    napiParcel->nativeParcel_->WriteUint32(typedarrayLength);
    bool result = napiParcel->nativeParcel_->WriteBuffer(typedarrayBufferPtr, typedarrayLength);
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeShortArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);

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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);

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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);
    DBINDER_LOGI("messageparcel WriteBuffer typedarrayLength = %{public}d", (int)(arrayLength));

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + BYTE_SIZE_64 * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);

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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + sizeof(double) * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);

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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 + sizeof(double) * arrayLength, napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);

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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);

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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    CHECK_WRITE_CAPACITY(env, BYTE_SIZE_32 * (arrayLength + 1), napiParcel);
    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);
        size_t bufferSize = 0;
        size_t strLength = 0;
        napi_get_value_string_utf8(env, element, nullptr, 0, &bufferSize);
        DBINDER_LOGI("messageparcel writeChar bufferSize = %{public}d", (int)bufferSize);
        char buffer[bufferSize + 1];
        napi_get_value_string_utf8(env, element, buffer, bufferSize + 1, &strLength);
        DBINDER_LOGI("messageparcel writeChar strLength = %{public}d", (int)strLength);

        std::string parcelString = buffer;
        auto value = reinterpret_cast<uint16_t *>(to_utf16(parcelString).data());
        result = napiParcel->nativeParcel_->WriteUint16(*value);
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
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 2 parameter");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter 1");

    size_t bufferSize = 0;
    size_t maxLen = 40960;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxLen, "string length too large");

    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, bufferSize + 1, &jsStringLength);
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
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        size_t maxSize = 40960;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);

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
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteInt32(1);
    napi_value propKey = nullptr;
    const char *propKeyStr = "marshalling";
    napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
    napi_value prop = nullptr;
    napi_get_property(env, argv[0], propKey, &prop);

    napi_value funcArg[1] = { thisVar };
    napi_value callResult = nullptr;
    napi_status status = napi_call_function(env, argv[0], prop, 1, funcArg, &callResult);
    bool result = (status == napi_ok);
    bool isExceptionPending = false;
    napi_is_exception_pending(env, &isExceptionPending);
    if (isExceptionPending) {
        napiParcel->nativeParcel_->RewindWrite(pos);
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeSequenceableArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool isArray;
    napi_is_array(env, argv[0], &isArray);
    NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

    uint32_t arrayLength = 0;
    napi_get_array_length(env, argv[0], &arrayLength);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    size_t pos = napiParcel->nativeParcel_->GetWritePosition();
    napiParcel->nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[0], i, &hasElement);
        NAPI_ASSERT(env, hasElement == true, "parameter check error");

        napi_value element = nullptr;
        napi_get_element(env, argv[0], i, &element);

        napi_value propKey = nullptr;
        const char *propKeyStr = "marshalling";
        napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
        napi_value prop = nullptr;
        napi_get_property(env, element, propKey, &prop);

        napi_value funcArg[1] = { thisVar };
        napi_value callResult = nullptr;
        napi_status status = napi_call_function(env, element, prop, 1, funcArg, &callResult);
        result = (status == napi_ok);

        bool isExceptionPending = false;
        napi_is_exception_pending(env, &isExceptionPending);
        if (!result || isExceptionPending) {
            napiParcel->nativeParcel_->RewindWrite(pos);
            break;
        }
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readByte(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

    uint16_t value = napiParcel->nativeParcel_->ReadUint16();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readString(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

    std::u16string parcelString = napiParcel->nativeParcel_->ReadString16();
    std::string outString = Str16ToStr8(parcelString.c_str());
    napi_value napiValue = nullptr;
    napi_create_string_utf8(env, outString.c_str(), outString.length(), &napiValue);
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_getSize(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

    size_t value = napiParcel->nativeParcel_->GetDataCapacity();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_setSize(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t value = 0;
    napi_get_value_uint32(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->SetDataSize(static_cast<size_t>(value));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_setCapacity(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t value = 0;
    napi_get_value_uint32(env, argv[0], &value);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

    size_t value = napiParcel->nativeParcel_->GetReadPosition();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_rewindRead(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t pos = 0;
    napi_get_value_uint32(env, argv[0], &pos);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

    size_t value = napiParcel->nativeParcel_->GetWritePosition();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_rewindWrite(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "type mismatch for parameter 1");

    uint32_t pos = 0;
    napi_get_value_uint32(env, argv[0], &pos);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    bool result = napiParcel->nativeParcel_->RewindWrite(static_cast<size_t>(pos));
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readByteArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    uint32_t maxBytesLen = 40960;
    uint32_t arrayBufferLength = napiParcel->nativeParcel_->ReadUint32();
    NAPI_ASSERT(env, arrayBufferLength < maxBytesLen, "byte array length too large");
    size_t len = (arrayBufferLength / BYTE_SIZE_32) + (arrayBufferLength % BYTE_SIZE_32 == 0 ? 0 : 1);
    DBINDER_LOGI("messageparcel WriteBuffer typedarrayLength = %{public}d", (int)(len));

    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, len, BYTE_SIZE_32, napiParcel);
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isTypedArray;
        napi_is_typedarray(env, argv[0], &isTypedArray);
        NAPI_ASSERT(env, isTypedArray == true, "type mismatch for parameter 1");

        napi_typedarray_type arrayType;
        size_t arrayLength = 0;
        void *arrayBufferPtr = nullptr;
        napi_value tmpArrayBuffer = nullptr;
        size_t byteOffset = 0;
        napi_get_typedarray_info(env, argv[0], &arrayType, &arrayLength, &arrayBufferPtr,
            &tmpArrayBuffer, &byteOffset);
        NAPI_ASSERT(env, arrayType == napi_int8_array, "array type mismatch for parameter 1");
        NAPI_ASSERT(env, arrayLength == arrayBufferLength, "array size mismatch for length");

        const uint8_t *arrayAddr = napiParcel->nativeParcel_->ReadUnpadBuffer(arrayBufferLength);
        NAPI_ASSERT(env, arrayAddr != nullptr, "buffer is nullptr");
        errno_t status = memcpy_s(arrayBufferPtr, arrayBufferLength, arrayAddr, arrayBufferLength);
        NAPI_ASSERT(env, status == EOK, "memcpy_s is failed");

        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    CHECK_READ_LENGTH(env, len, BYTE_SIZE_32, napiParcel);
    napi_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    napi_create_arraybuffer(env, arrayBufferLength, &arrayBufferPtr, &arrayBuffer);
    napi_value typedarray = nullptr;
    napi_create_typedarray(env, napi_int8_array, arrayBufferLength, arrayBuffer, 0, &typedarray);
    if (arrayBufferLength == 0) {
        return typedarray;
    }

    const uint8_t *arrayAddr = napiParcel->nativeParcel_->ReadUnpadBuffer(arrayBufferLength);
    NAPI_ASSERT(env, arrayAddr != nullptr, "buffer is nullptr");
    errno_t status = memcpy_s(arrayBufferPtr, arrayBufferLength, arrayAddr, arrayBufferLength);
    NAPI_ASSERT(env, status == EOK, "memcpy_s is failed");
    return typedarray;
}

napi_value NAPI_MessageParcel::JS_readShortArray(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray;
        napi_is_array(env, argv[0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (int32_t i = 0; i < arrayLength; i++) {
            int16_t val = napiParcel->nativeParcel_->ReadInt16();
            napi_value num = nullptr;
            napi_create_int32(env, val, &num);
            napi_set_element(env, argv[0], i, num);
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
    napi_value result = nullptr;
    napi_create_array_with_length(env, arrayLength, &result);

    for (int32_t i = 0; i < arrayLength; i++) {
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray;
        napi_is_array(env, argv[0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (int32_t i = 0; i < arrayLength; i++) {
            int32_t val = napiParcel->nativeParcel_->ReadInt32();
            napi_value num = nullptr;
            napi_create_int32(env, val, &num);
            napi_set_element(env, argv[0], i, num);
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
    napi_value result = nullptr;
    napi_create_array_with_length(env, arrayLength, &result);

    for (int32_t i = 0; i < arrayLength; i++) {
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_64, napiParcel)
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray;
        napi_is_array(env, argv[0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (int32_t i = 0; i < arrayLength; i++) {
            int64_t val = napiParcel->nativeParcel_->ReadInt64();
            napi_value num = nullptr;
            napi_create_int64(env, val, &num);
            napi_set_element(env, argv[0], i, num);
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_64, napiParcel)
    napi_value result = nullptr;
    napi_create_array_with_length(env, arrayLength, &result);

    for (int32_t i = 0; i < arrayLength; i++) {
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel)
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray;
        napi_is_array(env, argv[0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (int32_t i = 0; i < arrayLength; i++) {
            double val = napiParcel->nativeParcel_->ReadDouble();
            napi_value num = nullptr;
            napi_create_double(env, val, &num);
            napi_set_element(env, argv[0], i, num);
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel)
    napi_value result = nullptr;
    napi_create_array_with_length(env, arrayLength, &result);

    for (int32_t i = 0; i < arrayLength; i++) {
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel)
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray;
        napi_is_array(env, argv[0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (int32_t i = 0; i < arrayLength; i++) {
            double val = napiParcel->nativeParcel_->ReadDouble();
            napi_value num = nullptr;
            napi_create_double(env, val, &num);
            napi_set_element(env, argv[0], i, num);
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiParcel)
    napi_value result = nullptr;
    napi_create_array_with_length(env, arrayLength, &result);

    for (int32_t i = 0; i < arrayLength; i++) {
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray;
        napi_is_array(env, argv[0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (int32_t i = 0; i < arrayLength; i++) {
            int8_t val = napiParcel->nativeParcel_->ReadInt8();
            napi_value boolean = nullptr;
            napi_get_boolean(env, val, &boolean);
            napi_set_element(env, argv[0], i, boolean);
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

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
    napi_value result = nullptr;
    napi_create_array_with_length(env, arrayLength, &result);

    for (int32_t i = 0; i < arrayLength; i++) {
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray;
        napi_is_array(env, argv[0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (int32_t i = 0; i < arrayLength; i++) {
            uint16_t val = napiParcel->nativeParcel_->ReadUint16();
            napi_value num = nullptr;
            napi_create_uint32(env, val, &num);
            napi_set_element(env, argv[0], i, num);
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
    napi_value result = nullptr;
    napi_create_array_with_length(env, arrayLength, &result);

    for (int32_t i = 0; i < arrayLength; i++) {
        uint16_t val = napiParcel->nativeParcel_->ReadUint16();
        napi_value num = nullptr;
        napi_create_uint32(env, val, &num);
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
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    int32_t arrayLength = napiParcel->nativeParcel_->ReadInt32();
    if (argc > 0) {
        NAPI_ASSERT(env, argc == 1, "type mismatch for parameter 1");
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
        napi_value argv[1] = {0};
        void *data = nullptr;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

        bool isArray;
        napi_is_array(env, argv[0], &isArray);
        NAPI_ASSERT(env, isArray == true, "type mismatch for parameter 1");

        for (int32_t i = 0; i < arrayLength; i++) {
            if (napiParcel->nativeParcel_->GetReadableBytes() <= 0) {
                break;
            }
            std::u16string parcelString = napiParcel->nativeParcel_->ReadString16();
            std::string outString = Str16ToStr8(parcelString.c_str());
            napi_value val = nullptr;
            napi_create_string_utf8(env, outString.c_str(), outString.length(), &val);
            napi_set_element(env, argv[0], i, val);
        }
        napi_value napiValue = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, true, &napiValue));
        return napiValue;
    }

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiParcel)
    napi_value result = nullptr;
    napi_create_array(env, &result);
    for (int32_t i = 0; i < arrayLength; i++) {
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

napi_value NAPI_MessageParcel::JS_readSequenceable(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

    int32_t len = napiParcel->nativeParcel_->ReadInt32();
    bool result = false;
    if (len > 0) {
        napi_value propKey = nullptr;
        const char *propKeyStr = "unmarshalling";
        napi_create_string_utf8(env, propKeyStr, strlen(propKeyStr), &propKey);
        napi_value prop = nullptr;
        napi_get_property(env, argv[0], propKey, &prop);

        napi_value funcArg[1] = {thisVar};
        napi_value callResult = nullptr;
        napi_status status = napi_call_function(env, argv[0], prop, 1, funcArg, &callResult);
        result = (status == napi_ok);
    }

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
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
    napi_remove_wrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    delete napiParcel;

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NAPI_MessageParcel::JS_writeRemoteObject(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_value napiValue = nullptr;
    sptr<IRemoteObject> remoteObject = NAPI_ohos_rpc_getNativeRemoteObject(env, argv[0]);
    if (remoteObject == nullptr) {
        NAPI_CALL(env, napi_get_boolean(env, false, &napiValue));
        return napiValue;
    }
    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");
    bool result = napiParcel->nativeParcel_->WriteRemoteObject(remoteObject);
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readRemoteObject(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

    sptr<IRemoteObject> value = napiParcel->nativeParcel_->ReadRemoteObject();
    napi_value napiValue = NAPI_ohos_rpc_CreateJsRemoteObject(env, value);
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_writeInterfaceToken(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "type mismatch for parameter");

    size_t bufferSize = 0;
    size_t maxSize = 40960;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &bufferSize);
    NAPI_ASSERT(env, bufferSize < maxSize, "string length too large");

    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, bufferSize + 1, &jsStringLength);
    NAPI_ASSERT(env, jsStringLength == bufferSize, "string length wrong");

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT(env, napiParcel != nullptr, "napiParcel is null");

    std::string parcelString = stringValue;
    bool result = napiParcel->nativeParcel_->WriteInterfaceToken(to_utf16(parcelString));

    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, result, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageParcel::JS_readInterfaceToken(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageParcel *napiParcel = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiParcel);
    NAPI_ASSERT_BASE(env, napiParcel != nullptr, "napiParcel is null", 0);

    std::u16string parcelString = napiParcel->nativeParcel_->ReadInterfaceToken();
    std::string outString = Str16ToStr8(parcelString.c_str());
    napi_value napiValue = nullptr;
    napi_create_string_utf8(env, outString.c_str(), outString.length(), &napiValue);
    return napiValue;
}

napi_value NAPI_MessageParcel::Export(napi_env env, napi_value exports)
{
    const std::string className = "MessageParcel";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("create", NAPI_MessageParcel::JS_create),
        DECLARE_NAPI_FUNCTION("reclaim", NAPI_MessageParcel::JS_reclaim),
        DECLARE_NAPI_FUNCTION("writeByte", NAPI_MessageParcel::JS_writeByte),
        DECLARE_NAPI_FUNCTION("writeShort", NAPI_MessageParcel::JS_writeShort),
        DECLARE_NAPI_FUNCTION("writeInt", NAPI_MessageParcel::JS_writeInt),
        DECLARE_NAPI_FUNCTION("writeLong", NAPI_MessageParcel::JS_writeLong),
        DECLARE_NAPI_FUNCTION("writeFloat", NAPI_MessageParcel::JS_writeFloat),
        DECLARE_NAPI_FUNCTION("writeDouble", NAPI_MessageParcel::JS_writeDouble),
        DECLARE_NAPI_FUNCTION("writeBoolean", NAPI_MessageParcel::JS_writeBoolean),
        DECLARE_NAPI_FUNCTION("writeChar", NAPI_MessageParcel::JS_writeChar),
        DECLARE_NAPI_FUNCTION("writeStringWithLength", NAPI_MessageParcel::JS_writeStringWithLength),
        DECLARE_NAPI_FUNCTION("writeString", NAPI_MessageParcel::JS_writeString),
        DECLARE_NAPI_FUNCTION("writeByteArray", NAPI_MessageParcel::JS_writeByteArray),
        DECLARE_NAPI_FUNCTION("readByte", NAPI_MessageParcel::JS_readByte),
        DECLARE_NAPI_FUNCTION("readShort", NAPI_MessageParcel::JS_readShort),
        DECLARE_NAPI_FUNCTION("readInt", NAPI_MessageParcel::JS_readInt),
        DECLARE_NAPI_FUNCTION("readLong", NAPI_MessageParcel::JS_readLong),
        DECLARE_NAPI_FUNCTION("readFloat", NAPI_MessageParcel::JS_readFloat),
        DECLARE_NAPI_FUNCTION("readDouble", NAPI_MessageParcel::JS_readDouble),
        DECLARE_NAPI_FUNCTION("readBoolean", NAPI_MessageParcel::JS_readBoolean),
        DECLARE_NAPI_FUNCTION("readChar", NAPI_MessageParcel::JS_readChar),
        DECLARE_NAPI_FUNCTION("readString", NAPI_MessageParcel::JS_readString),
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
        DECLARE_NAPI_FUNCTION("rewindWrite", NAPI_MessageParcel::JS_rewindWrite),
        DECLARE_NAPI_FUNCTION("rewindRead", NAPI_MessageParcel::JS_rewindRead),
        DECLARE_NAPI_FUNCTION("writeSequenceable", NAPI_MessageParcel::JS_writeSequenceable),
        DECLARE_NAPI_FUNCTION("writeShortArray", NAPI_MessageParcel::JS_writeShortArray),
        DECLARE_NAPI_FUNCTION("writeIntArray", NAPI_MessageParcel::JS_writeIntArray),
        DECLARE_NAPI_FUNCTION("writeLongArray", NAPI_MessageParcel::JS_writeLongArray),
        DECLARE_NAPI_FUNCTION("writeFloatArray", NAPI_MessageParcel::JS_writeFloatArray),
        DECLARE_NAPI_FUNCTION("writeDoubleArray", NAPI_MessageParcel::JS_writeDoubleArray),
        DECLARE_NAPI_FUNCTION("writeBooleanArray", NAPI_MessageParcel::JS_writeBooleanArray),
        DECLARE_NAPI_FUNCTION("writeCharArray", NAPI_MessageParcel::JS_writeCharArray),
        DECLARE_NAPI_FUNCTION("writeStringArray", NAPI_MessageParcel::JS_writeStringArray),
        DECLARE_NAPI_FUNCTION("writeSequenceableArray", NAPI_MessageParcel::JS_writeSequenceableArray),
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
    napi_value argv[1] = { 0 };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi get callback info failed");
    MessageParcel *parcel = nullptr;
    if (argv[0] != nullptr) {
        int64_t tmp = 0;
        napi_get_value_int64(env, argv[0], &tmp);
        parcel = reinterpret_cast<MessageParcel *>(tmp);
        NAPI_ASSERT(env, parcel != nullptr, "parcel is null");
    }
    // new native parcel object
    auto messageParcel = new NAPI_MessageParcel(env, thisVar, parcel);
    // connect native object to js thisVar
    status = napi_wrap(
        env, thisVar, messageParcel,
        [](napi_env env, void *data, void *hint) {
        },
        nullptr, nullptr);
    NAPI_ASSERT(env, status == napi_ok, "napi wrap message parcel failed");
    return thisVar;
}
} // namespace OHOS

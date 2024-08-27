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
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "NAPI_MessageSequenceRead" };

napi_value NAPI_MessageSequence::JS_getSize(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

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
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetDataCapacity();
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
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

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
    NAPI_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetReadPosition();
    napi_value napiValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, value, &napiValue));
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_rewindRead(napi_env env, napi_callback_info info)
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
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    bool result = napiSequence->nativeParcel_->RewindRead(static_cast<size_t>(pos));
    NAPI_ASSERT(env, result == true, "rewind read failed");
    napi_value napiValue = nullptr;
    napi_get_undefined(env, &napiValue);
    return napiValue;
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
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LOG_LABEL, "remote object is null time:%{public}" PRIu64, curTime);
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    return napiValue;
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
    napi_value napiValue = nullptr;
    napi_create_string_utf16(env, parcelString.c_str(), parcelString.length(), &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readException(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
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
    // This function implementation is the same as JS_readFloat
    return NAPI_MessageSequence::JS_readFloat(env, info);
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
    napi_value napiValue = nullptr;
    napi_create_string_utf16(env, parcelString.c_str(), parcelString.length(), &napiValue);
    return napiValue;
}

napi_value NAPI_MessageSequence::JS_readParcelable(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = {0};
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
    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();

    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiSequence);
        napi_value argv[ARGV_LENGTH_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
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

    if (arrayLength == 0) {
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
        napi_value argv[ARGV_LENGTH_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
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
        napi_value argv[ARGV_LENGTH_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
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
        napi_value argv[ARGV_LENGTH_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
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
        napi_value argv[ARGV_LENGTH_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
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
    // This function implementation is the same as JS_readFloatArray
    return NAPI_MessageSequence::JS_readFloatArray(env, info);
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
        napi_value argv[ARGV_LENGTH_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
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
        napi_value argv[ARGV_LENGTH_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
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

    if (arrayLength == 0) {
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
        napi_value argv[ARGV_LENGTH_1] = {0};
        napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            if (napiSequence->nativeParcel_->GetReadableBytes() <= 0) {
                break;
            }
            std::u16string parcelString = napiSequence->nativeParcel_->ReadString16();
            napi_value val = nullptr;
            napi_create_string_utf16(env, parcelString.c_str(), parcelString.length(), &val);
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
        napi_value val = nullptr;
        napi_create_string_utf16(env, parcelString.c_str(), parcelString.length(), &val);
        napi_set_element(env, result, i, val);
    }
    return result;
}

napi_value NAPI_MessageSequence::JS_readParcelableArray(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value thisVar = nullptr;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
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
                ZLOGE(LOG_LABEL, "call unmarshalling failed, element index:%{public}d", i);
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
    napi_value argv[ARGV_LENGTH_1] = {0};
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
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
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

napi_value NAPI_MessageSequence::JS_ReadRawData(napi_env env, napi_callback_info info)
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
    int32_t arraySize = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &arraySize);
    napi_value result = nullptr;
    if (arraySize <= 0) {
        ZLOGE(LOG_LABEL, "arraySize is %{public}d, error", arraySize);
        napi_create_array(env, &result);
        return result;
    }
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
    napi_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    size_t bufferSize = static_cast<size_t>(arraySize) * BYTE_SIZE_32;

    napi_status isCreateBufferOk = napi_create_arraybuffer(env, bufferSize, &arrayBufferPtr, &arrayBuffer);
    if (isCreateBufferOk != napi_ok) {
        ZLOGE(LOG_LABEL, "JS_ReadRawData create arrayBuffer failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    napi_status isCreateArrayOk =
        napi_create_typedarray(env, napi_int32_array, arraySize, arrayBuffer, 0, &result);
    if (isCreateArrayOk != napi_ok) {
        ZLOGE(LOG_LABEL, "JS_ReadRawData create Typedarray failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    errno_t status = memcpy_s(arrayBufferPtr, bufferSize, rawData, bufferSize);
    NAPI_ASSERT(env, status == EOK, "JS_ReadRawData memcpy_s is failed");
    return result;
}

napi_value NAPI_MessageSequence::JS_ReadRawDataBuffer(napi_env env, napi_callback_info info)
{
    size_t argc = ARGV_LENGTH_1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGV_LENGTH_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int64_t arraySize = 0;
    napi_get_value_int64(env, argv[ARGV_INDEX_0], &arraySize);
    napi_value result = nullptr;
    if (arraySize <= 0) {
        ZLOGE(LOG_LABEL, "arraySize is %{public}" PRId64 ", error", arraySize);
        napi_create_array(env, &result);
        return result;
    }
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    const void *rawData = napiSequence->nativeParcel_->ReadRawData(arraySize);
    if (rawData == nullptr) {
        ZLOGE(LOG_LABEL, "rawData is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    napi_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    size_t bufferSize = static_cast<size_t>(arraySize);
    napi_status isCreateBufferOk = napi_create_arraybuffer(env, bufferSize, &arrayBufferPtr, &arrayBuffer);
    if (isCreateBufferOk != napi_ok) {
        ZLOGE(LOG_LABEL, "JS_ReadRawData create arrayBuffer failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    errno_t status = memcpy_s(arrayBufferPtr, bufferSize, rawData, bufferSize);
    NAPI_ASSERT(env, status == EOK, "JS_ReadRawDataBuffer memcpy_s fail");
    return arrayBuffer;
}

template<typename T>
napi_value NAPI_MessageSequence::JS_CopyVectorToBuffer(napi_env env, std::vector<T> vector, size_t bufferSize)
{
    napi_value arrayBuffer = nullptr;
    void* arrayBufferPtr = nullptr;

    napi_status createStatus = napi_create_arraybuffer(env, bufferSize, &arrayBufferPtr, &arrayBuffer);
    if (createStatus != napi_ok) {
        ZLOGE(LOG_LABEL, "create arrayBuffer failed. status:%{public}d", createStatus);
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    errno_t status = memcpy_s(arrayBufferPtr, bufferSize, vector.data(), bufferSize);
    NAPI_ASSERT(env, status == EOK, "memcpy_s is failed");

    return arrayBuffer;
}

napi_value NAPI_MessageSequence::JS_readArrayBuffer(napi_env env, napi_callback_info info)
{
    size_t argc = ARGV_LENGTH_1;
    napi_value argv[ARGV_LENGTH_1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    napi_valuetype valueType = napi_null;
    napi_status status = napi_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != napi_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1, not number. status:%{public}d", status);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    NAPI_MessageSequence *napiSequence = nullptr;
    napi_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t typeCode = 0;
    napi_get_value_int32(env, argv[ARGV_INDEX_0], &typeCode);
    if (typeCode < INT8_ARRAY || typeCode > BIGUINT64_ARRAY) {
        ZLOGE(LOG_LABEL, "the value of parameter 1 is out of range. typeCode:%{public}d", typeCode);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    return JS_readVectorByTypeCode(env, typeCode, napiSequence);
}

napi_value NAPI_MessageSequence::JS_readVectorByTypeCode(napi_env env,
                                                         int32_t typeCode,
                                                         NAPI_MessageSequence *napiSequence)
{
    switch (typeCode) {
        case INT8_ARRAY: {
            return JS_readInt8ArrayBuffer(env, napiSequence);
        }
        case UINT8_ARRAY: {
            return JS_readUInt8ArrayBuffer(env, napiSequence);
        }
        case INT16_ARRAY: {
            return JS_readInt16ArrayBuffer(env, napiSequence);
        }
        case UINT16_ARRAY: {
            return JS_readUInt16ArrayBuffer(env, napiSequence);
        }
        case INT32_ARRAY: {
            return JS_readInt32ArrayBuffer(env, napiSequence);
        }
        case UINT32_ARRAY: {
            return JS_readUInt32ArrayBuffer(env, napiSequence);
        }
        case FLOAT32_ARRAY: {
            return JS_readFloatArrayBuffer(env, napiSequence);
        }
        case FLOAT64_ARRAY: {
            return JS_readDoubleArrayBuffer(env, napiSequence);
        }
        case BIGINT64_ARRAY: {
            return JS_readInt64ArrayBuffer(env, napiSequence);
        }
        case BIGUINT64_ARRAY: {
            return JS_readUInt64ArrayBuffer(env, napiSequence);
        }
        default:
            ZLOGE(LOG_LABEL, "unsupported typeCode:%{public}d", typeCode);
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
}

napi_value NAPI_MessageSequence::JS_readInt8ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<int8_t> int8Vector;
    if (!napiSequence->nativeParcel_->ReadInt8Vector(&int8Vector)) {
        ZLOGE(LOG_LABEL, "read Int8Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = int8Vector.size();
    return JS_CopyVectorToBuffer(env, int8Vector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readUInt8ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<uint8_t> uint8Vector;
    if (!napiSequence->nativeParcel_->ReadUInt8Vector(&uint8Vector)) {
        ZLOGE(LOG_LABEL, "read UInt8Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = uint8Vector.size();
    return JS_CopyVectorToBuffer(env, uint8Vector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readInt16ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<int16_t> int16Vector;
    if (!napiSequence->nativeParcel_->ReadInt16Vector(&int16Vector)) {
        ZLOGE(LOG_LABEL, "read Int16Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = int16Vector.size() * BYTE_SIZE_16;
    return JS_CopyVectorToBuffer(env, int16Vector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readUInt16ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<uint16_t> uint16Vector;
    if (!napiSequence->nativeParcel_->ReadUInt16Vector(&uint16Vector)) {
        ZLOGE(LOG_LABEL, "read UInt16Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = uint16Vector.size() * BYTE_SIZE_16;
    return JS_CopyVectorToBuffer(env, uint16Vector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readInt32ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<int32_t> int32Vector;
    if (!napiSequence->nativeParcel_->ReadInt32Vector(&int32Vector)) {
        ZLOGE(LOG_LABEL, "read Int32Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = int32Vector.size() * BYTE_SIZE_32;
    return JS_CopyVectorToBuffer(env, int32Vector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readUInt32ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<uint32_t> uint32Vector;
    if (!napiSequence->nativeParcel_->ReadUInt32Vector(&uint32Vector)) {
        ZLOGE(LOG_LABEL, "read UInt32Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = uint32Vector.size() * BYTE_SIZE_32;
    return JS_CopyVectorToBuffer(env, uint32Vector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readFloatArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<float> floatVector;
    if (!napiSequence->nativeParcel_->ReadFloatVector(&floatVector)) {
        ZLOGE(LOG_LABEL, "read FloatVector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = floatVector.size() * BYTE_SIZE_32;
    return JS_CopyVectorToBuffer(env, floatVector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readDoubleArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<double> doubleVector;
    if (!napiSequence->nativeParcel_->ReadDoubleVector(&doubleVector)) {
        ZLOGE(LOG_LABEL, "read DoubleVector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = doubleVector.size() * BYTE_SIZE_64;
    return JS_CopyVectorToBuffer(env, doubleVector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readInt64ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<int64_t> int64Vector;
    if (!napiSequence->nativeParcel_->ReadInt64Vector(&int64Vector)) {
        ZLOGE(LOG_LABEL, "read Int64Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = int64Vector.size() * BYTE_SIZE_64;
    return JS_CopyVectorToBuffer(env, int64Vector, bufferSize);
}

napi_value NAPI_MessageSequence::JS_readUInt64ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence)
{
    std::vector<uint64_t> uint64vector;
    if (!napiSequence->nativeParcel_->ReadUInt64Vector(&uint64vector)) {
        ZLOGE(LOG_LABEL, "read UInt64Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = uint64vector.size() * BYTE_SIZE_64;
    return JS_CopyVectorToBuffer(env, uint64vector, bufferSize);
}
} // namespace OHOS
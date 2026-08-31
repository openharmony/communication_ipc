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
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "ani_MessageSequenceRead" };

ani_value ani_MessageSequence::JS_getSize(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    ani_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetDataSize();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_getCapacity(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    ani_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetDataCapacity();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_getReadableBytes(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    ani_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetReadableBytes();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, static_cast<uint32_t>(value), &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_getReadPosition(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    ani_ASSERT_BASE(env, napiSequence != nullptr, "napiSequence is null", nullptr);

    size_t value = napiSequence->nativeParcel_->GetReadPosition();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_uint32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_rewindRead(ani_env env, ani_callback_info info)
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
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    bool result = napiSequence->nativeParcel_->RewindRead(static_cast<size_t>(pos));
    ani_ASSERT(env, result == true, "rewind read failed");
    ani_value napiValue = nullptr;
    ani_get_undefined(env, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_readRemoteObject(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    sptr<IRemoteObject> value = napiSequence->nativeParcel_->ReadRemoteObject();
    ani_value napiValue = ani_ohos_rpc_CreateJsRemoteObject(env, value);
    if (napiValue == nullptr) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LOG_LABEL, "remote object is null time:%{public}" PRIu64, curTime);
        return napiErr.ThrowError(env, errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR);
    }
    return napiValue;
}

ani_value ani_MessageSequence::JS_readInterfaceToken(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    std::u16string parcelString = napiSequence->nativeParcel_->ReadInterfaceToken();
    ani_value napiValue = nullptr;
    ani_status status = ani_create_string_utf16(env, parcelString.c_str(), parcelString.length(), &napiValue);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "create string failed");
        return napiValue;
    }
    return napiValue;
}

ani_value ani_MessageSequence::JS_readException(ani_env env, ani_callback_info info)
{
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t code = napiSequence->nativeParcel_->ReadInt32();
    if (code == 0) {
        return result;
    }
    std::u16string str = napiSequence->nativeParcel_->ReadString16();
    ani_throw_error(env, nullptr, Str16ToStr8(str).c_str());
    return result;
}

ani_value ani_MessageSequence::JS_readByte(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int8_t value = napiSequence->nativeParcel_->ReadInt8();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_int32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_readShort(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int16_t value = napiSequence->nativeParcel_->ReadInt16();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_int32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_readInt(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGD(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t value = napiSequence->nativeParcel_->ReadInt32();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_int32(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_readLong(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int64_t value = napiSequence->nativeParcel_->ReadInt64();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_int64(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_readFloat(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    double value = napiSequence->nativeParcel_->ReadDouble();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_create_double(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_readDouble(ani_env env, ani_callback_info info)
{
    // This function implementation is the same as JS_readFloat
    return ani_MessageSequence::JS_readFloat(env, info);
}

ani_value ani_MessageSequence::JS_readBoolean(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int8_t value = napiSequence->nativeParcel_->ReadInt8();
    ani_value napiValue = nullptr;
    ani_CALL(env, ani_get_boolean(env, value, &napiValue));
    return napiValue;
}

ani_value ani_MessageSequence::JS_readChar(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint8_t value = napiSequence->nativeParcel_->ReadUint8();
    ani_value result = nullptr;
    ani_create_uint32(env, static_cast<uint32_t>(value), &result);
    return result;
}

ani_value ani_MessageSequence::JS_readString(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    std::u16string parcelString = napiSequence->nativeParcel_->ReadString16();
    ani_value napiValue = nullptr;
    ani_status status = ani_create_string_utf16(env, parcelString.c_str(), parcelString.length(), &napiValue);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "create string failed");
        return napiValue;
    }
    return napiValue;
}

ani_value ani_MessageSequence::JS_readParcelable(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t len = napiSequence->nativeParcel_->ReadInt32();
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

    return napiErr.ThrowError(env, errorDesc::CALL_JS_METHOD_ERROR);
}

ani_value ani_MessageSequence::JS_readByteArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();

    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiSequence);
        ani_value argv[ARGV_LENGTH_1] = {0};
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < arrayLength; i++) {
            int8_t val = napiSequence->nativeParcel_->ReadInt8();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiSequence);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);
    for (uint32_t i = 0; i < arrayLength; i++) {
        int8_t val = napiSequence->nativeParcel_->ReadInt8();
        ani_value num = nullptr;
        ani_create_int32(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageSequence::JS_readShortArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        ani_value argv[ARGV_LENGTH_1] = {0};
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < arrayLength; i++) {
            int16_t val = napiSequence->nativeParcel_->ReadInt16();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < arrayLength; i++) {
        int16_t val = napiSequence->nativeParcel_->ReadInt16();
        ani_value num = nullptr;
        ani_create_int32(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageSequence::JS_readIntArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        ani_value argv[ARGV_LENGTH_1] = {0};
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < arrayLength; i++) {
            int32_t val = napiSequence->nativeParcel_->ReadInt32();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < arrayLength; i++) {
        int32_t val = napiSequence->nativeParcel_->ReadInt32();
        ani_value num = nullptr;
        ani_create_int32(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageSequence::JS_readLongArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        ani_value argv[ARGV_LENGTH_1] = {0};
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < arrayLength; i++) {
            int64_t val = napiSequence->nativeParcel_->ReadInt64();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_64, napiSequence);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < arrayLength; i++) {
        int64_t val = napiSequence->nativeParcel_->ReadInt64();
        ani_value num = nullptr;
        ani_create_int64(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageSequence::JS_readFloatArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        ani_value argv[ARGV_LENGTH_1] = {0};
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < arrayLength; i++) {
            double val = napiSequence->nativeParcel_->ReadDouble();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, sizeof(double), napiSequence);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < arrayLength; i++) {
        double val = napiSequence->nativeParcel_->ReadDouble();
        ani_value num = nullptr;
        ani_create_double(env, val, &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

ani_value ani_MessageSequence::JS_readDoubleArray(ani_env env, ani_callback_info info)
{
    // This function implementation is the same as JS_readFloatArray
    return ani_MessageSequence::JS_readFloatArray(env, info);
}


ani_value ani_MessageSequence::JS_readBooleanArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        ani_value argv[ARGV_LENGTH_1] = {0};
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < arrayLength; i++) {
            int8_t val = napiSequence->nativeParcel_->ReadInt8();
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

    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < arrayLength; i++) {
        int8_t val = napiSequence->nativeParcel_->ReadInt8();
        ani_value boolean = nullptr;
        ani_get_boolean(env, val, &boolean);
        ani_set_element(env, result, i, boolean);
    }
    return result;
}


ani_value ani_MessageSequence::JS_readCharArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        ani_value argv[ARGV_LENGTH_1] = {0};
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }

        for (uint32_t i = 0; i < arrayLength; i++) {
            uint8_t val = napiSequence->nativeParcel_->ReadUint8();
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
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    ani_value result = nullptr;
    ani_create_array_with_length(env, (size_t)arrayLength, &result);

    for (uint32_t i = 0; i < arrayLength; i++) {
        uint8_t val = napiSequence->nativeParcel_->ReadUint8();
        ani_value num = nullptr;
        ani_create_uint32(env, static_cast<uint32_t>(val), &num);
        ani_set_element(env, result, i, num);
    }
    return result;
}

bool ani_MessageSequence::ReadAndSetStringToArray(ani_env env, ani_MessageSequence* napiSequence,
    ani_value array, uint32_t index)
{
    std::u16string parcelString = napiSequence->nativeParcel_->ReadString16();
    ani_value val = nullptr;
    ani_status status = ani_create_string_utf16(env, parcelString.c_str(), parcelString.length(), &val);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "create string failed");
        return false;
    }
    ani_set_element(env, array, index, val);
    return true;
}

ani_value ani_MessageSequence::JS_readStringArray(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    if (argc > 0) {
        CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
        ani_value argv[ARGV_LENGTH_1] = {0};
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }
        for (uint32_t i = 0; i < arrayLength; i++) {
            if (napiSequence->nativeParcel_->GetReadableBytes() <= 0) {
                break;
            }
            ani_value val = nullptr;
            if (!ReadAndSetStringToArray(env, napiSequence, argv[ARGV_INDEX_0], i)) {
                return val;
            }
        }
        ani_value napiValue = nullptr;
        ani_CALL(env, ani_get_boolean(env, true, &napiValue));
        return napiValue;
    }
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_32, napiSequence);
    ani_value result = nullptr;
    ani_create_array(env, &result);
    for (uint32_t i = 0; i < arrayLength; i++) {
        if (napiSequence->nativeParcel_->GetReadableBytes() <= 0) {
            break;
        }
        ani_value val = nullptr;
        if (!ReadAndSetStringToArray(env, napiSequence, result, i)) {
            return val;
        }
    }
    return result;
}

ani_value ani_MessageSequence::JS_readParcelableArray(ani_env env, ani_callback_info info)
{
    size_t argc = 1;
    ani_value thisVar = nullptr;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
    if (checkArgsResult == nullptr) {
        ZLOGE(LOG_LABEL, "checkArgsResult is null");
        return checkArgsResult;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    uint32_t arrayLength = napiSequence->nativeParcel_->ReadUint32();
    // checking here is not accurate, but we can defend some extreme attacking case.
    CHECK_READ_LENGTH(env, (size_t)arrayLength, BYTE_SIZE_8, napiSequence);

    uint32_t length = 0;
    ani_get_array_length(env, argv[ARGV_INDEX_0], &length);
    if (length != arrayLength) {
        ZLOGE(LOG_LABEL, "Bad length while reading Sequenceable array");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    for (uint32_t i = 0; i < arrayLength; i++) {
        int32_t len = napiSequence->nativeParcel_->ReadInt32();
        if (len > 0) {
            bool hasElement = false;
            ani_has_element(env, argv[ARGV_INDEX_0], i, &hasElement);
            if (!hasElement) {
                ZLOGE(LOG_LABEL, "parameter check error");
                return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
            }
            ani_value element = nullptr;
            ani_get_element(env, argv[ARGV_INDEX_0], i, &element);
            ani_value callJsFuncResult = JS_readParcelableArrayCallJsFunc(env, element, thisVar);
            if (callJsFuncResult == nullptr) {
                ZLOGE(LOG_LABEL, "call unmarshalling failed, element index:%{public}d", i);
                return callJsFuncResult;
            }
        }
    }
    ani_value result = nullptr;
    ani_get_undefined(env, &result);
    return result;
}

ani_value ani_MessageSequence::JS_readRemoteObjectArray(ani_env env, ani_callback_info info)
{
    ani_value result = nullptr;
    ani_get_undefined(env, &result);

    size_t argc = 0;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t arrayLength = napiSequence->nativeParcel_->ReadInt32();
    if (argc > 0) { // uses passed in array
        ani_value checkArgsResult = JS_checkReadArrayArgs(env, info, argc, thisVar, argv);
        if (checkArgsResult == nullptr) {
            ZLOGE(LOG_LABEL, "checkArgsResult is null");
            return checkArgsResult;
        }
        uint32_t length = 0;
        ani_get_array_length(env, argv[ARGV_INDEX_0], &length);
        if (static_cast<int32_t>(length) != arrayLength) {
            ZLOGE(LOG_LABEL, "Bad length while reading RemoteObject array");
            return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        }
        for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
            sptr<IRemoteObject> value = napiSequence->nativeParcel_->ReadRemoteObject();
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
        sptr<IRemoteObject> value = napiSequence->nativeParcel_->ReadRemoteObject();
        CHECK_BREAK(value != nullptr);
        ani_value napiValue = ani_ohos_rpc_CreateJsRemoteObject(env, value);
        ani_set_element(env, result, i, napiValue);
    }
    return result;
}

ani_value ani_MessageSequence::JS_ReadFileDescriptor(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    int32_t result = napiSequence->nativeParcel_->ReadFileDescriptor();
    if (result == -1) {
        ZLOGE(LOG_LABEL, "read file descriptor failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    ani_value napiValue;
    ani_create_int32(env, result, &napiValue);
    return napiValue;
}

ani_value ani_MessageSequence::JS_ReadAshmem(ani_env env, ani_callback_info info)
{
    size_t argc = 0;
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    sptr<Ashmem> nativeAshmem = napiSequence->nativeParcel_->ReadAshmem();
    if (nativeAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "nativeAshmem is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
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
    ani_value jsAshmem;
    status = ani_new_instance(env, constructor, 0, nullptr, &jsAshmem);
    if (status != ani_ok) {
        ZLOGE(LOG_LABEL, "failed to  construct js Ashmem");
        return napiValue;
    }
    NAPIAshmem *napiAshmem = nullptr;
    ani_unwrap(env, jsAshmem, (void **)&napiAshmem);
    if (napiAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "napiAshmem is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    napiAshmem->SetAshmem(nativeAshmem);
    return jsAshmem;
}

static int32_t GetArraySize(ani_env env, ani_callback_info info, ani_value &thisVar, ani_value& result)
{
    size_t argc = 1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != 1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        result = napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        return -1;
    }
    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1");
        result = napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
        return -1;
    }
    int32_t arraySize = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &arraySize);
    if (arraySize <= 0) {
        ZLOGE(LOG_LABEL, "arraySize is %{public}d, error", arraySize);
        ani_create_array(env, &result);
    }
    return arraySize;
}

ani_value ani_MessageSequence::JS_ReadRawData(ani_env env, ani_callback_info info)
{
    ani_value thisVar = nullptr;
    ani_value result = nullptr;
    int32_t arraySize = GetArraySize(env, info, thisVar, result);
    if (arraySize <= 0) {
        return result;
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
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
    ani_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    size_t bufferSize = static_cast<size_t>(arraySize) * BYTE_SIZE_32;

    ani_status isCreateBufferOk = ani_create_arraybuffer(env, bufferSize, &arrayBufferPtr, &arrayBuffer);
    if (isCreateBufferOk != ani_ok) {
        ZLOGE(LOG_LABEL, "JS_ReadRawData create arrayBuffer failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    ani_status isCreateArrayOk =
        ani_create_typedarray(env, ani_int32_array, arraySize, arrayBuffer, 0, &result);
    if (isCreateArrayOk != ani_ok) {
        ZLOGE(LOG_LABEL, "JS_ReadRawData create Typedarray failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    errno_t status = memcpy_s(arrayBufferPtr, bufferSize, rawData, bufferSize);
    ani_ASSERT(env, status == EOK, "JS_ReadRawData memcpy_s is failed");
    return result;
}

ani_value ani_MessageSequence::JS_ReadRawDataBuffer(ani_env env, ani_callback_info info)
{
    size_t argc = ARGV_LENGTH_1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGV_LENGTH_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameters");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGD(LOG_LABEL, "type mismatch for parameter 1");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }
    int64_t arraySize = 0;
    ani_get_value_int64(env, argv[ARGV_INDEX_0], &arraySize);
    ani_value result = nullptr;
    if (arraySize <= 0) {
        ZLOGE(LOG_LABEL, "arraySize is %{public}" PRId64 ", error", arraySize);
        ani_create_array(env, &result);
        return result;
    }
    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    const void *rawData = napiSequence->nativeParcel_->ReadRawData(arraySize);
    if (rawData == nullptr) {
        ZLOGD(LOG_LABEL, "rawData is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    ani_value arrayBuffer = nullptr;
    void *arrayBufferPtr = nullptr;
    size_t bufferSize = static_cast<size_t>(arraySize);
    ani_status isCreateBufferOk = ani_create_arraybuffer(env, bufferSize, &arrayBufferPtr, &arrayBuffer);
    if (isCreateBufferOk != ani_ok) {
        ZLOGE(LOG_LABEL, "JS_ReadRawData create arrayBuffer failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    errno_t status = memcpy_s(arrayBufferPtr, bufferSize, rawData, bufferSize);
    ani_ASSERT(env, status == EOK, "JS_ReadRawDataBuffer memcpy_s fail");
    return arrayBuffer;
}

template<typename T>
ani_value ani_MessageSequence::JS_CopyVectorToBuffer(ani_env env, std::vector<T> vector, size_t bufferSize)
{
    ani_value arrayBuffer = nullptr;
    void* arrayBufferPtr = nullptr;

    ani_status createStatus = ani_create_arraybuffer(env, bufferSize, &arrayBufferPtr, &arrayBuffer);
    if (createStatus != ani_ok) {
        ZLOGE(LOG_LABEL, "create arrayBuffer failed. status:%{public}d", createStatus);
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    errno_t status = memcpy_s(arrayBufferPtr, bufferSize, vector.data(), bufferSize);
    ani_ASSERT(env, status == EOK, "memcpy_s is failed");

    return arrayBuffer;
}

ani_value ani_MessageSequence::JS_readArrayBuffer(ani_env env, ani_callback_info info)
{
    size_t argc = ARGV_LENGTH_1;
    ani_value argv[ARGV_LENGTH_1] = {0};
    ani_value thisVar = nullptr;
    ani_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != REQUIRED_ARGS_COUNT_1) {
        ZLOGE(LOG_LABEL, "requires 1 parameter");
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_valuetype valueType = ani_null;
    ani_status status = ani_typeof(env, argv[ARGV_INDEX_0], &valueType);
    if (valueType != ani_number) {
        ZLOGE(LOG_LABEL, "type mismatch for parameter 1, not number. status:%{public}d", status);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    ani_MessageSequence *napiSequence = nullptr;
    ani_unwrap(env, thisVar, (void **)&napiSequence);
    if (napiSequence == nullptr) {
        ZLOGE(LOG_LABEL, "napiSequence is null");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }

    int32_t typeCode = 0;
    ani_get_value_int32(env, argv[ARGV_INDEX_0], &typeCode);
    if (typeCode < INT8_ARRAY || typeCode > BIGUINT64_ARRAY) {
        ZLOGE(LOG_LABEL, "the value of parameter 1 is out of range. typeCode:%{public}d", typeCode);
        return napiErr.ThrowError(env, errorDesc::CHECK_PARAM_ERROR);
    }

    return JS_readVectorByTypeCode(env, typeCode, napiSequence);
}

ani_value ani_MessageSequence::JS_readVectorByTypeCode(ani_env env,
                                                         int32_t typeCode,
                                                         ani_MessageSequence *napiSequence)
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

ani_value ani_MessageSequence::JS_readInt8ArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<int8_t> int8Vector;
    if (!napiSequence->nativeParcel_->ReadInt8Vector(&int8Vector)) {
        ZLOGE(LOG_LABEL, "read Int8Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = int8Vector.size();
    return JS_CopyVectorToBuffer(env, int8Vector, bufferSize);
}

ani_value ani_MessageSequence::JS_readUInt8ArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<uint8_t> uint8Vector;
    if (!napiSequence->nativeParcel_->ReadUInt8Vector(&uint8Vector)) {
        ZLOGE(LOG_LABEL, "read UInt8Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = uint8Vector.size();
    return JS_CopyVectorToBuffer(env, uint8Vector, bufferSize);
}

ani_value ani_MessageSequence::JS_readInt16ArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<int16_t> int16Vector;
    if (!napiSequence->nativeParcel_->ReadInt16Vector(&int16Vector)) {
        ZLOGE(LOG_LABEL, "read Int16Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = int16Vector.size() * BYTE_SIZE_16;
    return JS_CopyVectorToBuffer(env, int16Vector, bufferSize);
}

ani_value ani_MessageSequence::JS_readUInt16ArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<uint16_t> uint16Vector;
    if (!napiSequence->nativeParcel_->ReadUInt16Vector(&uint16Vector)) {
        ZLOGE(LOG_LABEL, "read UInt16Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = uint16Vector.size() * BYTE_SIZE_16;
    return JS_CopyVectorToBuffer(env, uint16Vector, bufferSize);
}

ani_value ani_MessageSequence::JS_readInt32ArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<int32_t> int32Vector;
    if (!napiSequence->nativeParcel_->ReadInt32Vector(&int32Vector)) {
        ZLOGE(LOG_LABEL, "read Int32Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = int32Vector.size() * BYTE_SIZE_32;
    return JS_CopyVectorToBuffer(env, int32Vector, bufferSize);
}

ani_value ani_MessageSequence::JS_readUInt32ArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<uint32_t> uint32Vector;
    if (!napiSequence->nativeParcel_->ReadUInt32Vector(&uint32Vector)) {
        ZLOGE(LOG_LABEL, "read UInt32Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = uint32Vector.size() * BYTE_SIZE_32;
    return JS_CopyVectorToBuffer(env, uint32Vector, bufferSize);
}

ani_value ani_MessageSequence::JS_readFloatArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<float> floatVector;
    if (!napiSequence->nativeParcel_->ReadFloatVector(&floatVector)) {
        ZLOGE(LOG_LABEL, "read FloatVector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = floatVector.size() * BYTE_SIZE_32;
    return JS_CopyVectorToBuffer(env, floatVector, bufferSize);
}

ani_value ani_MessageSequence::JS_readDoubleArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<double> doubleVector;
    if (!napiSequence->nativeParcel_->ReadDoubleVector(&doubleVector)) {
        ZLOGE(LOG_LABEL, "read DoubleVector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = doubleVector.size() * BYTE_SIZE_64;
    return JS_CopyVectorToBuffer(env, doubleVector, bufferSize);
}

ani_value ani_MessageSequence::JS_readInt64ArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
{
    std::vector<int64_t> int64Vector;
    if (!napiSequence->nativeParcel_->ReadInt64Vector(&int64Vector)) {
        ZLOGE(LOG_LABEL, "read Int64Vector failed");
        return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    size_t bufferSize = int64Vector.size() * BYTE_SIZE_64;
    return JS_CopyVectorToBuffer(env, int64Vector, bufferSize);
}

ani_value ani_MessageSequence::JS_readUInt64ArrayBuffer(ani_env env, ani_MessageSequence *napiSequence)
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

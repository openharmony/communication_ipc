/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ipc_ffi.h"

#include <string_ex.h>

#include "ipc_skeleton_imp.h"
#include "message_option.h"
#include "napi_remote_object_holder.h"
#include "napi_remote_proxy_holder.h"
#include "napi/native_common.h"
#include "remote_object_impl.h"
#include "remote_proxy_holder_impl.h"
#include "securec.h"

using namespace OHOS::FFI;

namespace OHOS {
static const size_t ARGV_LENGTH_1 = 1;
extern "C" {
int64_t FfiRpcMessageSequenceImplCreate()
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplCreate start");
    auto rpc = FFIData::Create<MessageSequenceImpl>(nullptr);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplCreate failed");
        return -1;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplCreate end");
    return rpc->GetID();
}

void FfiRpcMessageSequenceImplWriteInterfaceToken(int64_t id, char* token, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteInterfaceToken start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    std::u16string str = converter.from_bytes(token);
    if (str.length() >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "[RPC] string length too large");
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteInterfaceToken end");
    *errCode = rpc->CJ_WriteInterfaceToken(str);
}

char* FfiRpcMessageSequenceImplReadInterfaceToken(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInterfaceToken start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    std::u16string token = rpc->CJ_ReadInterfaceToken(errCode);
    if (*errCode != 0) {
        return nullptr;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    std::string str = converter.to_bytes(token);
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInterfaceToken end");
    return MallocCString(str);
}

uint32_t FfiRpcMessageSequenceImplGetSize(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetSize start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetSize end");
    return rpc->CJ_GetSize(errCode);
}

uint32_t FfiRpcMessageSequenceImplGetCapacity(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetCapacity start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetCapacity end");
    return rpc->CJ_GetCapacity(errCode);
}

void FfiRpcMessageSequenceImplSetSize(int64_t id, uint32_t value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplSetSize start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplSetSize end");
    *errCode = rpc->CJ_SetSize(value);
    return;
}

void FfiRpcMessageSequenceImplSetCapacity(int64_t id, uint32_t value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplSetCapacity start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplSetCapacity end");
    *errCode = rpc->CJ_SetCapacity(value);
    return;
}

uint32_t FfiRpcMessageSequenceImplGetWritableBytes(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetWritableBytes start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetWritableBytes end");
    return rpc->CJ_GetWritableBytes(errCode);
}

uint32_t FfiRpcMessageSequenceImplGetReadableBytes(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetReadableBytes start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetReadableBytes end");
    return rpc->CJ_GetReadableBytes(errCode);
}

uint32_t FfiRpcMessageSequenceImplGetReadPosition(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetReadPosition start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetReadPosition end");
    return rpc->CJ_GetReadPosition(errCode);
}

uint32_t FfiRpcMessageSequenceImplGetWritePosition(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetWritePosition start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetWritePosition end");
    return rpc->CJ_GetWritePosition(errCode);
}

void FfiRpcMessageSequenceImplRewindWrite(int64_t id, uint32_t pos, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplRewindWrite start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplRewindWrite end");
    *errCode = rpc->CJ_RewindWrite(pos);
}

void FfiRpcMessageSequenceImplRewindRead(int64_t id, uint32_t pos, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplRewindRead start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplRewindRead end");
    *errCode = rpc->CJ_RewindRead(pos);
}

void FfiRpcMessageSequenceImplWriteNoException(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteNoException start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteNoException end");
    *errCode = rpc->CJ_WriteNoException();
}

char* FfiRpcMessageSequenceImplReadException(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadException start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadException end");
    std::string res = rpc->CJ_ReadException(errCode);
    if (*errCode != 0) {
        return nullptr;
    }
    return MallocCString(res);
}

void FfiRpcMessageSequenceImplWriteByte(int64_t id, int8_t value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteByte start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteByte end");
    *errCode = rpc->CJ_WriteByte(value);
}

void FfiRpcMessageSequenceImplWriteShort(int64_t id, int16_t value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteShort start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteShort end");
    *errCode = rpc->CJ_WriteShort(value);
}

void FfiRpcMessageSequenceImplWriteInt(int64_t id, int32_t value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteInt start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteInt end");
    *errCode = rpc->CJ_WriteInt(value);
}

void FfiRpcMessageSequenceImplWriteLong(int64_t id, int64_t value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteLong start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteLong end");
    *errCode = rpc->CJ_WriteLong(value);
}

void FfiRpcMessageSequenceImplWriteFloat(int64_t id, float value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteFloat start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteFloat end");
    *errCode = rpc->CJ_WriteFloat(value);
}

void FfiRpcMessageSequenceImplWriteDouble(int64_t id, double value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteDouble start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteDouble end");
    *errCode = rpc->CJ_WriteDouble(value);
}

void FfiRpcMessageSequenceImplWriteBoolean(int64_t id, int8_t value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteBoolean start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteBoolean end");
    *errCode = rpc->CJ_WriteBoolean(value);
}

void FfiRpcMessageSequenceImplWriteChar(int64_t id, uint8_t value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteChar start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteChar end");
    *errCode = rpc->CJ_WriteChar(value);
}

void FfiRpcMessageSequenceImplWriteString(int64_t id, char* value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteString start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    std::u16string str = converter.from_bytes(value);
    if (str.length() >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "string length too large");
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteString end");
    *errCode = rpc->CJ_WriteString(str);
}

void FfiRpcMessageSequenceImplWriteByteArray(int64_t id, OHOS::CJByteArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteByteArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteByteArray end");
    *errCode = rpc->CJ_WriteByteArray(value);
}

void FfiRpcMessageSequenceImplWriteShortArray(int64_t id, OHOS::CJShortArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteShortArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWritShortArray end");
    *errCode = rpc->CJ_WriteShortArray(value);
}

void FfiRpcMessageSequenceImplWriteIntArray(int64_t id, OHOS::CJIntArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteIntArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteIntArray end");
    *errCode = rpc->CJ_WriteIntArray(value);
}

void FfiRpcMessageSequenceImplWriteLongArray(int64_t id, OHOS::CJLongArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteLongArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteLongArray end");
    *errCode = rpc->CJ_WriteLongArray(value);
}

void FfiRpcMessageSequenceImplWriteFloatArray(int64_t id, OHOS::CJFloatArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteFloatArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteFloatArray end");
    *errCode = rpc->CJ_WriteFloatArray(value);
}

void FfiRpcMessageSequenceImplWriteDoubleArray(int64_t id, OHOS::CJDoubleArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteDoubleArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteDoubleArray end");
    *errCode = rpc->CJ_WriteDoubleArray(value);
}

void FfiRpcMessageSequenceImplWriteBooleanArray(int64_t id, OHOS::CJByteArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteBooleanArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteBooleanArray end");
    *errCode = rpc->CJ_WriteBooleanArray(value);
}

void FfiRpcMessageSequenceImplWriteCharArray(int64_t id, OHOS::CJCharArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteCharArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteCharArray end");
    *errCode = rpc->CJ_WriteCharArray(value);
}

void FfiRpcMessageSequenceImplWriteStringArray(int64_t id, OHOS::CJStringArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteStringArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    std::u16string stringValue[value.len];
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    for (uint32_t i = 0; i < value.len; i++) {
        stringValue[i] = converter.from_bytes(value.data[i]);
        if (stringValue[i].length() >= MAX_BYTES_LENGTH) {
            ZLOGE(LOG_LABEL, "string length too large");
            *errCode = errorDesc::CHECK_PARAM_ERROR;
            return;
        }
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteStringArray end");
    *errCode = rpc->CJ_WriteStringArray(stringValue, value.len);
}

void FfiRpcMessageSequenceImplWriteArrayBuffer(
    int64_t id, int32_t typeCode, void* value, size_t byteLength, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteArrayBuffer end");
    *errCode = rpc->CJ_WriteArrayBuffer(typeCode, value, byteLength);
}

bool FfiRpcMessageSequenceImplWriteUint32(int64_t id, uint32_t value)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteUint32 start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        return false;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteUint32 end");
    return rpc->CJ_WriteUint32(value);
}

void FfiRpcMessageSequenceImplWriteRawDataBuffer(int64_t id, uint8_t* data, int64_t size, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteRawDataBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteRawDataBuffer end");
    *errCode = rpc->CJ_WriteRawDataBuffer(data, size);
}

void FfiRpcMessageSequenceImplWriteRemoteObject(int64_t id, int64_t object, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteRemoteObject start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteRemoteObject end");
    *errCode = rpc->CJ_WriteRemoteObject(object);
}

void FfiRpcMessageSequenceImplWriteRemoteObjectArray(int64_t id, OHOS::CJLongArray value, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteRemoteObjectArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteRemoteObjectArray end");
    *errCode = rpc->CJ_WriteRemoteObjectArray(value);
}

int8_t FfiRpcMessageSequenceImplReadByte(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadByte start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadByte end");
    return rpc->CJ_ReadByte(errCode);
}

int16_t FfiRpcMessageSequenceImplReadShort(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadShort start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadShort end");
    return rpc->CJ_ReadShort(errCode);
}

int32_t FfiRpcMessageSequenceImplReadInt(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt end");
    return rpc->CJ_ReadInt(errCode);
}

int64_t FfiRpcMessageSequenceImplReadLong(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadLong start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadLong end");
    return rpc->CJ_ReadLong(errCode);
}

float FfiRpcMessageSequenceImplReadFloat(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadFloat start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadFloat end");
    return rpc->CJ_ReadFloat(errCode);
}

double FfiRpcMessageSequenceImplReadDouble(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadDouble start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadDouble end");
    return rpc->CJ_ReadDouble(errCode);
}

int8_t FfiRpcMessageSequenceImplReadBoolean(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadBoolean start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadBoolean end");
    return rpc->CJ_ReadBoolean(errCode);
}

uint8_t FfiRpcMessageSequenceImplReadChar(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadChar start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadChar end");
    return rpc->CJ_ReadChar(errCode);
}

char* FfiRpcMessageSequenceImplReadString(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadString start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    std::u16string token = rpc->CJ_ReadString(errCode);
    if (*errCode != 0) {
        return nullptr;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    std::string str = converter.to_bytes(token);
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadString end");
    return MallocCString(str);
}

OHOS::CJByteArray FfiRpcMessageSequenceImplReadByteArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadByteArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJByteArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadByteArray end");
    return rpc->CJ_ReadByteArray(errCode);
}

OHOS::CJShortArray FfiRpcMessageSequenceImplReadShortArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadShortArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJShortArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadShortArray end");
    return rpc->CJ_ReadShortArray(errCode);
}

OHOS::CJIntArray FfiRpcMessageSequenceImplReadIntArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadIntArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJIntArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadIntArray end");
    return rpc->CJ_ReadIntArray(errCode);
}

OHOS::CJLongArray FfiRpcMessageSequenceImplReadLongArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadLongArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJLongArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadLongArray end");
    return rpc->CJ_ReadLongArray(errCode);
}

OHOS::CJFloatArray FfiRpcMessageSequenceImplReadFloatArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadFloatArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJFloatArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadFloatArray end");
    return rpc->CJ_ReadFloatArray(errCode);
}

OHOS::CJDoubleArray FfiRpcMessageSequenceImplReadDoubleArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadDoubleArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJDoubleArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadDoubleArray end");
    return rpc->CJ_ReadDoubleArray(errCode);
}

OHOS::CJByteArray FfiRpcMessageSequenceImplReadBooleanArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadBooleanArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJByteArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadBooleanArray end");
    return rpc->CJ_ReadBooleanArray(errCode);
}

OHOS::CJCharArray FfiRpcMessageSequenceImplReadCharArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadCharArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJCharArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadCharArray end");
    return rpc->CJ_ReadCharArray(errCode);
}

OHOS::CJStringArray FfiRpcMessageSequenceImplReadStringArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadStringArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJStringArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadStringArray end");
    return rpc->CJ_ReadStringArray(errCode);
}

OHOS::CJByteArray FfiRpcMessageSequenceImplReadInt8ArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt8ArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJByteArray { 0 };
    }
    std::vector<int8_t> vector = rpc->CJ_ReadInt8ArrayBuffer(errCode);
    if (*errCode != 0) {
        return OHOS::CJByteArray { 0 };
    }
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJByteArray { 0 };
    }
    int8_t* arr = static_cast<int8_t*>(malloc(bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJByteArray { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize, vector.data(), bufferSize);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJByteArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt8ArrayBuffer end");
    return OHOS::CJByteArray { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

OHOS::CJCharArray FfiRpcMessageSequenceImplReadUInt8ArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadUInt8ArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJCharArray { 0 };
    }
    std::vector<uint8_t> vector = rpc->CJ_ReadUInt8ArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJCharArray { 0 };
    }
    uint8_t* arr = static_cast<uint8_t*>(malloc(bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJCharArray { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize, vector.data(), bufferSize);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJCharArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadUInt8ArrayBuffer end");
    return OHOS::CJCharArray { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

OHOS::CJShortArray FfiRpcMessageSequenceImplReadInt16ArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt16ArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJShortArray { 0 };
    }
    std::vector<int16_t> vector = rpc->CJ_ReadInt16ArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJShortArray { 0 };
    }
    int16_t* arr = static_cast<int16_t*>(malloc(sizeof(int16_t) * bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJShortArray { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize * BYTE_SIZE_16, vector.data(), bufferSize * BYTE_SIZE_16);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJShortArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt16ArrayBuffer end");
    return OHOS::CJShortArray { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

OHOS::CJUInt16Array FfiRpcMessageSequenceImplReadUInt16ArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadUInt16ArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt16Array { 0 };
    }
    std::vector<uint16_t> vector = rpc->CJ_ReadUInt16ArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJUInt16Array { 0 };
    }
    uint16_t* arr = static_cast<uint16_t*>(malloc(sizeof(uint16_t) * bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt16Array { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize * BYTE_SIZE_16, vector.data(), bufferSize * BYTE_SIZE_16);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt16Array { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadUInt16ArrayBuffer end");
    return OHOS::CJUInt16Array { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

OHOS::CJIntArray FfiRpcMessageSequenceImplReadInt32ArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt32ArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJIntArray { 0 };
    }
    std::vector<int32_t> vector = rpc->CJ_ReadInt32ArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJIntArray { 0 };
    }
    int32_t* arr = static_cast<int32_t*>(malloc(sizeof(int32_t) * bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJIntArray { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize * BYTE_SIZE_32, vector.data(), bufferSize * BYTE_SIZE_32);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJIntArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt32ArrayBuffer end");
    return OHOS::CJIntArray { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

OHOS::CJUInt32Array FfiRpcMessageSequenceImplReadUInt32ArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadUInt32ArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt32Array { 0 };
    }
    std::vector<uint32_t> vector = rpc->CJ_ReadUInt32ArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJUInt32Array { 0 };
    }
    uint32_t* arr = static_cast<uint32_t*>(malloc(sizeof(uint32_t) * bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt32Array { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize * BYTE_SIZE_32, vector.data(), bufferSize * BYTE_SIZE_32);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt32Array { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadUInt32ArrayBuffer end");
    return OHOS::CJUInt32Array { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

OHOS::CJFloatArray FfiRpcMessageSequenceImplReadFloatArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadFloatArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJFloatArray { 0 };
    }
    std::vector<float> vector = rpc->CJ_ReadFloatArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJFloatArray { 0 };
    }
    float* arr = static_cast<float*>(malloc(sizeof(float) * bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJFloatArray { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize * BYTE_SIZE_32, vector.data(), bufferSize * BYTE_SIZE_32);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJFloatArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadFloatArrayBuffer end");
    return OHOS::CJFloatArray { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

OHOS::CJDoubleArray FfiRpcMessageSequenceImplReadDoubleArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadDoubleArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJDoubleArray { 0 };
    }
    std::vector<double> vector = rpc->CJ_ReadDoubleArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJDoubleArray { 0 };
    }
    double* arr = static_cast<double*>(malloc(sizeof(double) * bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJDoubleArray { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize * BYTE_SIZE_64, vector.data(), bufferSize * BYTE_SIZE_64);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJDoubleArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadDoubleArrayBuffer end");
    return OHOS::CJDoubleArray { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}
OHOS::CJLongArray FfiRpcMessageSequenceImplReadInt64ArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt64ArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJLongArray { 0 };
    }
    std::vector<int64_t> vector = rpc->CJ_ReadInt64ArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJLongArray { 0 };
    }
    int64_t* arr = static_cast<int64_t*>(malloc(sizeof(int64_t) * bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJLongArray { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize * BYTE_SIZE_64, vector.data(), bufferSize * BYTE_SIZE_64);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJLongArray { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadInt64ArrayBuffer end");
    return OHOS::CJLongArray { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

OHOS::CJUInt64Array FfiRpcMessageSequenceImplReadUInt64ArrayBuffer(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadUInt64ArrayBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt64Array { 0 };
    }
    std::vector<uint64_t> vector = rpc->CJ_ReadUInt64ArrayBuffer(errCode);
    size_t bufferSize = vector.size();
    if (bufferSize <= 0) {
        return OHOS::CJUInt64Array { 0 };
    }
    uint64_t* arr = static_cast<uint64_t*>(malloc(sizeof(uint64_t) * bufferSize));
    if (arr == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] create arrayBuffer failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt64Array { 0 };
    }
    errno_t ret = memcpy_s(arr, bufferSize * BYTE_SIZE_64, vector.data(), bufferSize * BYTE_SIZE_64);
    if (ret != EOK) {
        free(arr);
        ZLOGE(LOG_LABEL, "[RPC] memcpy_s is failed.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::CJUInt64Array { 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadUInt64ArrayBuffer end");
    return OHOS::CJUInt64Array { .data = arr, .len = static_cast<uint32_t>(bufferSize) };
}

uint8_t* FfiRpcMessageSequenceImplReadRawDataBuffer(int64_t id, int64_t size, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadRawDataBuffer start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadRawDataBuffer end");
    return rpc->CJ_ReadRawDataBuffer(size, errCode);
}


RetDataI64 FfiRpcMessageSequenceImplReadRemoteObject(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadRemoteObject start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return RetDataI64 { 0, 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadRemoteObject end");
    return rpc->CJ_ReadRemoteObject(errCode);
}

OHOS::RemoteObjectArray FfiRpcMessageSequenceImplReadRemoteObjectArray(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadRemoteObjectArray start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return OHOS::RemoteObjectArray { nullptr, nullptr, 0 };
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadRemoteObjectArray end");
    return rpc->CJ_ReadRemoteObjectArray(errCode);
}

void FfiRpcMessageSequenceImplCloseFileDescriptor(int32_t fd)
{
    return MessageSequenceImpl::CJ_CloseFileDescriptor(fd);
}

int32_t FfiRpcMessageSequenceImplDupFileDescriptor(int32_t fd)
{
    return MessageSequenceImpl::CJ_DupFileDescriptor(fd);
}

bool FfiRpcMessageSequenceImplContainFileDescriptors(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplContainFileDescriptors start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return false;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplContainFileDescriptors end");
    return rpc->CJ_ContainFileDescriptors(errCode);
}

void FfiRpcMessageSequenceImplWriteFileDescriptor(int64_t id, int32_t fd, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteFileDescriptor start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteFileDescriptor end");
    *errCode = rpc->CJ_WriteFileDescriptor(fd);
}

int32_t FfiRpcMessageSequenceImplReadFileDescriptor(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadFileDescriptor start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadFileDescriptor end");
    return rpc->CJ_ReadFileDescriptor(errCode);
}

void FfiRpcMessageSequenceImplWriteAshmem(int64_t mid, int64_t aid, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteAshmem start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(mid);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    auto ashmem = FFIData::GetData<AshmemImpl>(aid);
    if (!ashmem || ashmem->GetAshmem() == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplWriteAshmem end");
    *errCode = rpc->CJ_WriteAshmem(ashmem->GetAshmem());
}

int64_t FfiRpcMessageSequenceImplReadAshmem(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadAshmem start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return -1;
    }
    sptr<Ashmem> nativeAshmem = rpc->CJ_ReadAshmem(errCode);
    if (*errCode != 0) {
        return -1;
    }
    auto ashmem = FFIData::Create<AshmemImpl>(nativeAshmem);
    if (!ashmem) {
        ZLOGE(LOG_LABEL, "[RPC] failed to construct cj Ashmem");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return -1;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplReadAshmem end");
    return ashmem->GetID();
}

uint32_t FfiRpcMessageSequenceImplGetRawDataCapacity(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetRawDataCapacity start");
    auto rpc = FFIData::GetData<MessageSequenceImpl>(id);
    if (!rpc) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcMessageSequenceImplGetRawDataCapacity end");
    return rpc->CJ_GetRawDataCapacity(errCode);
}

int64_t FfiRpcAshmemImplCreate(char* ashmemName, int32_t ashmemSize)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplCreate start");
    sptr<Ashmem> nativeAshmem = Ashmem::CreateAshmem(ashmemName, ashmemSize);
    if (nativeAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] instance not exist.");
        return -1;
    }
    auto ashmem = FFIData::Create<AshmemImpl>(nativeAshmem);
    if (!ashmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplCreate failed");
        return -1;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplCreate end");
    return ashmem->GetID();
}

int64_t FfiRpcAshmemImplCreateFromExisting(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplCreateFromExisting start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplCreateFromExisting failed");
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return -1;
    }
    int32_t fd = nativeAshmem->GetAshmem()->GetAshmemFd();
    int32_t size = nativeAshmem->GetAshmem()->GetAshmemSize();
    if (fd <= 0 || size <= 0) {
        ZLOGE(LOG_LABEL, "[RPC] fd <= 0 or  size <= 0");
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return -1;
    }
    sptr<Ashmem> newAshmem(new Ashmem(dup(fd), size));
    if (newAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "[RPC] newAshmem is null");
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return -1;
    }
    auto ashmem = FFIData::Create<AshmemImpl>(newAshmem);
    if (!ashmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplCreateFromExisting failed");
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return -1;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplCreateFromExisting end");
    return ashmem->GetID();
}

void FfiRpcAshmemImplCloseAshmem(int64_t id)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplCloseAshmem start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplCloseAshmem failed");
        return;
    }
    nativeAshmem->CloseAshmem();
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplCloseAshmem end");
}

void FfiRpcAshmemImplUnmapAshmem(int64_t id)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplUnmapAshmem start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplUnmapAshmem failed");
        return;
    }
    nativeAshmem->UnmapAshmem();
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplUnmapAshmem end");
}

int32_t FfiRpcAshmemImplGetAshmemSize(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplGetAshmemSize start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplGetAshmemSize failed");
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return 0;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplGetAshmemSize end");
    return nativeAshmem->GetAshmemSize(errCode);
}

void FfiRpcAshmemImplMapTypedAshmem(int64_t id, uint32_t mapType, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapTypedAshmem start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapTypedAshmem failed");
        *errCode = errorDesc::OS_MMAP_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapTypedAshmem end");
    *errCode = nativeAshmem->MapTypedAshmem(mapType);
}

void FfiRpcAshmemImplMapReadWriteAshmem(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapReadWriteAshmem start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapReadWriteAshmem failed");
        *errCode = errorDesc::OS_MMAP_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapReadWriteAshmem end");
    *errCode = nativeAshmem->MapReadWriteAshmem();
}

void FfiRpcAshmemImplMapReadonlyAshmem(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapReadonlyAshmem start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapReadonlyAshmem failed");
        *errCode = errorDesc::OS_MMAP_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplMapReadonlyAshmem end");
    *errCode = nativeAshmem->MapReadonlyAshmem();
}

void FfiRpcAshmemImplSetProtectionType(int64_t id, uint32_t protectionType, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplSetProtectionType start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplSetProtectionType failed");
        *errCode = errorDesc::OS_IOCTL_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplSetProtectionType end");
    *errCode = nativeAshmem->SetProtectionType(protectionType);
}

void FfiRpcAshmemImplWriteDataToAshmem(int64_t id, uint8_t* data, int64_t size, int64_t offset, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplWriteDataToAshmem start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplWriteDataToAshmem failed");
        *errCode = errorDesc::WRITE_TO_ASHMEM_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplWriteDataToAshmem end");
    *errCode = nativeAshmem->WriteDataToAshmem(data, size, offset);
}

uint8_t* FfiRpcAshmemImplReadDataFromAshmem(int64_t id, int64_t size, int64_t offset, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplReadDataFromAshmem start");
    auto nativeAshmem = FFIData::GetData<AshmemImpl>(id);
    if (!nativeAshmem) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcAshmemImplReadDataFromAshmem failed");
        *errCode = errorDesc::READ_FROM_ASHMEM_ERROR;
        return nullptr;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcAshmemImplReadDataFromAshmem end");
    return nativeAshmem->ReadDataFromAshmem(size, offset, errCode);
}

int64_t FfiRpcRemoteObjectConstructor(char* stringValue)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteObjectConstructor start");
    if (strlen(stringValue) >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "string length too large");
        return -1;
    }
    std::string descriptor = stringValue;
    RemoteObjectHolderImpl* holder = new (std::nothrow) RemoteObjectHolderImpl(Str8ToStr16(descriptor));
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "new RemoteObjectHolderImpl failed");
        return -1;
    }
    auto remoteObject = FFIData::Create<CjRemoteObjectImpl>(holder);
    if (!remoteObject) {
        delete holder;
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteObjectConstructor failed");
        return -1;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteObjectConstructor end");
    return remoteObject->GetID();
}

int32_t FfiRpcRemoteObjectSendMessageRequest(
    int64_t id, uint32_t code, int64_t dataId, int64_t replyId, MesOption opt, int64_t funcId)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteObjectSendMessageRequest start");
    auto remoteObject = FFIData::GetData<CjRemoteObjectImpl>(id);
    if (!remoteObject) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteObjectSendMessageRequest failed");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    MessageOption option = MessageOption(opt.flags, opt.waitTime);
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteObjectSendMessageRequest end");
    return remoteObject->SendMessageRequest(code, dataId, replyId, option, funcId);
}

int32_t FfiRpcRemoteObjectGetCallingPid()
{
    return GetCallingPid();
}

int32_t FfiRpcRemoteObjectGetCallingUid()
{
    return GetCallingUid();
}

char* FfiRpcRemoteObjectGetDescriptor(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteObjectGetDescriptor start");
    auto remoteObject = FFIData::GetData<CjRemoteObjectImpl>(id);
    if (!remoteObject) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteObjectGetDescriptor failed");
        *errCode = errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        return nullptr;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteObjectGetDescriptor end");
    return remoteObject->GetDescriptor(errCode);
}

void FfiRpcRemoteObjectModifyLocalInterface(int64_t id, char* stringValue, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteObjectModifyLocalInterface start");
    auto remoteObject = FFIData::GetData<CjRemoteObjectImpl>(id);
    if (!remoteObject) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteObjectModifyLocalInterface failed");
        *errCode = errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteObjectModifyLocalInterface end");
    *errCode = remoteObject->ModifyLocalInterface(stringValue);
}

RetDataI64 FfiRpcIPCSkeletonGetContextObject()
{
    return GetContextObject();
}

int32_t FfiRpcIPCSkeletonGetCallingPid()
{
    return GetCallingPid();
}

int32_t FfiRpcIPCSkeletonGetCallingUid()
{
    return GetCallingUid();
}

uint32_t FfiRpcIPCSkeletonGetCallingTokenId()
{
    return GetCallingTokenId();
}

char* FfiRpcIPCSkeletonGetCallingDeviceID()
{
    return GetCallingDeviceID();
}

char* FfiRpcIPCSkeletonGetLocalDeviceID()
{
    return GetLocalDeviceID();
}

bool FfiRpcIPCSkeletonIsLocalCalling()
{
    return IsLocalCalling();
}

void FfiRpcIPCSkeletonFlushCmdBuffer(int64_t object)
{
    FlushCmdBuffer(object);
}

int32_t FfiRpcRemoteProxySendMessageRequest(
    int64_t id, uint32_t code, int64_t dataId, int64_t replyId, MesOption opt, int64_t funcId)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxySendMessageRequest start");
    auto remoteProxy = FFIData::GetData<RemoteProxyHolderImpl>(id);
    if (!remoteProxy) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteProxySendMessageRequest failed");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    MessageOption option = MessageOption(opt.flags, opt.waitTime);
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxySendMessageRequest end");
    return remoteProxy->SendMessageRequest(code, dataId, replyId, option, funcId);
}

void FfiRpcRemoteProxyRegisterDeathRecipient(int64_t id, int64_t funcId, int32_t flag, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxyRegisterDeathRecipient start");
    auto remoteProxy = FFIData::GetData<RemoteProxyHolderImpl>(id);
    if (!remoteProxy) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteProxyRegisterDeathRecipient failed");
        *errCode = errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxyRegisterDeathRecipient end");
    *errCode = remoteProxy->RegisterDeathRecipient(funcId, flag);
}

void FfiRpcRemoteProxyUnregisterDeathRecipient(int64_t id, int64_t funcId, int32_t flag, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxyUnregisterDeathRecipient start");
    auto remoteProxy = FFIData::GetData<RemoteProxyHolderImpl>(id);
    if (!remoteProxy) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteProxyUnregisterDeathRecipient failed");
        *errCode = errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        return;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxyUnregisterDeathRecipient end");
    *errCode = remoteProxy->UnregisterDeathRecipient(funcId, flag);
}

char* FfiRpcRemoteProxyGetDescriptor(int64_t id, int32_t* errCode)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxyGetDescriptor start");
    auto remoteProxy = FFIData::GetData<RemoteProxyHolderImpl>(id);
    if (!remoteProxy) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteProxyGetDescriptor failed");
        *errCode = errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        return nullptr;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxyGetDescriptor end");
    return remoteProxy->GetDescriptor(errCode);
}

bool FfiRpcRemoteProxyIsObjectDead(int64_t id)
{
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxyIsObjectDead start");
    auto remoteProxy = FFIData::GetData<RemoteProxyHolderImpl>(id);
    if (!remoteProxy) {
        ZLOGE(LOG_LABEL, "[RPC] FfiRpcRemoteProxyIsObjectDead failed");
        return false;
    }
    ZLOGD(LOG_LABEL, "[RPC] FfiRpcRemoteProxyIsObjectDead end");
    return remoteProxy->IsObjectDead();
}

int32_t FfiRpcGetRemoteType(int64_t id)
{
    auto remoteObject  = FFIData::GetData<CjIRemoteObjectImpl>(id);
    if (!remoteObject) {
        ZLOGE(LOG_LABEL, "[RPC] get construct failed");
        return -1;
    }
    return remoteObject->IsProxyObject() ? 1 : 0;
}

NAPIRemoteProxyHolder *GetRemoteProxyHolder(napi_env env, napi_value jsRemoteProxy)
{
    NAPIRemoteProxyHolder *proxyHolder = nullptr;
    napi_unwrap(env, jsRemoteProxy, (void **)&proxyHolder);
    NAPI_ASSERT(env, proxyHolder != nullptr, "failed to get napi remote proxy holder");
    return proxyHolder;
}

int64_t FfiCreateRemoteObjectFromNapi(napi_env env, napi_value object)
{
    if (env != nullptr || object != nullptr) {
        napi_value global = nullptr;
        napi_status status = napi_get_global(env, &global);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "get napi global failed");
            return 0;
        }
        napi_value stubConstructor = nullptr;
        status = napi_get_named_property(env, global, "IPCStubConstructor_", &stubConstructor);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "get stub constructor failed");
            return 0;
        }
        bool instanceOfStub = false;
        status = napi_instanceof(env, object, stubConstructor, &instanceOfStub);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "failed to check js object type");
            return 0;
        }
        if (instanceOfStub) {
            NAPIRemoteObjectHolder *holder = nullptr;
            napi_unwrap(env, object, (void **)&holder);
            if (holder == nullptr) {
                ZLOGE(LOG_LABEL, "failed to get napi remote object holder");
                return 0;
            }
            return CreateStubRemoteObject(holder->Get());
        }

        napi_value proxyConstructor = nullptr;
        status = napi_get_named_property(env, global, "IPCProxyConstructor_", &proxyConstructor);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "get proxy constructor failed");
            return 0;
        }
        bool instanceOfProxy = false;
        status = napi_instanceof(env, object, proxyConstructor, &instanceOfProxy);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "failed to check js object type");
            return 0;
        }
        if (instanceOfProxy) {
            NAPIRemoteProxyHolder *proxyHolder = GetRemoteProxyHolder(env, object);
            return CreateProxyRemoteObject(proxyHolder->object_);
        }
    }
    return 0;
}

napi_value CreateJsProxyRemoteObject(napi_env env, const sptr<IRemoteObject> target)
{
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "IPCProxyConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "get proxy constructor failed");
    napi_value jsRemoteProxy;
    status = napi_new_instance(env, constructor, 0, nullptr, &jsRemoteProxy);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteProxy");
    NAPIRemoteProxyHolder *proxyHolder = NAPI_ohos_rpc_getRemoteProxyHolder(env, jsRemoteProxy);
    if (proxyHolder == nullptr) {
        ZLOGE(LOG_LABEL, "proxyHolder null");
        return nullptr;
    }
    proxyHolder->object_ = target;
    proxyHolder->list_ = new (std::nothrow) NAPIDeathRecipientList();
    NAPI_ASSERT(env, proxyHolder->list_ != nullptr, "new NAPIDeathRecipientList failed");

    return jsRemoteProxy;
}

napi_value CreateJsStubRemoteObject(napi_env env, const sptr<IRemoteObject> target)
{
    // retrieve js remote object constructor
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    NAPI_ASSERT(env, status == napi_ok, "get napi global failed");
    napi_value constructor = nullptr;
    status = napi_get_named_property(env, global, "IPCStubConstructor_", &constructor);
    NAPI_ASSERT(env, status == napi_ok, "set stub constructor failed");
    NAPI_ASSERT(env, constructor != nullptr, "failed to get js RemoteObject constructor");
    // retrieve descriptor and it's length
    std::u16string descriptor = target->GetObjectDescriptor();
    std::string desc = Str16ToStr8(descriptor);
    napi_value jsDesc = nullptr;
    napi_create_string_utf8(env, desc.c_str(), desc.length(), &jsDesc);
    // create a new js remote object
    size_t argc = 1;
    napi_value argv[ARGV_LENGTH_1] = { jsDesc };
    napi_value jsRemoteObject = nullptr;
    status = napi_new_instance(env, constructor, argc, argv, &jsRemoteObject);
    NAPI_ASSERT(env, status == napi_ok, "failed to  construct js RemoteObject");
    // retrieve holder and set object
    NAPIRemoteObjectHolder *holder = nullptr;
    napi_unwrap(env, jsRemoteObject, (void **)&holder);
    NAPI_ASSERT(env, holder != nullptr, "failed to get napi remote object holder");
    holder->Set(target);
    return jsRemoteObject;
}

napi_value FfiConvertRemoteObject2Napi(napi_env env, int64_t object)
{
    sptr<IRemoteObject> target = CJ_rpc_getNativeRemoteObject(object);
    if (target == nullptr) {
        return nullptr;
    }
    if (!target->IsProxyObject()) {
        IPCObjectStub *tmp = static_cast<IPCObjectStub *>(target.GetRefPtr());
        uint32_t objectType = static_cast<uint32_t>(tmp->GetObjectType());
        ZLOGD(LOG_LABEL, "create js object, type:%{public}d", objectType);
        if (objectType == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT || objectType == IPCObjectStub::OBJECT_TYPE_NATIVE) {
            return CreateJsStubRemoteObject(env, target);
        }
    }

    return CreateJsProxyRemoteObject(env, target);
}
}
} // namespace OHOS
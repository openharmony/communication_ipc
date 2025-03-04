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

#include "message_sequence_impl.h"

#include <cinttypes>
#include <cstring>
#include <unistd.h>

#include "remote_object_impl.h"
#include "string_ex.h"

namespace OHOS {
MessageSequenceImpl::MessageSequenceImpl(MessageParcel* parcel)
{
    maxCapacityToWrite_ = MAX_CAPACITY_TO_WRITE;
    if (parcel == nullptr) {
        nativeParcel_ = std::make_shared<MessageParcel>();
        owner = true;
    } else {
        nativeParcel_ = std::shared_ptr<MessageParcel>(parcel, release);
        owner = false;
    }
}

MessageSequenceImpl::~MessageSequenceImpl()
{
    ZLOGD(LOG_LABEL, "MessageSequence_FFI::Destructor");
    nativeParcel_ = nullptr;
}

void MessageSequenceImpl::release(MessageParcel* parcel)
{
    ZLOGD(LOG_LABEL, "message parcel is created by others, do nothing");
}

std::shared_ptr<MessageParcel> MessageSequenceImpl::GetMessageParcel()
{
    return nativeParcel_;
}

int32_t MessageSequenceImpl::CJ_WriteInterfaceToken(std::u16string value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    bool writeResult = nativeParcel_->WriteInterfaceToken(value);
    if (writeResult == false) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    return 0;
}

std::u16string MessageSequenceImpl::CJ_ReadInterfaceToken(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return u"";
    }
    return nativeParcel_->ReadInterfaceToken();
}

uint32_t MessageSequenceImpl::CJ_GetSize(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return static_cast<uint32_t>(nativeParcel_->GetDataSize());
}

uint32_t MessageSequenceImpl::CJ_GetCapacity(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    size_t value = nativeParcel_->GetDataCapacity();
    return static_cast<uint32_t>(value);
}

int32_t MessageSequenceImpl::CJ_SetSize(uint32_t value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    nativeParcel_->SetDataSize(static_cast<size_t>(value));
    return 0;
}

int32_t MessageSequenceImpl::CJ_SetCapacity(uint32_t value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    nativeParcel_->SetDataCapacity(static_cast<size_t>(value));
    return 0;
}

uint32_t MessageSequenceImpl::CJ_GetWritableBytes(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    size_t value = nativeParcel_->GetWritableBytes();
    return static_cast<uint32_t>(value);
}

uint32_t MessageSequenceImpl::CJ_GetReadableBytes(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    size_t value = nativeParcel_->GetReadableBytes();
    return static_cast<uint32_t>(value);
}

uint32_t MessageSequenceImpl::CJ_GetReadPosition(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    size_t value = nativeParcel_->GetReadableBytes();
    return static_cast<uint32_t>(value);
}

uint32_t MessageSequenceImpl::CJ_GetWritePosition(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    size_t value = nativeParcel_->GetWritePosition();
    return static_cast<uint32_t>(value);
}

int32_t MessageSequenceImpl::CJ_RewindWrite(uint32_t pos)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    bool result = nativeParcel_->RewindWrite(static_cast<size_t>(pos));
    return result ? 0 : errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_RewindRead(uint32_t pos)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    bool result = nativeParcel_->RewindRead(static_cast<size_t>(pos));
    return result ? 0 : errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteNoException()
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    bool writeResult = nativeParcel_->WriteInt32(0);
    if (writeResult == false) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    return 0;
}

std::string MessageSequenceImpl::CJ_ReadException(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return "";
    }
    int32_t code = nativeParcel_->ReadInt32();
    if (code == 0) {
        return "";
    }
    std::u16string str = nativeParcel_->ReadString16();
    return Str16ToStr8(str);
}

bool MessageSequenceImpl::CheckWritePosition()
{
    if (maxCapacityToWrite_ < nativeParcel_->GetWritePosition()) {
        ZLOGE(LOG_LABEL, "invalid write position, maxCapacityToWrite_:%{public}zu, GetWritePosition:%{public}zu",
            maxCapacityToWrite_, nativeParcel_->GetWritePosition());
        return false;
    }
    return true;
}

bool MessageSequenceImpl::CheckWriteCapacity(size_t lenToWrite)
{
    if (CheckWritePosition()) {
        size_t cap = maxCapacityToWrite_ - nativeParcel_->GetWritePosition();
        if (cap < lenToWrite) {
            ZLOGE(LOG_LABEL, "No enough write capacity, cap:%{public}zu, lenToWrite:%{public}zu", cap, lenToWrite);
            return false;
        }
        return true;
    }
    return false;
}

bool MessageSequenceImpl::RewindIfWriteCheckFail(size_t lenToWrite, size_t pos)
{
    if (CheckWritePosition()) {
        size_t cap = maxCapacityToWrite_ - nativeParcel_->GetWritePosition();
        if (cap < lenToWrite) {
            ZLOGE(LOG_LABEL, "No enough write capacity, cap:%{public}zu, lenToWrite:%{public}zu", cap, lenToWrite);
            nativeParcel_->RewindWrite(pos);
            return false;
        }
        return true;
    }
    return false;
}

int32_t MessageSequenceImpl::CJ_WriteByte(int8_t value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32)) {
        bool result = nativeParcel_->WriteInt8(value);
        if (!result) {
            ZLOGE(LOG_LABEL, "write int8 failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
        return 0;
    }
    return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteShort(int16_t value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32)) {
        bool result = nativeParcel_->WriteInt16(value);
        if (!result) {
            ZLOGE(LOG_LABEL, "write int16 failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
        return 0;
    }
    return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteInt(int32_t value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32)) {
        bool result = nativeParcel_->WriteInt32(value);
        if (!result) {
            ZLOGE(LOG_LABEL, "write int32 failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
        return 0;
    }
    return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteLong(int64_t value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_64)) {
        bool result = nativeParcel_->WriteInt64(value);
        if (!result) {
            ZLOGE(LOG_LABEL, "write int64 failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
        return 0;
    }
    return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteFloat(double value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(sizeof(double))) {
        bool result = nativeParcel_->WriteDouble(value);
        if (!result) {
            ZLOGE(LOG_LABEL, "write double failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
        return 0;
    }
    return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteDouble(double value)
{
    return CJ_WriteFloat(value);
}

int32_t MessageSequenceImpl::CJ_WriteBoolean(int8_t value)
{
    return CJ_WriteByte(value);
}

int32_t MessageSequenceImpl::CJ_WriteChar(uint8_t value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32)) {
        bool result = nativeParcel_->WriteUint8(value);
        if (!result) {
            ZLOGE(LOG_LABEL, "write uint8 failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
        return 0;
    }
    return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteString(std::u16string value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32 * value.length())) {
        bool result = nativeParcel_->WriteString16(value);
        if (!result) {
            ZLOGE(LOG_LABEL, "write string16 failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
        return 0;
    }
    return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteByteArray(CJByteArray value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_8 * (value.len + 1))) {
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(value.len);
        bool result = false;
        for (size_t i = 0; i < value.len; i++) {
            result = nativeParcel_->WriteInt8(value.data[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write int8 failed");
                return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
            }
        }
        return 0;
    }
    return errorDesc::CHECK_PARAM_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteShortArray(CJShortArray value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32 * (value.len + 1))) {
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(value.len);
        bool result = false;
        for (size_t i = 0; i < value.len; i++) {
            result = nativeParcel_->WriteInt16(value.data[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write int16 failed");
                return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
            }
        }
        return 0;
    }
    return errorDesc::CHECK_PARAM_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteIntArray(CJIntArray value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32 * (value.len + 1))) {
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(value.len);
        bool result = false;
        for (size_t i = 0; i < value.len; i++) {
            result = nativeParcel_->WriteInt32(value.data[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write int32 failed");
                return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
            }
        }
        return 0;
    }
    return errorDesc::CHECK_PARAM_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteLongArray(CJLongArray value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32 + BYTE_SIZE_64 * value.len)) {
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(value.len);
        bool result = false;
        for (size_t i = 0; i < value.len; i++) {
            result = nativeParcel_->WriteInt64(value.data[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write int64 failed");
                return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
            }
        }
        return 0;
    }
    return errorDesc::CHECK_PARAM_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteFloatArray(CJDoubleArray value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32 + sizeof(double) * value.len)) {
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(value.len);
        bool result = false;
        for (size_t i = 0; i < value.len; i++) {
            result = nativeParcel_->WriteDouble(value.data[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write double failed");
                return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
            }
        }
        return 0;
    }
    return errorDesc::CHECK_PARAM_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteDoubleArray(CJDoubleArray value)
{
    return CJ_WriteFloatArray(value);
}

int32_t MessageSequenceImpl::CJ_WriteBooleanArray(CJByteArray value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32 * (value.len + 1))) {
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(value.len);
        bool result = false;
        for (size_t i = 0; i < value.len; i++) {
            result = nativeParcel_->WriteInt8(value.data[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write int8 failed");
                return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
            }
        }
        return 0;
    }
    return errorDesc::CHECK_PARAM_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteCharArray(CJCharArray value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(BYTE_SIZE_32 * (value.len + 1))) {
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(value.len);
        bool result = false;
        for (size_t i = 0; i < value.len; i++) {
            result = nativeParcel_->WriteUint8(value.data[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write uint8 failed");
                return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
            }
        }
        return 0;
    }
    return errorDesc::CHECK_PARAM_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteStringArray(std::u16string value[], uint32_t arrayLength)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        if (RewindIfWriteCheckFail(BYTE_SIZE_32 * value[i].length(), pos)) {
            result = nativeParcel_->WriteString16(value[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write string16 failed");
                return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
            }
        } else {
            ZLOGE(LOG_LABEL, "No enough capacity to write");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
    }
    return 0;
}

int32_t MessageSequenceImpl::CJ_WriteArrayBuffer(int32_t typeCode, void* value, size_t byteLength)
{
    if (nativeParcel_ == nullptr || value == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (CheckWriteCapacity(byteLength)) {
        bool writeSuccess = CJ_WriteVectorByTypeCode(typeCode, value, byteLength);
        if (!writeSuccess) {
            ZLOGE(LOG_LABEL, "write buffer failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
        return 0;
    }
    return errorDesc::CHECK_PARAM_ERROR;
}

int32_t MessageSequenceImpl::CJ_WriteRawDataBuffer(uint8_t* data, int64_t size)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    if (data == nullptr) {
        return errorDesc::CHECK_PARAM_ERROR;
    }
    if (!nativeParcel_->WriteRawData(data, size)) {
        ZLOGE(LOG_LABEL, "write raw data failed");
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    return 0;
}

bool MessageSequenceImpl::CJ_WriteUint32(uint32_t value)
{
    if (nativeParcel_ == nullptr) {
        return false;
    }
    return nativeParcel_->WriteUint32(value);
}

int32_t MessageSequenceImpl::CJ_WriteRemoteObject(RetDataI64 object)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    sptr<IRemoteObject> remoteObject = CJ_rpc_getNativeRemoteObject(object);
    if (remoteObject == nullptr) {
        ZLOGE(LOG_LABEL, "remote object is nullptr");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    bool writeResult = nativeParcel_->WriteRemoteObject(remoteObject);
    if (!writeResult) {
        ZLOGE(LOG_LABEL, "write remote object failed");
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    return 0;
}

int32_t MessageSequenceImpl::CJ_WriteRemoteObjectArray(RemoteObjectArray value)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    uint32_t arrayLength = static_cast<uint32_t>(value.len);
    size_t pos = nativeParcel_->GetWritePosition();
    bool result = nativeParcel_->WriteInt32(arrayLength);
    for (size_t i = 0; i < arrayLength; i++) {
        RetDataI64 object = RetDataI64 { value.type[i], value.id[i] };
        sptr<IRemoteObject> remoteObject = CJ_rpc_getNativeRemoteObject(object);
        if (remoteObject == nullptr) {
            ZLOGE(LOG_LABEL, "remote object is nullptr");
            return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        }
        result = nativeParcel_->WriteRemoteObject(remoteObject);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write remote object failed");
            return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
        }
    }
    return 0;
}

template<typename T>
static std::vector<T> BufferToVector(void* data, size_t byteLength)
{
    const T* dataPtr = reinterpret_cast<const T*>(data);
    std::vector<T> vec;
    std::copy(dataPtr, dataPtr + byteLength / sizeof(T), std::back_inserter(vec));
    return vec;
}

bool MessageSequenceImpl::CJ_WriteVectorByTypeCode(int32_t typeCode, void* data, size_t byteLength)
{
    switch (typeCode) {
        case INT8_ARRAY: {
            return nativeParcel_->WriteInt8Vector(BufferToVector<int8_t>(data, byteLength));
        }
        case UINT8_ARRAY: {
            return nativeParcel_->WriteUInt8Vector(BufferToVector<uint8_t>(data, byteLength));
        }
        case INT16_ARRAY: {
            return nativeParcel_->WriteInt16Vector(BufferToVector<int16_t>(data, byteLength));
        }
        case UINT16_ARRAY: {
            return nativeParcel_->WriteUInt16Vector(BufferToVector<uint16_t>(data, byteLength));
        }
        case INT32_ARRAY: {
            return nativeParcel_->WriteInt32Vector(BufferToVector<int32_t>(data, byteLength));
        }
        case UINT32_ARRAY: {
            return nativeParcel_->WriteUInt32Vector(BufferToVector<uint32_t>(data, byteLength));
        }
        case FLOAT32_ARRAY: {
            return nativeParcel_->WriteFloatVector(BufferToVector<float>(data, byteLength));
        }
        case FLOAT64_ARRAY: {
            return nativeParcel_->WriteDoubleVector(BufferToVector<double>(data, byteLength));
        }
        case BIGINT64_ARRAY: {
            return nativeParcel_->WriteInt64Vector(BufferToVector<int64_t>(data, byteLength));
        }
        case BIGUINT64_ARRAY: {
            return nativeParcel_->WriteUInt64Vector(BufferToVector<uint64_t>(data, byteLength));
        }
        default:
            ZLOGE(LOG_LABEL, "unsupported typeCode:%{public}d", typeCode);
            return false;
    }
}

int8_t MessageSequenceImpl::CJ_ReadByte(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return nativeParcel_->ReadInt8();
}

int16_t MessageSequenceImpl::CJ_ReadShort(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return nativeParcel_->ReadInt16();
}

int32_t MessageSequenceImpl::CJ_ReadInt(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return nativeParcel_->ReadInt32();
}

int64_t MessageSequenceImpl::CJ_ReadLong(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return nativeParcel_->ReadInt64();
}

double MessageSequenceImpl::CJ_ReadFloat(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return nativeParcel_->ReadDouble();
}

double MessageSequenceImpl::CJ_ReadDouble(int32_t* errCode)
{
    return CJ_ReadFloat(errCode);
}

int8_t MessageSequenceImpl::CJ_ReadBoolean(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return nativeParcel_->ReadInt8();
}

uint8_t MessageSequenceImpl::CJ_ReadChar(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return nativeParcel_->ReadUint8();
}

std::u16string MessageSequenceImpl::CJ_ReadString(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return u"";
    }
    return nativeParcel_->ReadString16();
}

bool MessageSequenceImpl::CheckReadPosition()
{
    if (nativeParcel_->GetDataSize() < nativeParcel_->GetReadPosition()) {
        ZLOGE(LOG_LABEL, "invalid write position, maxCapacityToWrite_:%{public}zu, GetWritePosition:%{public}zu",
            maxCapacityToWrite_, nativeParcel_->GetWritePosition());
        return false;
    }
    return true;
}

bool MessageSequenceImpl::CheckReadLength(size_t arrayLength, size_t typeSize)
{
    if (CheckReadPosition()) {
        size_t remainSize = nativeParcel_->GetDataSize() - nativeParcel_->GetReadPosition();
        if ((arrayLength > remainSize) || ((arrayLength) * (typeSize) > remainSize)) {
            ZLOGE(LOG_LABEL,
                "No enough data to read, arrayLength:%{public}zu, remainSize:%{public}zu,"
                "typeSize:%{public}zu, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",
                arrayLength, remainSize, typeSize, nativeParcel_->GetDataSize(), nativeParcel_->GetReadPosition());
            return false;
        }
        return true;
    }
    return false;
}

CJByteArray MessageSequenceImpl::CJ_ReadByteArray(int32_t* errCode)
{
    CJByteArray arr = CJByteArray { 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return arr;
    }
    arr.len = nativeParcel_->ReadUint32();
    if (arr.len == 0) {
        return arr;
    }
    if (CheckReadLength(static_cast<size_t>(arr.len), BYTE_SIZE_8)) {
        arr.data = static_cast<int8_t*>(malloc(sizeof(int8_t) * arr.len));
        if (arr.data == nullptr) {
            *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
            return arr;
        }
        for (uint32_t i = 0; i < arr.len; i++) {
            arr.data[i] = nativeParcel_->ReadInt8();
        }
    }
    return arr;
}

CJShortArray MessageSequenceImpl::CJ_ReadShortArray(int32_t* errCode)
{
    CJShortArray arr = CJShortArray { 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return arr;
    }
    arr.len = nativeParcel_->ReadUint32();
    if (arr.len == 0) {
        return arr;
    }
    if (CheckReadLength(static_cast<size_t>(arr.len), BYTE_SIZE_32)) {
        arr.data = static_cast<int16_t*>(malloc(sizeof(int16_t) * arr.len));
        if (arr.data == nullptr) {
            *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
            return arr;
        }
        for (uint32_t i = 0; i < arr.len; i++) {
            arr.data[i] = nativeParcel_->ReadInt16();
        }
    }
    return arr;
}

CJIntArray MessageSequenceImpl::CJ_ReadIntArray(int32_t* errCode)
{
    CJIntArray arr = CJIntArray { 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return arr;
    }
    arr.len = nativeParcel_->ReadUint32();
    if (arr.len == 0) {
        return arr;
    }
    if (CheckReadLength(static_cast<size_t>(arr.len), BYTE_SIZE_32)) {
        arr.data = static_cast<int32_t*>(malloc(sizeof(int32_t) * arr.len));
        if (arr.data == nullptr) {
            *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
            return arr;
        }
        for (uint32_t i = 0; i < arr.len; i++) {
            arr.data[i] = nativeParcel_->ReadInt32();
        }
    }
    return arr;
}

CJLongArray MessageSequenceImpl::CJ_ReadLongArray(int32_t* errCode)
{
    CJLongArray arr = CJLongArray { 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return arr;
    }
    arr.len = nativeParcel_->ReadUint32();
    if (arr.len == 0) {
        return arr;
    }
    if (CheckReadLength(static_cast<size_t>(arr.len), BYTE_SIZE_64)) {
        arr.data = static_cast<int64_t*>(malloc(sizeof(int64_t) * arr.len));
        if (arr.data == nullptr) {
            *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
            return arr;
        }
        for (uint32_t i = 0; i < arr.len; i++) {
            arr.data[i] = nativeParcel_->ReadInt64();
        }
    }
    return arr;
}

CJDoubleArray MessageSequenceImpl::CJ_ReadFloatArray(int32_t* errCode)
{
    CJDoubleArray arr = CJDoubleArray { 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return arr;
    }
    arr.len = nativeParcel_->ReadUint32();
    if (arr.len == 0) {
        return arr;
    }
    if (CheckReadLength(static_cast<size_t>(arr.len), sizeof(double))) {
        arr.data = static_cast<double*>(malloc(sizeof(double) * arr.len));
        if (arr.data == nullptr) {
            *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
            return arr;
        }
        for (uint32_t i = 0; i < arr.len; i++) {
            arr.data[i] = nativeParcel_->ReadDouble();
        }
    }
    return arr;
}

CJDoubleArray MessageSequenceImpl::CJ_ReadDoubleArray(int32_t* errCode)
{
    return CJ_ReadFloatArray(errCode);
}

CJByteArray MessageSequenceImpl::CJ_ReadBooleanArray(int32_t* errCode)
{
    CJByteArray arr = CJByteArray { 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return arr;
    }
    arr.len = nativeParcel_->ReadUint32();
    if (arr.len == 0) {
        return arr;
    }
    if (CheckReadLength(static_cast<size_t>(arr.len), BYTE_SIZE_32)) {
        arr.data = static_cast<int8_t*>(malloc(sizeof(int8_t) * arr.len));
        if (arr.data == nullptr) {
            *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
            return arr;
        }
        for (uint32_t i = 0; i < arr.len; i++) {
            arr.data[i] = nativeParcel_->ReadInt8();
        }
    }
    return arr;
}

CJCharArray MessageSequenceImpl::CJ_ReadCharArray(int32_t* errCode)
{
    CJCharArray arr = CJCharArray { 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return arr;
    }
    arr.len = nativeParcel_->ReadUint32();
    if (arr.len == 0) {
        return arr;
    }
    if (CheckReadLength(static_cast<size_t>(arr.len), BYTE_SIZE_32)) {
        arr.data = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * arr.len));
        if (arr.data == nullptr) {
            *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
            return arr;
        }
        for (uint32_t i = 0; i < arr.len; i++) {
            arr.data[i] = nativeParcel_->ReadUint8();
        }
    }
    return arr;
}

CJStringArray MessageSequenceImpl::CJ_ReadStringArray(int32_t* errCode)
{
    CJStringArray arr = CJStringArray { 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return arr;
    }
    arr.len = nativeParcel_->ReadUint32();
    if (arr.len == 0) {
        return arr;
    }
    if (CheckReadLength(static_cast<size_t>(arr.len), BYTE_SIZE_32)) {
        arr.data = static_cast<char**>(malloc(sizeof(char*) * arr.len));
        if (arr.data == nullptr) {
            *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
            return arr;
        }
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
        for (uint32_t i = 0; i < arr.len; i++) {
            if (nativeParcel_->GetReadableBytes() <= 0) {
                break;
            }
            std::u16string parcelString = nativeParcel_->ReadString16();
            std::string str = converter.to_bytes(parcelString);
            arr.data[i] = MallocCString(str);
        }
    }
    return arr;
}

std::vector<int8_t> MessageSequenceImpl::CJ_ReadInt8ArrayBuffer(int32_t* errCode)
{
    std::vector<int8_t> int8Vector;
    if (!nativeParcel_ || !nativeParcel_->ReadInt8Vector(&int8Vector)) {
        ZLOGE(LOG_LABEL, "read Int8Vector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return int8Vector;
}

std::vector<uint8_t> MessageSequenceImpl::CJ_ReadUInt8ArrayBuffer(int32_t* errCode)
{
    std::vector<uint8_t> uint8Vector;
    if (!nativeParcel_ || !nativeParcel_->ReadUInt8Vector(&uint8Vector)) {
        ZLOGE(LOG_LABEL, "read UInt8Vector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return uint8Vector;
}

std::vector<int16_t> MessageSequenceImpl::CJ_ReadInt16ArrayBuffer(int32_t* errCode)
{
    std::vector<int16_t> int16Vector;
    if (!nativeParcel_ || !nativeParcel_->ReadInt16Vector(&int16Vector)) {
        ZLOGE(LOG_LABEL, "read Int16Vector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return int16Vector;
}

std::vector<uint16_t> MessageSequenceImpl::CJ_ReadUInt16ArrayBuffer(int32_t* errCode)
{
    std::vector<uint16_t> uint16Vector;
    if (!nativeParcel_ || !nativeParcel_->ReadUInt16Vector(&uint16Vector)) {
        ZLOGE(LOG_LABEL, "read UInt16Vector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return uint16Vector;
}

std::vector<int32_t> MessageSequenceImpl::CJ_ReadInt32ArrayBuffer(int32_t* errCode)
{
    std::vector<int32_t> int32Vector;
    if (!nativeParcel_ || !nativeParcel_->ReadInt32Vector(&int32Vector)) {
        ZLOGE(LOG_LABEL, "read Int32Vector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return int32Vector;
}

std::vector<uint32_t> MessageSequenceImpl::CJ_ReadUInt32ArrayBuffer(int32_t* errCode)
{
    std::vector<uint32_t> uint32Vector;
    if (!nativeParcel_ || !nativeParcel_->ReadUInt32Vector(&uint32Vector)) {
        ZLOGE(LOG_LABEL, "read UInt32Vector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return uint32Vector;
}

std::vector<float> MessageSequenceImpl::CJ_ReadFloatArrayBuffer(int32_t* errCode)
{
    std::vector<float> floatVector;
    if (!nativeParcel_ || !nativeParcel_->ReadFloatVector(&floatVector)) {
        ZLOGE(LOG_LABEL, "read FloatVector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return floatVector;
}

std::vector<double> MessageSequenceImpl::CJ_ReadDoubleArrayBuffer(int32_t* errCode)
{
    std::vector<double> doubleVector;
    if (!nativeParcel_ || !nativeParcel_->ReadDoubleVector(&doubleVector)) {
        ZLOGE(LOG_LABEL, "read DoubleVector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return doubleVector;
}

std::vector<int64_t> MessageSequenceImpl::CJ_ReadInt64ArrayBuffer(int32_t* errCode)
{
    std::vector<int64_t> int64Vector;
    if (!nativeParcel_ || !nativeParcel_->ReadInt64Vector(&int64Vector)) {
        ZLOGE(LOG_LABEL, "read Int64Vector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return int64Vector;
}

std::vector<uint64_t> MessageSequenceImpl::CJ_ReadUInt64ArrayBuffer(int32_t* errCode)
{
    std::vector<uint64_t> uint64vector;
    if (!nativeParcel_ || !nativeParcel_->ReadUInt64Vector(&uint64vector)) {
        ZLOGE(LOG_LABEL, "read UInt64Vector failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return uint64vector;
}

uint8_t* MessageSequenceImpl::CJ_ReadRawDataBuffer(int64_t size, int32_t* errCode)
{
    if (size <= 0) {
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return nullptr;
    }
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    const void* rawData = nativeParcel_->ReadRawData(size);
    if (rawData == nullptr) {
        ZLOGE(LOG_LABEL, "rawData is null");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    uint8_t* data = static_cast<uint8_t*>(malloc(size));
    if (data == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    errno_t status = memcpy_s(data, size, rawData, size);
    if (status != EOK) {
        free(data);
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    return data;
}

RetDataI64 MessageSequenceImpl::CJ_ReadRemoteObject(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return RetDataI64 { 0, 0 };
    }
    sptr<IRemoteObject> value = nativeParcel_->ReadRemoteObject();
    return CJ_rpc_CreateRemoteObject(value);
}

RemoteObjectArray MessageSequenceImpl::CJ_ReadRemoteObjectArray(int32_t* errCode)
{
    RemoteObjectArray res = RemoteObjectArray { nullptr, nullptr, 0 };
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return res;
    }
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        return res;
    }
    int32_t* type = static_cast<int32_t*>(malloc(arrayLength));
    if (type == nullptr) {
        return res;
    }
    int64_t* id = static_cast<int64_t*>(malloc(arrayLength));
    if (id == nullptr) {
        free(type);
        return res;
    }
    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        sptr<IRemoteObject> value = nativeParcel_->ReadRemoteObject();
        RetDataI64 element = CJ_rpc_CreateRemoteObject(value);
        type[i] = element.code;
        id[i] = element.data;
    }
    res.type = type;
    res.id = id;
    return res;
}

void MessageSequenceImpl::CJ_CloseFileDescriptor(int32_t fd)
{
    close(fd);
}

int32_t MessageSequenceImpl::CJ_DupFileDescriptor(int32_t fd)
{
    return dup(fd);
}

bool MessageSequenceImpl::CJ_ContainFileDescriptors(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return false;
    }
    return nativeParcel_->ContainFileDescriptors();
}

int32_t MessageSequenceImpl::CJ_WriteFileDescriptor(int32_t fd)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    bool result = nativeParcel_->WriteFileDescriptor(fd);
    if (!result) {
        ZLOGE(LOG_LABEL, "write file descriptor failed");
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    return 0;
}

int32_t MessageSequenceImpl::CJ_ReadFileDescriptor(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    int32_t result = nativeParcel_->ReadFileDescriptor();
    if (result == -1) {
        ZLOGE(LOG_LABEL, "read file descriptor failed");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return result;
}

int32_t MessageSequenceImpl::CJ_WriteAshmem(sptr<Ashmem> nativeAshmem)
{
    if (nativeParcel_ == nullptr) {
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    bool result = nativeParcel_->WriteAshmem(nativeAshmem);
    if (!result) {
        ZLOGE(LOG_LABEL, "write ashmem failed");
        return errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR;
    }
    return 0;
}

sptr<Ashmem> MessageSequenceImpl::CJ_ReadAshmem(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return nullptr;
    }
    sptr<Ashmem> nativeAshmem = nativeParcel_->ReadAshmem();
    if (nativeAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "nativeAshmem is null");
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
    }
    return nativeAshmem;
}

uint32_t MessageSequenceImpl::CJ_GetRawDataCapacity(int32_t* errCode)
{
    if (nativeParcel_ == nullptr) {
        *errCode = errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR;
        return 0;
    }
    return nativeParcel_->GetRawDataCapacity();
}
} // namespace OHOS

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
#ifndef MESSAGE_SEQUENCE_IMPL_H
#define MESSAGE_SEQUENCE_IMPL_H

#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "ipc_skeleton.h"
#include "ipc_utils_ffi.h"
#include "message_parcel.h"
#include "securec.h"

namespace OHOS {
extern "C" {
struct MesOption {
    int flags;
    int waitTime;
};
}
class FFI_EXPORT MessageSequenceImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(MessageSequenceImpl, OHOS::FFI::FFIData)
public:
    explicit MessageSequenceImpl(MessageParcel* parcel);
    virtual ~MessageSequenceImpl();
    std::shared_ptr<MessageParcel> GetMessageParcel();

    int32_t CJ_WriteInterfaceToken(std::u16string value);
    std::u16string CJ_ReadInterfaceToken(int32_t* errCode);
    uint32_t CJ_GetSize(int32_t* errCode);
    uint32_t CJ_GetCapacity(int32_t* errCode);
    int32_t CJ_SetSize(uint32_t value);
    int32_t CJ_SetCapacity(uint32_t value);
    uint32_t CJ_GetWritableBytes(int32_t* errCode);
    uint32_t CJ_GetReadableBytes(int32_t* errCode);
    uint32_t CJ_GetReadPosition(int32_t* errCode);
    uint32_t CJ_GetWritePosition(int32_t* errCode);
    int32_t CJ_RewindWrite(uint32_t pos);
    int32_t CJ_RewindRead(uint32_t pos);
    int32_t CJ_WriteNoException();
    std::string CJ_ReadException(int32_t* errCode);

    int32_t CJ_WriteByte(int8_t value);
    int32_t CJ_WriteShort(int16_t value);
    int32_t CJ_WriteInt(int32_t value);
    int32_t CJ_WriteLong(int64_t value);
    int32_t CJ_WriteFloat(float value);
    int32_t CJ_WriteDouble(double value);
    int32_t CJ_WriteBoolean(int8_t value);
    int32_t CJ_WriteChar(uint8_t value);
    int32_t CJ_WriteString(std::u16string value);
    int32_t CJ_WriteByteArray(CJByteArray value);
    int32_t CJ_WriteShortArray(CJShortArray value);
    int32_t CJ_WriteIntArray(CJIntArray value);
    int32_t CJ_WriteLongArray(CJLongArray value);
    int32_t CJ_WriteFloatArray(CJFloatArray value);
    int32_t CJ_WriteDoubleArray(CJDoubleArray value);
    int32_t CJ_WriteBooleanArray(CJByteArray value);
    int32_t CJ_WriteCharArray(CJCharArray value);
    int32_t CJ_WriteStringArray(std::u16string value[], uint32_t arrayLength);
    int32_t CJ_WriteArrayBuffer(int32_t typeCode, void* value, size_t byteLength);
    int32_t CJ_WriteRawDataBuffer(uint8_t* data, int64_t size);
    bool CJ_WriteUint32(uint32_t value);
    int32_t CJ_WriteRemoteObject(int64_t object);
    int32_t CJ_WriteRemoteObjectArray(CJLongArray value);

    int8_t CJ_ReadByte(int32_t* errCode);
    int16_t CJ_ReadShort(int32_t* errCode);
    int32_t CJ_ReadInt(int32_t* errCode);
    int64_t CJ_ReadLong(int32_t* errCode);
    float CJ_ReadFloat(int32_t* errCode);
    double CJ_ReadDouble(int32_t* errCode);
    int8_t CJ_ReadBoolean(int32_t* errCode);
    uint8_t CJ_ReadChar(int32_t* errCode);
    std::u16string CJ_ReadString(int32_t* errCode);
    CJByteArray CJ_ReadByteArray(int32_t* errCode);
    CJShortArray CJ_ReadShortArray(int32_t* errCode);
    CJIntArray CJ_ReadIntArray(int32_t* errCode);
    CJLongArray CJ_ReadLongArray(int32_t* errCode);
    CJFloatArray CJ_ReadFloatArray(int32_t* errCode);
    CJDoubleArray CJ_ReadDoubleArray(int32_t* errCode);
    CJByteArray CJ_ReadBooleanArray(int32_t* errCode);
    CJCharArray CJ_ReadCharArray(int32_t* errCode);
    CJStringArray CJ_ReadStringArray(int32_t* errCode);
    std::vector<int8_t> CJ_ReadInt8ArrayBuffer(int32_t* errCode);
    std::vector<uint8_t> CJ_ReadUInt8ArrayBuffer(int32_t* errCode);
    std::vector<int16_t> CJ_ReadInt16ArrayBuffer(int32_t* errCode);
    std::vector<uint16_t> CJ_ReadUInt16ArrayBuffer(int32_t* errCode);
    std::vector<int32_t> CJ_ReadInt32ArrayBuffer(int32_t* errCode);
    std::vector<uint32_t> CJ_ReadUInt32ArrayBuffer(int32_t* errCode);
    std::vector<float> CJ_ReadFloatArrayBuffer(int32_t* errCode);
    std::vector<double> CJ_ReadDoubleArrayBuffer(int32_t* errCode);
    std::vector<int64_t> CJ_ReadInt64ArrayBuffer(int32_t* errCode);
    std::vector<uint64_t> CJ_ReadUInt64ArrayBuffer(int32_t* errCode);
    uint8_t* CJ_ReadRawDataBuffer(int64_t size, int32_t* errCode);
    RetDataI64 CJ_ReadRemoteObject(int32_t* errCode);
    RemoteObjectArray CJ_ReadRemoteObjectArray(int32_t* errCode);

    static void CJ_CloseFileDescriptor(int32_t fd);
    static int32_t CJ_DupFileDescriptor(int32_t fd);
    bool CJ_ContainFileDescriptors(int32_t* errCode);
    int32_t CJ_WriteFileDescriptor(int32_t fd);
    int32_t CJ_ReadFileDescriptor(int32_t* errCode);
    uint32_t CJ_GetRawDataCapacity(int32_t* errCode);
    int32_t CJ_WriteAshmem(sptr<Ashmem> nativeAshmem);
    sptr<Ashmem> CJ_ReadAshmem(int32_t* errCode);

private:
    static void release(MessageParcel* parcel);
    bool CheckWritePosition();
    bool CheckWriteCapacity(size_t lenToWrite);
    bool RewindIfWriteCheckFail(size_t lenToWrite, size_t pos);
    bool CheckReadPosition();
    bool CheckReadLength(size_t arrayLength, size_t typeSize);
    bool CJ_WriteVectorByTypeCode(int32_t typeCode, void* data, size_t byteLength);

    bool owner;
    std::shared_ptr<MessageParcel> nativeParcel_ = nullptr;
    size_t maxCapacityToWrite_;
};
} // namespace OHOS

#endif

/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_TAIHE_MESSAGE_SEQUENCE_H
#define OHOS_IPC_TAIHE_MESSAGE_SEQUENCE_H

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <cinttypes>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "napi/native_api.h"

namespace OHOS {
class MessageSequenceImpl {
public:
    MessageSequenceImpl();

    MessageSequenceImpl(OHOS::MessageParcel* messageparcel);

    explicit MessageSequenceImpl(std::shared_ptr<OHOS::MessageParcel> messageparcel);

    ~MessageSequenceImpl();

    void Reclaim();

    void WriteRemoteObject(::ohos::rpc::rpc::IRemoteObjectUnion const& object);

    ::ohos::rpc::rpc::IRemoteObjectUnion ReadRemoteObject();

    void WriteInterfaceToken(::taihe::string_view token);

    ::taihe::string ReadInterfaceToken();

    int32_t GetCapacity();

    void SetCapacity(int32_t size);

    void WriteNoException();

    void ReadException();

    void WriteInt(int32_t val);

    void WriteLong(int64_t val);

    void WriteDouble(double val);

    void WriteChar(int32_t val);

    void WriteBoolean(bool val);

    void WriteString(::taihe::string_view val);

    void WriteParcelable(::ohos::rpc::rpc::weak::Parcelable val);

    void WriteByteArray(::taihe::array_view<int8_t> byteArray);

    void WriteShortArray(::taihe::array_view<int32_t> shortArray);

    void WriteIntArray(::taihe::array_view<int32_t> intArray);

    void WriteLongArray(::taihe::array_view<int64_t> longArray);

    void WriteFloatArray(::taihe::array_view<double> floatArray);

    void WriteDoubleArray(::taihe::array_view<double> doubleArray);

    void WriteBooleanArray(::taihe::array_view<bool> booleanArray);

    void WriteCharArray(::taihe::array_view<int32_t> charArray);

    void WriteStringArray(::taihe::array_view<::taihe::string> stringArray);

    void WriteParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray);

    void WriteRemoteObjectArray(::taihe::array_view<::ohos::rpc::rpc::IRemoteObjectUnion> objectArray);

    int32_t ReadInt();

    int64_t ReadLong();

    bool ReadBoolean();

    ::taihe::string ReadString();

    void ReadParcelable(::ohos::rpc::rpc::weak::Parcelable dataIn);

    ::taihe::array<int32_t> ReadIntArrayImpl();

    ::taihe::array<double> ReadDoubleArrayImpl();

    ::taihe::array<bool> ReadBooleanArrayImpl();

    ::taihe::array<::taihe::string> ReadStringArrayImpl();

    ::taihe::array<int32_t> ReadCharArrayImpl();

    ::taihe::array<double> ReadFloatArrayImpl();

    ::taihe::array<int64_t> ReadLongArrayImpl();

    ::taihe::array<int32_t> ReadShortArrayImpl();

    int32_t ReadChar();

    double ReadFloat();

    double ReadDouble();

    int32_t ReadShort();

    int32_t ReadByte();

    void ReadParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray);

    void WriteFileDescriptor(int32_t fd);

    int32_t ReadFileDescriptor();

    void WriteAshmem(::ohos::rpc::rpc::weak::Ashmem ashmem);

    ::ohos::rpc::rpc::Ashmem ReadAshmem();

    void WriteRawDataBuffer(::taihe::array_view<uint8_t> rawData, int32_t size);

    ::taihe::array<uint8_t> ReadRawDataBuffer(int32_t size);

    int64_t GetNativePtr();

    void AddJsObjWeakRef(::ohos::rpc::rpc::weak::MessageSequence obj);

    static ::ohos::rpc::rpc::MessageSequence CreateMessageSequence();
    static void CloseFileDescriptor(int32_t fd);

    int64_t GetMessageSequenceImpl();

    void WriteArrayBuffer(::taihe::array_view<uint8_t> buf, ::ohos::rpc::rpc::TypeCode typeCode);

    bool WriteVectorByTypeCode(void *data, ::ohos::rpc::rpc::TypeCode typeCode, int32_t byteLength);

    ::taihe::array<uint8_t> ReadArrayBuffer(::ohos::rpc::rpc::TypeCode typeCode);

    ::taihe::array<uint8_t> ReadInt8ArrayBuffer();

    ::taihe::array<uint8_t> ReadUInt8ArrayBuffer();

    ::taihe::array<uint8_t> ReadInt16ArrayBuffer();

    ::taihe::array<uint8_t> ReadUInt16ArrayBuffer();

    ::taihe::array<uint8_t> ReadInt32ArrayBuffer();

    ::taihe::array<uint8_t> ReadUInt32ArrayBuffer();

    ::taihe::array<uint8_t> ReadFloatArrayBuffer();

    ::taihe::array<uint8_t> ReadDoubleArrayBuffer();

    ::taihe::array<uint8_t> ReadInt64ArrayBuffer();

    ::taihe::array<uint8_t> ReadUInt64ArrayBuffer();

    int32_t GetSize();

    int32_t GetWritableBytes();

    int32_t GetReadableBytes();

    int32_t GetReadPosition();

    int32_t GetWritePosition();

    bool ContainFileDescriptors();

    int32_t GetRawDataCapacity();

    void RewindRead(int32_t pos);

    void RewindWrite(int32_t pos);

    void SetSize(int32_t size);

    ::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion> ReadRemoteObjectArrayImpl();

    ::taihe::array<int32_t> ReadByteArrayImpl();

    void WriteByte(int32_t val);

    void WriteShort(int32_t val);

    void WriteFloat(double val);

    static int32_t DupFileDescriptor(int32_t fd);

    static ::ohos::rpc::rpc::MessageSequence RpcTransferStaicImpl(uintptr_t input);

    static uintptr_t RpcTransferDynamicImpl(::ohos::rpc::rpc::MessageSequence obj);

    static void CreateJsMessageSequence(napi_env jsenv, napi_status status,
            napi_value global, napi_value* jsMessageSequence);

    MessageParcel* GetNativeParcel() const
    {
        return nativeParcel_;
    }

private:
    OHOS::MessageParcel* nativeParcel_ = nullptr;
    std::optional<::ohos::rpc::rpc::weak::MessageSequence> jsObjRef_;
    bool isOwner_ = false;
};
} // namespace

#endif // OHOS_IPC_TAIHE_MESSAGE_SEQUENCE_H
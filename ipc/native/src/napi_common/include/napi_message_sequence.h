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

#ifndef NAPI_IPC_OHOS_MESSAGE_SEQUENCE_H
#define NAPI_IPC_OHOS_MESSAGE_SEQUENCE_H

#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_rpc_error.h"
#include "securec.h"

namespace OHOS {
class NAPI_MessageSequence {
public:
    NAPI_MessageSequence(napi_env env, napi_value thisVar, MessageParcel *parcel);
    virtual ~NAPI_MessageSequence();
    std::shared_ptr<MessageParcel> GetMessageParcel();
    static napi_value Export(napi_env env, napi_value exports);
private:
    // Napi methods and properties
    static napi_value JS_create(napi_env env, napi_callback_info info);
    static napi_value JS_reclaim(napi_env env, napi_callback_info info);
    static napi_value JS_writeRemoteObject(napi_env env, napi_callback_info info);
    static napi_value JS_readRemoteObject(napi_env env, napi_callback_info info);
    static napi_value JS_writeInterfaceToken(napi_env env, napi_callback_info info);
    static napi_value JS_readInterfaceToken(napi_env env, napi_callback_info info);
    static napi_value JS_getSize(napi_env env, napi_callback_info info);
    static napi_value JS_getCapacity(napi_env env, napi_callback_info info);
    static napi_value JS_setSize(napi_env env, napi_callback_info info);
    static napi_value JS_setCapacity(napi_env env, napi_callback_info info);
    static napi_value JS_getWritableBytes(napi_env env, napi_callback_info info);
    static napi_value JS_getReadableBytes(napi_env env, napi_callback_info info);
    static napi_value JS_getReadPosition(napi_env env, napi_callback_info info);
    static napi_value JS_getWritePosition(napi_env env, napi_callback_info info);
    static napi_value JS_rewindWrite(napi_env env, napi_callback_info info);
    static napi_value JS_rewindRead(napi_env env, napi_callback_info info);
    static napi_value JS_writeNoException(napi_env env, napi_callback_info info);
    static napi_value JS_readException(napi_env env, napi_callback_info info);

    static napi_value JS_writeByte(napi_env env, napi_callback_info info);
    static napi_value JS_writeShort(napi_env env, napi_callback_info info);
    static napi_value JS_writeInt(napi_env env, napi_callback_info info);
    static napi_value JS_writeLong(napi_env env, napi_callback_info info);
    static napi_value JS_writeFloat(napi_env env, napi_callback_info info);
    static napi_value JS_writeDouble(napi_env env, napi_callback_info info);
    static napi_value JS_writeBoolean(napi_env env, napi_callback_info info);
    static napi_value JS_writeChar(napi_env env, napi_callback_info info);
    static napi_value JS_writeString(napi_env env, napi_callback_info info);
    static napi_value JS_writeParcelable(napi_env env, napi_callback_info info);
    static napi_value JS_writeByteArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeShortArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeIntArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeLongArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeFloatArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeDoubleArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeBooleanArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeCharArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeStringArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeParcelableArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeRemoteObjectArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeArrayBuffer(napi_env env, napi_callback_info info);

    static napi_value JS_readByte(napi_env env, napi_callback_info info);
    static napi_value JS_readShort(napi_env env, napi_callback_info info);
    static napi_value JS_readInt(napi_env env, napi_callback_info info);
    static napi_value JS_readLong(napi_env env, napi_callback_info info);
    static napi_value JS_readFloat(napi_env env, napi_callback_info info);
    static napi_value JS_readDouble(napi_env env, napi_callback_info info);
    static napi_value JS_readBoolean(napi_env env, napi_callback_info info);
    static napi_value JS_readChar(napi_env env, napi_callback_info info);
    static napi_value JS_readString(napi_env env, napi_callback_info info);
    static napi_value JS_readParcelable(napi_env env, napi_callback_info info);
    static napi_value JS_readByteArray(napi_env env, napi_callback_info info);
    static napi_value JS_readShortArray(napi_env env, napi_callback_info info);
    static napi_value JS_readIntArray(napi_env env, napi_callback_info info);
    static napi_value JS_readLongArray(napi_env env, napi_callback_info info);
    static napi_value JS_readFloatArray(napi_env env, napi_callback_info info);
    static napi_value JS_readDoubleArray(napi_env env, napi_callback_info info);
    static napi_value JS_readBooleanArray(napi_env env, napi_callback_info info);
    static napi_value JS_readCharArray(napi_env env, napi_callback_info info);
    static napi_value JS_readStringArray(napi_env env, napi_callback_info info);
    static napi_value JS_readParcelableArray(napi_env env, napi_callback_info info);
    static napi_value JS_readRemoteObjectArray(napi_env env, napi_callback_info info);
    static napi_value JS_readArrayBuffer(napi_env env, napi_callback_info info);

    static napi_value JS_CloseFileDescriptor(napi_env env, napi_callback_info info);
    static napi_value JS_DupFileDescriptor(napi_env env, napi_callback_info info);
    static napi_value JS_WriteFileDescriptor(napi_env env, napi_callback_info info);
    static napi_value JS_ReadFileDescriptor(napi_env env, napi_callback_info info);
    static napi_value JS_ContainFileDescriptors(napi_env env, napi_callback_info info);
    static napi_value JS_WriteAshmem(napi_env env, napi_callback_info info);
    static napi_value JS_ReadAshmem(napi_env env, napi_callback_info info);
    static napi_value JS_GetRawDataCapacity(napi_env env, napi_callback_info info);
    static napi_value JS_WriteRawData(napi_env env, napi_callback_info info);
    static napi_value JS_ReadRawData(napi_env env, napi_callback_info info);
    static napi_value JS_WriteRawDataBuffer(napi_env env, napi_callback_info info);
    static napi_value JS_ReadRawDataBuffer(napi_env env, napi_callback_info info);

    static napi_value JS_constructor(napi_env env, napi_callback_info info);
    static void release(MessageParcel *parcel);

    static napi_value JS_checkWriteArrayArgs(napi_env env, size_t argc, napi_value* argv, uint32_t &arrayLength);
    static napi_value JS_checkWriteStringArrayElement(napi_env env, napi_value* argv, size_t &index,
                                                      size_t &bufferSize, napi_value &element);
    static napi_value JS_writeParcelableArrayCallJsFunc(napi_env env, napi_value &element, napi_value &thisVar);
    static napi_value JS_checkReadArrayArgs(napi_env env, napi_callback_info info, size_t &argc,
                                            napi_value &thisVar, napi_value* argv);
    static napi_value JS_readParcelableArrayCallJsFunc(napi_env env, napi_value &element, napi_value &thisVar);
    static napi_value JS_checkWriteRawDataArgs(napi_env env, size_t argc, napi_value* argv);
    static bool JS_WriteRawDataForArray(napi_env env, napi_value jsArray,
                                        uint32_t size, NAPI_MessageSequence *napiSequence);
    static bool JS_WriteRawDataForTypedArray(napi_env env, napi_value jsTypedArray,
                                             size_t size, NAPI_MessageSequence *napiSequence);
    static napi_value JS_checkWriteArrayBufferArgs(napi_env env, size_t argc, napi_value* argv);
    static bool JS_writeVectorByTypeCode(int32_t typeCode, void *data,
                                         size_t byteLength, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readVectorByTypeCode(napi_env env, int32_t typeCode, NAPI_MessageSequence *napiSequence);

    static napi_value JS_readInt8ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readUInt8ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readInt16ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readUInt16ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readInt32ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readUInt32ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readFloatArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readDoubleArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readInt64ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    static napi_value JS_readUInt64ArrayBuffer(napi_env env, NAPI_MessageSequence *napiSequence);
    template<typename T>
    static napi_value JS_CopyVectorToBuffer(napi_env env, std::vector<T> vector, size_t bufferSize);

    napi_env env_ = nullptr;
    bool owner;
    std::shared_ptr<MessageParcel> nativeParcel_ = nullptr;
    size_t maxCapacityToWrite_;

    static NapiError napiErr;
};
} // namespace OHOS
#endif //  NAPI_IPC_OHOS_MESSAGE_SEQUENCE_H

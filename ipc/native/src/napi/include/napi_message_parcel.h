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

#ifndef NAPI_IPC_OHOS_MESSAGE_PARCEL_H
#define NAPI_IPC_OHOS_MESSAGE_PARCEL_H

#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "securec.h"

namespace OHOS {
class NAPI_MessageParcel {
public:
    NAPI_MessageParcel(napi_env env, napi_value thisVar, MessageParcel *parcel);
    virtual ~NAPI_MessageParcel();
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
    static napi_value JS_writeSequenceable(napi_env env, napi_callback_info info);
    static napi_value JS_writeByteArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeShortArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeIntArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeLongArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeFloatArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeDoubleArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeBooleanArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeCharArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeStringArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeSequenceableArray(napi_env env, napi_callback_info info);
    static napi_value JS_writeRemoteObjectArray(napi_env env, napi_callback_info info);

    static napi_value JS_readByte(napi_env env, napi_callback_info info);
    static napi_value JS_readShort(napi_env env, napi_callback_info info);
    static napi_value JS_readInt(napi_env env, napi_callback_info info);
    static napi_value JS_readLong(napi_env env, napi_callback_info info);
    static napi_value JS_readFloat(napi_env env, napi_callback_info info);
    static napi_value JS_readDouble(napi_env env, napi_callback_info info);
    static napi_value JS_readBoolean(napi_env env, napi_callback_info info);
    static napi_value JS_readChar(napi_env env, napi_callback_info info);
    static napi_value JS_readString(napi_env env, napi_callback_info info);
    static napi_value JS_readSequenceable(napi_env env, napi_callback_info info);
    static napi_value JS_readByteArray(napi_env env, napi_callback_info info);
    static napi_value JS_readShortArray(napi_env env, napi_callback_info info);
    static napi_value JS_readIntArray(napi_env env, napi_callback_info info);
    static napi_value JS_readLongArray(napi_env env, napi_callback_info info);
    static napi_value JS_readFloatArray(napi_env env, napi_callback_info info);
    static napi_value JS_readDoubleArray(napi_env env, napi_callback_info info);
    static napi_value JS_readBooleanArray(napi_env env, napi_callback_info info);
    static napi_value JS_readCharArray(napi_env env, napi_callback_info info);
    static napi_value JS_readStringArray(napi_env env, napi_callback_info info);
    static napi_value JS_readSequenceableArray(napi_env env, napi_callback_info info);
    static napi_value JS_readRemoteObjectArray(napi_env env, napi_callback_info info);

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

    static napi_value JS_constructor(napi_env env, napi_callback_info info);
    static void release(MessageParcel *parcel);

    napi_env env_ = nullptr;
    bool owner;
    std::shared_ptr<MessageParcel> nativeParcel_ = nullptr;
    size_t maxCapacityToWrite_;
};
} // namespace OHOS
#endif //  NAPI_IPC_OHOS_MESSAGE_PARCEL_H

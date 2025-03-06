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
#ifndef IPC_FFI_H
#define IPC_FFI_H

#include "ashmem_impl.h"
#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "message_sequence_impl.h"
#include "napi/native_api.h"

extern "C" {
FFI_EXPORT int64_t FfiRpcMessageSequenceImplCreate();
FFI_EXPORT void FfiRpcMessageSequenceImplWriteInterfaceToken(int64_t id, char* token, int32_t* errCode);
FFI_EXPORT char* FfiRpcMessageSequenceImplReadInterfaceToken(int64_t id, int32_t* errCode);
FFI_EXPORT uint32_t FfiRpcMessageSequenceImplGetSize(int64_t id, int32_t* errCode);
FFI_EXPORT uint32_t FfiRpcMessageSequenceImplGetCapacity(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplSetSize(int64_t id, uint32_t value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplSetCapacity(int64_t id, uint32_t value, int32_t* errCode);
FFI_EXPORT uint32_t FfiRpcMessageSequenceImplGetWritableBytes(int64_t id, int32_t* errCode);
FFI_EXPORT uint32_t FfiRpcMessageSequenceImplGetReadableBytes(int64_t id, int32_t* errCode);
FFI_EXPORT uint32_t FfiRpcMessageSequenceImplGetReadPosition(int64_t id, int32_t* errCode);
FFI_EXPORT uint32_t FfiRpcMessageSequenceImplGetWritePosition(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplRewindWrite(int64_t id, uint32_t pos, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplRewindRead(int64_t id, uint32_t pos, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteNoException(int64_t id, int32_t* errCode);
FFI_EXPORT char* FfiRpcMessageSequenceImplReadException(int64_t id, int32_t* errCode);

FFI_EXPORT void FfiRpcMessageSequenceImplWriteByte(int64_t id, int8_t value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteShort(int64_t id, int16_t value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteInt(int64_t id, int32_t value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteLong(int64_t id, int64_t value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteFloat(int64_t id, double value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteDouble(int64_t id, double value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteBoolean(int64_t id, int8_t value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteChar(int64_t id, uint8_t value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteString(int64_t id, char* value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteByteArray(int64_t id, OHOS::CJByteArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteShortArray(int64_t id, OHOS::CJShortArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteIntArray(int64_t id, OHOS::CJIntArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteLongArray(int64_t id, OHOS::CJLongArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteFloatArray(int64_t id, OHOS::CJDoubleArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteDoubleArray(int64_t id, OHOS::CJDoubleArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteBooleanArray(int64_t id, OHOS::CJByteArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteCharArray(int64_t id, OHOS::CJCharArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteStringArray(int64_t id, OHOS::CJStringArray value, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteArrayBuffer(
    int64_t id, int32_t typeCode, void* value, size_t byteLength, int32_t* errCode);
FFI_EXPORT bool FfiRpcMessageSequenceImplWriteUint32(int64_t id, uint32_t value);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteRawDataBuffer(int64_t id, uint8_t* data, int64_t size, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteRemoteObject(int64_t id, int64_t object, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteRemoteObjectArray(
    int64_t id, OHOS::CJLongArray value, int32_t* errCode);

FFI_EXPORT int8_t FfiRpcMessageSequenceImplReadByte(int64_t id, int32_t* errCode);
FFI_EXPORT int16_t FfiRpcMessageSequenceImplReadShort(int64_t id, int32_t* errCode);
FFI_EXPORT int32_t FfiRpcMessageSequenceImplReadInt(int64_t id, int32_t* errCode);
FFI_EXPORT int64_t FfiRpcMessageSequenceImplReadLong(int64_t id, int32_t* errCode);
FFI_EXPORT double FfiRpcMessageSequenceImplReadFloat(int64_t id, int32_t* errCode);
FFI_EXPORT double FfiRpcMessageSequenceImplReadDouble(int64_t id, int32_t* errCode);
FFI_EXPORT int8_t FfiRpcMessageSequenceImplReadBoolean(int64_t id, int32_t* errCode);
FFI_EXPORT uint8_t FfiRpcMessageSequenceImplReadChar(int64_t id, int32_t* errCode);
FFI_EXPORT char* FfiRpcMessageSequenceImplReadString(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJByteArray FfiRpcMessageSequenceImplReadByteArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJShortArray FfiRpcMessageSequenceImplReadShortArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJIntArray FfiRpcMessageSequenceImplReadIntArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJLongArray FfiRpcMessageSequenceImplReadLongArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJDoubleArray FfiRpcMessageSequenceImplReadFloatArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJDoubleArray FfiRpcMessageSequenceImplReadDoubleArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJByteArray FfiRpcMessageSequenceImplReadBooleanArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJCharArray FfiRpcMessageSequenceImplReadCharArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJStringArray FfiRpcMessageSequenceImplReadStringArray(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJByteArray FfiRpcMessageSequenceImplReadInt8ArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJCharArray FfiRpcMessageSequenceImplReadUInt8ArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJShortArray FfiRpcMessageSequenceImplReadInt16ArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJUInt16Array FfiRpcMessageSequenceImplReadUInt16ArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJIntArray FfiRpcMessageSequenceImplReadInt32ArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJUInt32Array FfiRpcMessageSequenceImplReadUInt32ArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJFloatArray FfiRpcMessageSequenceImplReadFloatArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJDoubleArray FfiRpcMessageSequenceImplReadDoubleArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJLongArray FfiRpcMessageSequenceImplReadInt64ArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::CJUInt64Array FfiRpcMessageSequenceImplReadUInt64ArrayBuffer(int64_t id, int32_t* errCode);
FFI_EXPORT uint8_t* FfiRpcMessageSequenceImplReadRawDataBuffer(int64_t id, int64_t size, int32_t* errCode);
FFI_EXPORT RetDataI64 FfiRpcMessageSequenceImplReadRemoteObject(int64_t id, int32_t* errCode);
FFI_EXPORT OHOS::RemoteObjectArray FfiRpcMessageSequenceImplReadRemoteObjectArray(int64_t id, int32_t* errCode);

FFI_EXPORT void FfiRpcMessageSequenceImplCloseFileDescriptor(int32_t fd);
FFI_EXPORT int32_t FfiRpcMessageSequenceImplDupFileDescriptor(int32_t fd);
FFI_EXPORT bool FfiRpcMessageSequenceImplContainFileDescriptors(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteFileDescriptor(int64_t id, int32_t fd, int32_t* errCode);
FFI_EXPORT int32_t FfiRpcMessageSequenceImplReadFileDescriptor(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcMessageSequenceImplWriteAshmem(int64_t mid, int64_t aid, int32_t* errCode);
FFI_EXPORT int64_t FfiRpcMessageSequenceImplReadAshmem(int64_t id, int32_t* errCode);
FFI_EXPORT uint32_t FfiRpcMessageSequenceImplGetRawDataCapacity(int64_t id, int32_t* errCode);

FFI_EXPORT int64_t FfiRpcAshmemImplCreate(char* ashmemName, int32_t ashmemSize);
FFI_EXPORT int64_t FfiRpcAshmemImplCreateFromExisting(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcAshmemImplCloseAshmem(int64_t id);
FFI_EXPORT void FfiRpcAshmemImplUnmapAshmem(int64_t id);
FFI_EXPORT int32_t FfiRpcAshmemImplGetAshmemSize(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcAshmemImplMapTypedAshmem(int64_t id, uint32_t mapType, int32_t* errCode);
FFI_EXPORT void FfiRpcAshmemImplMapReadWriteAshmem(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcAshmemImplMapReadonlyAshmem(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcAshmemImplSetProtectionType(int64_t id, uint32_t protectionType, int32_t* errCode);
FFI_EXPORT void FfiRpcAshmemImplWriteDataToAshmem(
    int64_t id, uint8_t* data, int64_t size, int64_t offset, int32_t* errCode);
FFI_EXPORT uint8_t* FfiRpcAshmemImplReadDataFromAshmem(int64_t id, int64_t size, int64_t offset, int32_t* errCode);

FFI_EXPORT int64_t FfiRpcRemoteObjectConstructor(char* stringValue);
FFI_EXPORT int32_t FfiRpcRemoteObjectSendMessageRequest(
    int64_t id, uint32_t code, int64_t dataId, int64_t replyId, OHOS::MesOption opt, int64_t funcId);
FFI_EXPORT int32_t FfiRpcRemoteObjectGetCallingPid();
FFI_EXPORT int32_t FfiRpcRemoteObjectGetCallingUid();
FFI_EXPORT char* FfiRpcRemoteObjectGetDescriptor(int64_t id, int32_t* errCode);
FFI_EXPORT void FfiRpcRemoteObjectModifyLocalInterface(int64_t id, char* stringValue, int32_t* errCode);

FFI_EXPORT RetDataI64 FfiRpcIPCSkeletonGetContextObject();
FFI_EXPORT int32_t FfiRpcIPCSkeletonGetCallingPid();
FFI_EXPORT int32_t FfiRpcIPCSkeletonGetCallingUid();
FFI_EXPORT uint32_t FfiRpcIPCSkeletonGetCallingTokenId();
FFI_EXPORT char* FfiRpcIPCSkeletonGetCallingDeviceID();
FFI_EXPORT char* FfiRpcIPCSkeletonGetLocalDeviceID();
FFI_EXPORT bool FfiRpcIPCSkeletonIsLocalCalling();
FFI_EXPORT void FfiRpcIPCSkeletonFlushCmdBuffer(int64_t object);

FFI_EXPORT int32_t FfiRpcRemoteProxySendMessageRequest(
    int64_t id, uint32_t code, int64_t dataId, int64_t replyId, OHOS::MesOption opt, int64_t funcId);
FFI_EXPORT void FfiRpcRemoteProxyRegisterDeathRecipient(int64_t id, int64_t funcId, int32_t flag, int32_t* errCode);
FFI_EXPORT void FfiRpcRemoteProxyUnregisterDeathRecipient(int64_t id, int64_t funcId, int32_t flag, int32_t* errCode);
FFI_EXPORT char* FfiRpcRemoteProxyGetDescriptor(int64_t id, int32_t* errCode);
FFI_EXPORT bool FfiRpcRemoteProxyIsObjectDead(int64_t id);

FFI_EXPORT int32_t FfiRpcGetRemoteType(int64_t id);
FFI_EXPORT int64_t FfiCreateRemoteObjectFromNapi(napi_env env, napi_value object);
FFI_EXPORT napi_value FfiConvertRemoteObject2Napi(napi_env env, int64_t object);
}

#endif

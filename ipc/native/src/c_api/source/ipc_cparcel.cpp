/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ipc_cparcel.h"
#include "ipc_error_code.h"
#include "message_parcel.h"
#include "log_tags.h"
#include "ipc_debug.h"
#include "ipc_internal_utils.h"
#include "ipc_inner_object.h"

#include <securec.h>

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_CAPI, "OHIPCParcel" };

OHIPCParcel* OH_IPCParcel_Create(void)
{
    OHOS::MessageParcel *msgParcel = new (std::nothrow) OHOS::MessageParcel();
    if (msgParcel == nullptr) {
        ZLOGE(LOG_LABEL, "message parcel is null!");
        return nullptr;
    }
    OHIPCParcel *parcel = new (std::nothrow) OHIPCParcel();
    if (parcel == nullptr) {
        ZLOGE(LOG_LABEL, "ipc parcel is null!");
        delete msgParcel;
        return nullptr;
    }
    parcel->msgParcel = msgParcel;
    return parcel;
}

void OH_IPCParcel_Destroy(OHIPCParcel *parcel)
{
    if (parcel != nullptr) {
        if (parcel->msgParcel != nullptr) {
            delete parcel->msgParcel;
            parcel->msgParcel = nullptr;
        }
        delete parcel;
    }
}

template <typename T, typename U>
static int SetParcelProperty(OHIPCParcel *parcel, T value, bool (OHOS::MessageParcel::*SetProperty)(U value))
{
    if (!IsIPCParcelValid(parcel, __func__)) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    return (parcel->msgParcel->*SetProperty)(static_cast<U>(value)) ? OH_IPC_SUCCESS
        : OH_IPC_INNER_ERROR;
}

template <typename T, typename U>
static T GetParcelPropertyConst(const OHIPCParcel *parcel, U (OHOS::MessageParcel::*GetProperty)() const)
{
    if (!IsIPCParcelValid(parcel, __func__)) {
        return -1;
    }
    return static_cast<T>((parcel->msgParcel->*GetProperty)());
}

template <typename T, typename U>
static T GetParcelProperty(const OHIPCParcel *parcel, U (OHOS::MessageParcel::*GetProperty)())
{
    if (!IsIPCParcelValid(parcel, __func__)) {
        return -1;
    }
    return static_cast<T>((parcel->msgParcel->*GetProperty)());
}

int OH_IPCParcel_GetDataSize(const OHIPCParcel *parcel)
{
    return GetParcelPropertyConst<int, size_t>(parcel, &OHOS::MessageParcel::GetDataSize);
}

int OH_IPCParcel_GetWritableBytes(const OHIPCParcel *parcel)
{
    return GetParcelPropertyConst<int, size_t>(parcel, &OHOS::MessageParcel::GetWritableBytes);
}

int OH_IPCParcel_GetReadableBytes(const OHIPCParcel *parcel)
{
    return GetParcelPropertyConst<int, size_t>(parcel, &OHOS::MessageParcel::GetReadableBytes);
}

int OH_IPCParcel_GetReadPosition(const OHIPCParcel *parcel)
{
    return GetParcelProperty<int, size_t>(parcel, &OHOS::MessageParcel::GetReadPosition);
}

int OH_IPCParcel_GetWritePosition(const OHIPCParcel *parcel)
{
    return GetParcelProperty<int, size_t>(parcel, &OHOS::MessageParcel::GetWritePosition);
}

int OH_IPCParcel_RewindReadPosition(OHIPCParcel *parcel, uint32_t newReadPos)
{
    return SetParcelProperty<uint32_t, size_t>(parcel, newReadPos, &OHOS::MessageParcel::RewindRead);
}

int OH_IPCParcel_RewindWritePosition(OHIPCParcel *parcel, uint32_t newWritePos)
{
    return SetParcelProperty<uint32_t, size_t>(parcel, newWritePos, &OHOS::MessageParcel::RewindWrite);
}

template <typename T>
static int WriteValue(OHIPCParcel *parcel, T value, bool (OHOS::MessageParcel::*Write)(T value))
{
    if (!IsIPCParcelValid(parcel, __func__)) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    return (parcel->msgParcel->*Write)(value) ? OH_IPC_SUCCESS : OH_IPC_PARCEL_WRITE_ERROR;
}

template <typename T>
static int ReadValue(const OHIPCParcel *parcel, T* value, bool (OHOS::MessageParcel::*Read)(T& value))
{
    if (!IsIPCParcelValid(parcel, __func__) || value == nullptr) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    return (parcel->msgParcel->*Read)(*value) ? OH_IPC_SUCCESS : OH_IPC_PARCEL_READ_ERROR;
}

int OH_IPCParcel_WriteInt8(OHIPCParcel *parcel, int8_t value)
{
    return WriteValue<int8_t>(parcel, value, &OHOS::MessageParcel::WriteInt8);
}

int OH_IPCParcel_ReadInt8(const OHIPCParcel *parcel, int8_t *value)
{
    return ReadValue<int8_t>(parcel, value, &OHOS::MessageParcel::ReadInt8);
}

int OH_IPCParcel_WriteInt16(OHIPCParcel *parcel, int16_t value)
{
    return WriteValue<int16_t>(parcel, value, &OHOS::MessageParcel::WriteInt16);
}

int OH_IPCParcel_ReadInt16(const OHIPCParcel *parcel, int16_t *value)
{
    return ReadValue<int16_t>(parcel, value, &OHOS::MessageParcel::ReadInt16);
}

int OH_IPCParcel_WriteInt32(OHIPCParcel *parcel, int32_t value)
{
    return WriteValue<int32_t>(parcel, value, &OHOS::MessageParcel::WriteInt32);
}

int OH_IPCParcel_ReadInt32(const OHIPCParcel *parcel, int32_t *value)
{
    return ReadValue<int32_t>(parcel, value, &OHOS::MessageParcel::ReadInt32);
}

int OH_IPCParcel_WriteInt64(OHIPCParcel *parcel, int64_t value)
{
    return WriteValue<int64_t>(parcel, value, &OHOS::MessageParcel::WriteInt64);
}

int OH_IPCParcel_ReadInt64(const OHIPCParcel *parcel, int64_t *value)
{
    return ReadValue<int64_t>(parcel, value, &OHOS::MessageParcel::ReadInt64);
}

int OH_IPCParcel_WriteFloat(OHIPCParcel *parcel, float value)
{
    return WriteValue<float>(parcel, value, &OHOS::MessageParcel::WriteFloat);
}

int OH_IPCParcel_ReadFloat(const OHIPCParcel *parcel, float *value)
{
    return ReadValue<float>(parcel, value, &OHOS::MessageParcel::ReadFloat);
}

int OH_IPCParcel_WriteDouble(OHIPCParcel *parcel, double value)
{
    return WriteValue<double>(parcel, value, &OHOS::MessageParcel::WriteDouble);
}

int OH_IPCParcel_ReadDouble(const OHIPCParcel *parcel, double *value)
{
    return ReadValue<double>(parcel, value, &OHOS::MessageParcel::ReadDouble);
}

int OH_IPCParcel_WriteString(OHIPCParcel *parcel, const char *str)
{
    if (!IsIPCParcelValid(parcel, __func__) || str == nullptr) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    return parcel->msgParcel->WriteCString(str) ? OH_IPC_SUCCESS : OH_IPC_PARCEL_WRITE_ERROR;
}

const char* OH_IPCParcel_ReadString(const OHIPCParcel *parcel)
{
    if (!IsIPCParcelValid(parcel, __func__)) {
        return nullptr;
    }

    return parcel->msgParcel->ReadCString();
}

int OH_IPCParcel_WriteBuffer(OHIPCParcel *parcel, const uint8_t *buffer, int32_t len)
{
    if (!IsIPCParcelValid(parcel, __func__) || buffer == nullptr || len <= 0) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    size_t writePosition = parcel->msgParcel->GetWritePosition();
    if (!parcel->msgParcel->WriteBuffer(buffer, len)) {
        ZLOGE(LOG_LABEL, "write buffer failed! buffer len:%{public}d", len);
        parcel->msgParcel->RewindWrite(writePosition);
        return OH_IPC_PARCEL_WRITE_ERROR;
    }
    return OH_IPC_SUCCESS;
}

const uint8_t* OH_IPCParcel_ReadBuffer(const OHIPCParcel *parcel, int32_t len)
{
    if (!IsIPCParcelValid(parcel, __func__)) {
        return nullptr;
    }
    int readableBytes = static_cast<int>(parcel->msgParcel->GetReadableBytes());
    if (len <= 0 || len > readableBytes) {
        ZLOGE(LOG_LABEL, "read buf len:%{public}d invalid! ReadableBytes:%{public}d", len, readableBytes);
        return nullptr;
    }

    return parcel->msgParcel->ReadBuffer(len);
}

template <typename T>
static int WriteIPCRemoteObject(OHIPCParcel *parcel, const T *object)
{
    if (!IsIPCParcelValid(parcel, __func__) || object == nullptr) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    if (!parcel->msgParcel->WriteRemoteObject(object->remote)) {
        ZLOGE(LOG_LABEL, "write remote object failed!");
        return OH_IPC_PARCEL_WRITE_ERROR;
    }
    return OH_IPC_SUCCESS;
}

template <typename T>
static T* ReadIPCRemoteObject(const OHIPCParcel *parcel)
{
    if (!IsIPCParcelValid(parcel, __func__)) {
        return nullptr;
    }
    OHOS::sptr<OHOS::IRemoteObject> object = parcel->msgParcel->ReadRemoteObject();
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "read remote object failed!");
        return nullptr;
    }
    T *remoteObject = new (std::nothrow) T();
    if (remoteObject == nullptr) {
        ZLOGE(LOG_LABEL, "new remote object failed");
        return nullptr;
    }
    remoteObject->remote = object;
    return remoteObject;
}

int OH_IPCParcel_WriteRemoteStub(OHIPCParcel *parcel, const OHIPCRemoteStub *stub)
{
    return WriteIPCRemoteObject(parcel, stub);
}

OHIPCRemoteStub* OH_IPCParcel_ReadRemoteStub(const OHIPCParcel *parcel)
{
    return ReadIPCRemoteObject<OHIPCRemoteStub>(parcel);
}

int OH_IPCParcel_WriteRemoteProxy(OHIPCParcel *parcel, const OHIPCRemoteProxy *proxy)
{
    return WriteIPCRemoteObject(parcel, proxy);
}

OHIPCRemoteProxy* OH_IPCParcel_ReadRemoteProxy(const OHIPCParcel *parcel)
{
    return ReadIPCRemoteObject<OHIPCRemoteProxy>(parcel);
}

int OH_IPCParcel_WriteFileDescriptor(OHIPCParcel *parcel, int32_t fd)
{
    return WriteValue<int32_t>(parcel, fd, &OHOS::MessageParcel::WriteFileDescriptor);
}

int OH_IPCParcel_ReadFileDescriptor(const OHIPCParcel *parcel, int32_t *fd)
{
    if (!IsIPCParcelValid(parcel, __func__) || fd == nullptr) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    int tmpFd = parcel->msgParcel->ReadFileDescriptor();
    if (tmpFd == -1) {
        ZLOGE(LOG_LABEL, "read file descriptor failed!");
        return OH_IPC_PARCEL_READ_ERROR;
    }
    *fd = tmpFd;
    return OH_IPC_SUCCESS;
}

int OH_IPCParcel_Append(OHIPCParcel *parcel, const OHIPCParcel *data)
{
    if (!IsIPCParcelValid(parcel, __func__)
        || !IsIPCParcelValid(data, __func__)) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    return parcel->msgParcel->Append(*(data->msgParcel)) ? OH_IPC_SUCCESS : OH_IPC_PARCEL_WRITE_ERROR;
}

int OH_IPCParcel_WriteInterfaceToken(OHIPCParcel *parcel, const char *token)
{
    if (!IsIPCParcelValid(parcel, __func__) || token == nullptr) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    int tokenLen = strlen(token);
    if (tokenLen == 0 || tokenLen > MAX_PARCEL_LEN) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    std::u16string u16Token = OHOS::Str8ToStr16(std::string(token, tokenLen));
    if (u16Token.length() == 0 && tokenLen != 0) {
        ZLOGE(LOG_LABEL, "convert token to u16string failed: %{public}d", tokenLen);
        return OH_IPC_PARCEL_WRITE_ERROR;
    }
    size_t writePosition = parcel->msgParcel->GetWritePosition();
    if (!parcel->msgParcel->WriteInterfaceToken(u16Token)) {
        ZLOGE(LOG_LABEL, "WriteInterfaceToken failed! token len:%{public}d", tokenLen);
        parcel->msgParcel->RewindWrite(writePosition);
        return OH_IPC_PARCEL_WRITE_ERROR;
    }
    return OH_IPC_SUCCESS;
}

int OH_IPCParcel_ReadInterfaceToken(const OHIPCParcel *parcel, char **token, int32_t *len,
    OH_IPC_MemAllocator allocator)
{
    if (!IsIPCParcelValid(parcel, __func__) || !IsMemoryParamsValid(token, len, allocator, __func__)) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    size_t readPosition = parcel->msgParcel->GetReadPosition();
    std::u16string u16Token = parcel->msgParcel->ReadInterfaceToken();
    std::string strToken = OHOS::Str16ToStr8(u16Token);
    if (u16Token.length() != 0 && strToken.length() == 0) {
        parcel->msgParcel->RewindRead(readPosition);
        ZLOGE(LOG_LABEL, "Str16ToStr8 failed! u16Token len: %{public}u, string len: %{public}u",
            static_cast<uint32_t>(u16Token.length()), static_cast<uint32_t>(strToken.length()));
        return OH_IPC_PARCEL_READ_ERROR;
    }

    int memLength = static_cast<int>(strToken.length()) + 1;
    *token = static_cast<char*>(allocator(memLength));
    if (*token == nullptr) {
        parcel->msgParcel->RewindRead(readPosition);
        ZLOGE(LOG_LABEL, "memory allocator failed!");
        return OH_IPC_MEM_ALLOCATOR_ERROR;
    }
    if (memcpy_s(*token, memLength, strToken.c_str(), memLength) != EOK) {
        parcel->msgParcel->RewindRead(readPosition);
        ZLOGE(LOG_LABEL, "memcpy string failed, string len: %{public}d", memLength);
        return OH_IPC_PARCEL_READ_ERROR;
    }
    *len = memLength;
    return OH_IPC_SUCCESS;
}

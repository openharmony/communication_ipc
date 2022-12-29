/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "c_parcel_internal.h"

#include <securec.h>
#include <string_ex.h>
#include "c_remote_object_internal.h"

using namespace OHOS;

MessageParcelHolder::MessageParcelHolder(OHOS::MessageParcel *parcel)
    : isExternal_(true)
{
    if (parcel == nullptr) {
        parcel_ = new (std::nothrow) MessageParcel();
        isExternal_ = false;
    } else {
        parcel_ = parcel;
    }
}

MessageParcelHolder::~MessageParcelHolder(void)
{
    if (!isExternal_ && parcel_ != nullptr) {
        delete parcel_;
    }
}

static bool IsValidParcel(const CParcel *parcel, const char *promot)
{
    if (parcel == nullptr) {
        printf("%s: parcel is null\n", promot);
        return false;
    }
    if (parcel->parcel_ == nullptr) {
        printf("%s: wrapper parcel is null\n", promot);
        return false;
    }
    return true;
}

CParcel *CParcelObtain(void)
{
    CParcel *holder = new (std::nothrow) MessageParcelHolder();
    if (holder == nullptr) {
        printf("%s: malloc messsage parcel holder failed\n", __func__);
        return nullptr;
    }
    holder->IncStrongRef(nullptr);
    return holder;
}

void CParcelIncStrongRef(CParcel *parcel)
{
    if (parcel == nullptr) {
        printf("%s: parcel is nullptr\n", __func__);
        return;
    }
    parcel->IncStrongRef(nullptr);
}

void CParcelDecStrongRef(CParcel *parcel)
{
    if (parcel == nullptr) {
        printf("%s: parcel is nullptr\n", __func__);
        return;
    }
    parcel->DecStrongRef(nullptr);
}

bool CParcelWriteBool(CParcel *parcel, bool value)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteBool(value);
}

bool CParcelReadBool(const CParcel *parcel, bool *value)
{
    if (!IsValidParcel(parcel, __func__) || value == nullptr) {
        return false;
    }
    return parcel->parcel_->ReadBool(*value);
}

bool CParcelWriteInt8(CParcel *parcel, int8_t value)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteInt8(value);
}

bool CParcelReadInt8(const CParcel *parcel, int8_t *value)
{
    if (!IsValidParcel(parcel, __func__) || value == nullptr) {
        return false;
    }
    return parcel->parcel_->ReadInt8(*value);
}

bool CParcelWriteInt16(CParcel *parcel, int16_t value)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteInt16(value);
}

bool CParcelReadInt16(const CParcel *parcel, int16_t *value)
{
    if (!IsValidParcel(parcel, __func__) || value == nullptr) {
        return false;
    }
    return parcel->parcel_->ReadInt16(*value);
}

bool CParcelWriteInt32(CParcel *parcel, int32_t value)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteInt32(value);
}

bool CParcelReadInt32(const CParcel *parcel, int32_t *value)
{
    if (!IsValidParcel(parcel, __func__) || value == nullptr) {
        return false;
    }
    return parcel->parcel_->ReadInt32(*value);
}

bool CParcelWriteInt64(CParcel *parcel, int64_t value)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteInt64(value);
}

bool CParcelReadInt64(const CParcel *parcel, int64_t *value)
{
    if (!IsValidParcel(parcel, __func__) || value == nullptr) {
        return false;
    }
    return parcel->parcel_->ReadInt64(*value);
}

bool CParcelWriteFloat(CParcel *parcel, float value)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteFloat(value);
}

bool CParcelReadFloat(const CParcel *parcel, float *value)
{
    if (!IsValidParcel(parcel, __func__) || value == nullptr) {
        return false;
    }
    return parcel->parcel_->ReadFloat(*value);
}

bool CParcelWriteDouble(CParcel *parcel, double value)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteDouble(value);
}

bool CParcelReadDouble(const CParcel *parcel, double *value)
{
    if (!IsValidParcel(parcel, __func__) || value == nullptr) {
        return false;
    }
    return parcel->parcel_->ReadDouble(*value);
}

bool CParcelWriteString(CParcel *parcel, const char *stringData, int32_t length)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    if (stringData == nullptr) {
        if (length != -1) {
            printf("%s: stringData is null, len: %d\n", __func__, length);
            return false;
        }
        std::string value;
        return parcel->parcel_->WriteString(value);
    }
    if (length < 0) {
        printf("%s: stringData len is invalid: %d\n", __func__, length);
        return false;
    }
    std::string value(stringData, length);
    return parcel->parcel_->WriteString(value);
}

bool CParcelReadString(const CParcel *parcel, void *stringData, OnCParcelBytesAllocator allocator)
{
    if (!IsValidParcel(parcel, __func__) || allocator == nullptr) {
        return false;
    }
    std::string value;
    if (!parcel->parcel_->ReadString(value)) {
        printf("%s: read string from parcel failed\n", __func__);
        return false;
    }
    char *buffer = nullptr;
    bool isSuccess = allocator(stringData, &buffer, value.length());
    if (!isSuccess) {
        printf("%s: allocate string buffer is null\n", __func__);
        return false;
    }
    if (value.length() > 0 && memcpy_s(buffer, value.length(), value.data(), value.length()) != EOK) {
        printf("%s: memcpy string failed\n", __func__);
        return false;
    }
    return true;
}

bool CParcelWriteString16(CParcel *parcel, const char *str, int32_t strLen)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    if (str == nullptr) {
        if (strLen != -1) {
            printf("%s: str is null, len: %d\n", __func__, strLen);
            return false;
        }
        std::u16string value;
        return parcel->parcel_->WriteString16(value);
    }
    if (strLen < 0) {
        printf("%s: str len is invalid: %d\n", __func__, strLen);
        return false;
    }
    std::u16string u16string = Str8ToStr16(std::string(str, strLen));
    if (u16string.length() == 0 && strLen != 0) {
        printf("%s: convert u16string failed: %d\n", __func__, strLen);
        return false;
    }
    return parcel->parcel_->WriteString16(u16string);
}

bool CParcelReadString16(const CParcel *parcel, void *stringData, OnCParcelBytesAllocator allocator)
{
    if (!IsValidParcel(parcel, __func__) || allocator == nullptr) {
        return false;
    }
    std::u16string u16string;
    if (!parcel->parcel_->ReadString16(u16string)) {
        printf("%s: read u16string from parcel failed\n", __func__);
        return false;
    }
    std::string value = Str16ToStr8(u16string);
    if (u16string.length() != 0 && value.length() == 0) {
        printf("%s: u16string len: %lu, string len: %lu\n", __func__, u16string.length(), value.length());
        return false;
    }
    char *buffer = nullptr;
    bool isSuccess = allocator(stringData, &buffer, value.length());
    if (!isSuccess) {
        printf("%s: allocate string buffer is null\n", __func__);
        return false;
    }
    if (value.length() > 0 && memcpy_s(buffer, value.length(), value.data(), value.length()) != EOK) {
        printf("%s: memcpy string16 failed\n", __func__);
        return false;
    }
    return true;
}

bool CParcelWriteInterfaceToken(CParcel *parcel, const char *token, int32_t tokenLen)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    if (token == nullptr || tokenLen < 0) {
        printf("%s: token len is invalid: %d\n", __func__, tokenLen);
        return false;
    }
    std::u16string u16string = Str8ToStr16(std::string(token, tokenLen));
    if (u16string.length() == 0 && tokenLen != 0) {
        printf("%s: convert token to u16string failed: %d\n", __func__, tokenLen);
        return false;
    }
    return parcel->parcel_->WriteInterfaceToken(u16string);
}

bool CParcelReadInterfaceToken(const CParcel *parcel, void *token, OnCParcelBytesAllocator allocator)
{
    if (!IsValidParcel(parcel, __func__) || allocator == nullptr) {
        return false;
    }
    std::u16string u16string = parcel->parcel_->ReadInterfaceToken();
    std::string value = Str16ToStr8(u16string);
    if (u16string.length() != 0 && value.length() == 0) {
        printf("%s: u16string len: %lu, string len: %lu\n", __func__, u16string.length(), value.length());
        return false;
    }
    printf("%s: c read interface token: %s\n", __func__, value.c_str());
    char *buffer = nullptr;
    bool isSuccess = allocator(token, &buffer, value.length());
    if (!isSuccess) {
        printf("%s: allocate interface token buffer failed\n", __func__);
        return false;
    }
    if (value.length() > 0 && memcpy_s(buffer, value.length(), value.data(), value.length()) != EOK) {
        printf("%s: memcpy interface token failed\n", __func__);
        return false;
    }
    return true;
}

bool CParcelWriteRemoteObject(CParcel *parcel, const CRemoteObject *object)
{
    if (!IsValidParcel(parcel, __func__) || !IsValidRemoteObject(object, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteRemoteObject(object->remote_);
}

CRemoteObject *CParcelReadRemoteObject(const CParcel *parcel)
{
    if (!IsValidParcel(parcel, __func__)) {
        return nullptr;
    }
    sptr<IRemoteObject> remote = parcel->parcel_->ReadRemoteObject();
    if (remote == nullptr) {
        printf("%s: read remote object is null\n", __func__);
        return nullptr;
    }
    CRemoteObject *holder = nullptr;
    if (remote->IsProxyObject()) {
        holder = new (std::nothrow) CRemoteProxyHolder();
    } else {
        holder = new (std::nothrow) CRemoteStubHolder(nullptr, nullptr);
    }
    if (holder == nullptr) {
        printf("%s: craete remote object holder failed\n", __func__);
        return nullptr;
    }
    holder->remote_ = remote;
    holder->IncStrongRef(nullptr);
    return holder;
}

bool CParcelWriteFileDescriptor(CParcel *parcel, int32_t fd)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    return parcel->parcel_->WriteFileDescriptor(fd);
}

bool CParcelReadFileDescriptor(const CParcel *parcel, int32_t *fd)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    if (fd == nullptr) {
        printf("%s: fd is null\n", __func__);
        return false;
    }
    *fd = parcel->parcel_->ReadFileDescriptor();
    return (*fd < 0) ? false : true;
}

bool CParcelWriteBuffer(CParcel *parcel, const uint8_t *buffer, uint32_t len)
{
    if (!IsValidParcel(parcel, __func__)) {
        return false;
    }
    if (buffer == nullptr) {
        printf("%s: buffer is null: %d\n", __func__, len);
        return false;
    }
    return parcel->parcel_->WriteBuffer(buffer, len);
}

bool CParcelReadBuffer(const CParcel *parcel, uint8_t *value, uint32_t len)
{
    if (!IsValidParcel(parcel, __func__) || value == nullptr) {
        return false;
    }
    const uint8_t *data = parcel->parcel_->ReadBuffer(len);
    if (data == nullptr) {
        printf("%s: read buffer failed\n", __func__);
        return false;
    }
    if (len > 0 && memcpy_s(value, len, data, len) != EOK) {
        printf("%s: copy buffer failed\n", __func__);
        return false;
    }
    return true;
}

uint32_t CParcelGetDataSize(const CParcel *parcel)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->GetDataSize();
}

bool CParcelSetDataSize(CParcel *parcel, uint32_t new_size)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->SetDataSize(new_size);
}

uint32_t CParcelGetDataCapacity(const CParcel *parcel)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->GetDataCapacity();
}

bool CParcelSetDataCapacity(CParcel *parcel, uint32_t new_size)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->SetDataCapacity(new_size);
}

uint32_t CParcelGetMaxCapacity(const CParcel *parcel)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->GetMaxCapacity();
}

bool CParcelSetMaxCapacity(CParcel *parcel, uint32_t new_size)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->SetMaxCapacity(new_size);
}

uint32_t CParcelGetWritableBytes(const CParcel *parcel)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->GetWritableBytes();
}

uint32_t CParcelGetReadableBytes(const CParcel *parcel)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->GetReadableBytes();
}

uint32_t CParcelGetReadPosition(const CParcel *parcel)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->GetReadPosition();
}

uint32_t CParcelGetWritePosition(const CParcel *parcel)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->GetWritePosition();
}

bool CParcelRewindRead(CParcel *parcel, uint32_t new_pos)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->RewindRead(new_pos);
}

bool CParcelRewindWrite(CParcel *parcel, uint32_t new_pos)
{
    if (!IsValidParcel(parcel, __func__)) {
        return 0;
    }
    return parcel->parcel_->RewindWrite(new_pos);
}

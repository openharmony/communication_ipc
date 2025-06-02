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

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <cinttypes>
#include <string>
#include <unistd.h>
#include <vector>

#include "ashmem.h"
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "hilog/log.h"
#include "log_tags.h"
#include "message_option.h"
#include "message_parcel.h"
#include "refbase.h"
#include "rpc_taihe_error.h"

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_OTHER, "RpcTaiheImpl" };
constexpr size_t MAX_BYTES_LENGTH = 40960;
constexpr size_t MAX_CAPACITY_TO_WRITE = 200 * 1024;
constexpr size_t BYTE_SIZE_32 = 4;
constexpr size_t BYTE_SIZE_8 = 1;

#define CHECK_WRITE_POSITION(nativeParcel, maxCapacityToWrite)                                                        \
    do {                                                                                                              \
        if ((maxCapacityToWrite) < (nativeParcel)->GetWritePosition()) {                                              \
            ZLOGE(LOG_LABEL, "invalid write position, maxCapacityToWrite:%{public}zu, GetWritePosition:%{public}zu",  \
                (maxCapacityToWrite), (nativeParcel)->GetWritePosition());                                            \
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);                           \
        }                                                                                                             \
    } while (0)

#define CHECK_WRITE_CAPACITY(lenToWrite, nativeParcel, maxCapacityToWrite)                                            \
    do {                                                                                                              \
        CHECK_WRITE_POSITION(nativeParcel, maxCapacityToWrite);                                                       \
        size_t cap = (maxCapacityToWrite) - (nativeParcel)->GetWritePosition();                                       \
        if (cap < (lenToWrite)) {                                                                                     \
            ZLOGE(LOG_LABEL, "No enough write capacity, cap:%{public}zu, lenToWrite:%{public}zu", cap, lenToWrite);   \
            taihe::set_error("No enough capacity to write");                                                          \
            return;                                                                                                   \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_POSITION(nativeParcel)                                                                             \
    do {                                                                                                              \
        if ((nativeParcel)->GetDataSize() < (nativeParcel)->GetReadPosition()) {                                      \
            ZLOGE(LOG_LABEL, "invalid read position, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",           \
                (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());                                    \
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);                          \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_POSITION_RETVAL(nativeParcel, retVal)                                                              \
    do {                                                                                                              \
        if ((nativeParcel)->GetDataSize() < (nativeParcel)->GetReadPosition()) {                                      \
            ZLOGE(LOG_LABEL, "invalid read position, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",           \
                (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());                                    \
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, retVal);      \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_LENGTH(arrayLength, typeSize, nativeParcel)                                                        \
    do {                                                                                                              \
        CHECK_READ_POSITION(nativeParcel);                                                                            \
        size_t remainSize = (nativeParcel)->GetDataSize() - (nativeParcel)->GetReadPosition();                        \
        if (((arrayLength) < 0) || ((arrayLength) > remainSize) || (((arrayLength) * (typeSize)) > remainSize)) {     \
            ZLOGE(LOG_LABEL, "No enough data to read, arrayLength:%{public}zu, remainSize:%{public}zu,"               \
                "typeSize:%{public}zu, GetDataSize:%{public}zu, GetReadPosition:%{public}zu", arrayLength,            \
                remainSize, typeSize, (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());              \
            taihe::set_error("No enough data to read");                                                               \
            return;                                                                                                   \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_LENGTH_RETVAL(arrayLength, typeSize, nativeParcel, retVal)                                         \
    do {                                                                                                              \
        CHECK_READ_POSITION_RETVAL(nativeParcel, retVal);                                                             \
        size_t remainSize = (nativeParcel)->GetDataSize() - (nativeParcel)->GetReadPosition();                        \
        if (((arrayLength) < 0) || ((arrayLength) > remainSize) || (((arrayLength) * (typeSize)) > remainSize)) {     \
            ZLOGE(LOG_LABEL, "No enough data to read, arrayLength:%{public}zu, remainSize:%{public}zu,"               \
                "typeSize:%{public}zu, GetDataSize:%{public}zu, GetReadPosition:%{public}zu", arrayLength,            \
                remainSize, typeSize, (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());              \
            taihe::set_error("No enough data to read");                                                               \
            return retVal;                                                                                            \
        }                                                                                                             \
    } while (0)

#define REWIND_IF_WRITE_CHECK_FAIL(lenToWrite, pos, nativeParcel, maxCapacityToWrite)                                 \
    do {                                                                                                              \
        CHECK_WRITE_POSITION(nativeParcel, maxCapacityToWrite);                                                       \
        size_t cap = (maxCapacityToWrite) - (nativeParcel)->GetWritePosition();                                       \
        if (cap < (lenToWrite)) {                                                                                     \
            ZLOGE(LOG_LABEL, "No enough write capacity, cap:%{public}zu, lenToWrite:%{public}zu", cap, lenToWrite);   \
            (nativeParcel)->RewindWrite(pos);                                                                         \
            taihe::set_error("No enough data to read");                                                               \
            return;                                                                                                   \
        }                                                                                                             \
    } while (0)

#define CHECK_NATIVE_OBJECT(object, errorCode)                                                                        \
    do {                                                                                                              \
        if ((object) == nullptr) {                                                                                    \
            ZLOGE(LOG_LABEL, "native object is null");                                                                \
            RPC_TAIHE_ERROR(errorCode);                                                                               \
        }                                                                                                             \
    } while (0)

#define CHECK_NATIVE_OBJECT_WITH_RETVAL(object, errorCode, retval)                                                    \
    do {                                                                                                              \
        if ((object) == nullptr) {                                                                                    \
            ZLOGE(LOG_LABEL, "native object is null");                                                                \
            RPC_TAIHE_ERROR_WITH_RETVAL(errorCode, retval);                                                           \
        }                                                                                                             \
    } while (0)

class ParcelableImpl {
public:
    ParcelableImpl()
    {
    }

    bool Marshalling(::ohos::rpc::rpc::weak::MessageSequence dataOut)
    {
        TH_THROW(std::runtime_error, "mashalling not implemented");
    }

    bool Unmarshalling(::ohos::rpc::rpc::weak::MessageSequence dataIn)
    {
        TH_THROW(std::runtime_error, "unmarshalling not implemented");
    }
};

class AshmemImpl {
public:
    explicit AshmemImpl()
    {
    }

    explicit AshmemImpl(const char *name, int32_t size)
    {
        ashmem_ = OHOS::Ashmem::CreateAshmem(name, size);
    }

    explicit AshmemImpl(OHOS::sptr<OHOS::Ashmem> ashmem)
    {
        int32_t fd = ashmem->GetAshmemFd();
        int32_t size = ashmem->GetAshmemSize();
        if (fd < 0 || size == 0) {
            ZLOGE(LOG_LABEL, "fd < 0 or size == 0");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        int dupFd = dup(fd);
        if (dupFd < 0) {
            ZLOGE(LOG_LABEL, "fail to dup fd:%{public}d", dupFd);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::OS_DUP_ERROR);
        }
        OHOS::sptr<OHOS::Ashmem> newAshmem(new OHOS::Ashmem(dupFd, size));
        if (newAshmem == nullptr) {
            ZLOGE(LOG_LABEL, "fail to create new Ashmem");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::PARCEL_MEMORY_ALLOC_ERROR);
        }
        ashmem_ = newAshmem;
    }

    int64_t GetImplPtr()
    {
        return reinterpret_cast<int64_t>(this);
    }

    void MapReadWriteAshmem()
    {
        CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::OS_MMAP_ERROR);
        ashmem_->MapReadAndWriteAshmem();
    }

    int32_t GetAshmemSize()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(ashmem_, OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR, 0);
        return ashmem_->GetAshmemSize();
    }

    OHOS::sptr<OHOS::Ashmem> GetAshmem()
    {
        return ashmem_;
    }

    static ::ohos::rpc::rpc::Ashmem CreateAshmem_WithTwoParam(::taihe::string_view name, int32_t size);
    static ::ohos::rpc::rpc::Ashmem CreateAshmem_WithOneParam(::ohos::rpc::rpc::weak::Ashmem ashmem);

private:
    OHOS::sptr<OHOS::Ashmem> ashmem_ = nullptr;
};

class MessageSequenceImpl {
public:
    MessageSequenceImpl()
    {
        nativeParcel_ = std::make_shared<OHOS::MessageParcel>();
        maxCapacityToWrite_ = MAX_CAPACITY_TO_WRITE;
    }

    void Reclaim()
    {
        nativeParcel_ = nullptr;
    }

    void AddJsObjWeakRef(::ohos::rpc::rpc::weak::MessageSequence obj)
    {
        jsObjRef_ = std::optional<::ohos::rpc::rpc::weak::MessageSequence>(std::in_place, obj);
    }

    void WriteInterfaceToken(::taihe::string_view token)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        if (token.size() > MAX_BYTES_LENGTH) {
            ZLOGE(LOG_LABEL, "token is too large");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        std::u16string tokenStr(token.begin(), token.end());
        bool result = nativeParcel_->WriteInterfaceToken(tokenStr);
        if (!result) {
            ZLOGE(LOG_LABEL, "write interface token failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ::taihe::string ReadInterfaceToken()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "");
        std::u16string result = nativeParcel_->ReadInterfaceToken();
        return OHOS::Str16ToStr8(result);
    }

    int32_t GetCapacity()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
        int32_t result = nativeParcel_->GetDataCapacity();
        return result;
    }

    void SetCapacity(int32_t size)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        bool result = nativeParcel_->SetDataCapacity(size);
        if (!result) {
            ZLOGE(LOG_LABEL, "set data capacity failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        maxCapacityToWrite_ = size;
    }

    void WriteNoException()
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        bool result = nativeParcel_->WriteInt32(0);
        if (!result) {
            ZLOGE(LOG_LABEL, "write int32 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    void ReadException()
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        int32_t code = nativeParcel_->ReadInt32();
        if (code == 0) {
            ZLOGE(LOG_LABEL, "ReadException failed, no exception");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        }
        std::u16string result = nativeParcel_->ReadString16();
        taihe::set_business_error(code, OHOS::Str16ToStr8(result));
    }

    void WriteInt(int32_t val)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        bool result = nativeParcel_->WriteInt32(val);
        if (!result) {
            ZLOGE(LOG_LABEL, "write int32 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    void WriteLong(int64_t val)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        bool result = nativeParcel_->WriteInt64(val);
        if (!result) {
            ZLOGE(LOG_LABEL, "write int64 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    void WriteBoolean(bool val)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        bool result = nativeParcel_->WriteInt8(val);
        if (!result) {
            ZLOGE(LOG_LABEL, "write int8 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    void WriteString(::taihe::string_view val)
    {
        if (val.size() > MAX_BYTES_LENGTH) {
            ZLOGE(LOG_LABEL, "write string failed, string size:%{public}zu is too large", val.size());
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        CHECK_WRITE_CAPACITY(BYTE_SIZE_32 * val.size(), nativeParcel_, maxCapacityToWrite_);
        std::u16string str(val.begin(), val.end());
        bool result = nativeParcel_->WriteString16(str);
        if (!result) {
            ZLOGE(LOG_LABEL, "write string16 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    void WriteParcelable(::ohos::rpc::rpc::weak::Parcelable val)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteInt32(1);
        val->Marshalling(*jsObjRef_);
        if (taihe::has_error()) {
            ZLOGE(LOG_LABEL, "call marshalling failed");
            nativeParcel_->RewindWrite(pos);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    void WriteByteArray(::taihe::array_view<int8_t> byteArray)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        uint32_t arrayLength = byteArray.size();
        if (arrayLength == 0) {
            ZLOGE(LOG_LABEL, "arrayLength is 0");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        CHECK_WRITE_CAPACITY(BYTE_SIZE_8 * (arrayLength + 1), nativeParcel_, maxCapacityToWrite_);
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(arrayLength);
        bool result = false;
        for (size_t i = 0; i < arrayLength; i++) {
            result = nativeParcel_->WriteInt8(byteArray[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write int8 failed");
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        }
    }

    void WriteIntArray(::taihe::array_view<int32_t> intArray)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        uint32_t arrayLength = intArray.size();
        if (arrayLength == 0) {
            ZLOGE(LOG_LABEL, "arrayLength is 0");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        CHECK_WRITE_CAPACITY(BYTE_SIZE_32 * (arrayLength + 1), nativeParcel_, maxCapacityToWrite_);
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(arrayLength);
        bool result = false;
        for (size_t i = 0; i < arrayLength; i++) {
            result = nativeParcel_->WriteInt32(intArray[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write int32 failed");
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        }
    }

    void WriteDoubleArray(::taihe::array_view<double> doubleArray)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        uint32_t arrayLength = doubleArray.size();
        if (arrayLength == 0) {
            ZLOGE(LOG_LABEL, "arrayLength is 0");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(double) * arrayLength, nativeParcel_, maxCapacityToWrite_);
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(arrayLength);
        bool result = false;
        for (size_t i = 0; i < arrayLength; i++) {
            result = nativeParcel_->WriteDouble(doubleArray[i]);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write double failed");
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        }
    }

    void WriteBooleanArray(::taihe::array_view<bool> booleanArray)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        uint32_t arrayLength = booleanArray.size();
        if (arrayLength == 0) {
            ZLOGE(LOG_LABEL, "arrayLength is 0");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        CHECK_WRITE_CAPACITY(BYTE_SIZE_32 * (arrayLength + 1), nativeParcel_, maxCapacityToWrite_);
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(arrayLength);
        bool result = false;
        for (size_t i = 0; i < arrayLength; i++) {
            result = nativeParcel_->WriteInt8(static_cast<int8_t>(booleanArray[i]));
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write int8 failed");
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        }
    }

    void WriteStringArray(::taihe::array_view<::taihe::string> stringArray)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        uint32_t arrayLength = stringArray.size();
        if (arrayLength == 0) {
            ZLOGE(LOG_LABEL, "arrayLength is 0");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        size_t pos = nativeParcel_->GetWritePosition();
        nativeParcel_->WriteUint32(arrayLength);
        bool result = false;
        for (size_t i = 0; i < arrayLength; i++) {
            if (stringArray[i].size() > MAX_BYTES_LENGTH) {
                ZLOGE(LOG_LABEL, "string length is too long, index:%{public}zu, size:%{public}zu",
                    i, stringArray[i].size());
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
            }
            REWIND_IF_WRITE_CHECK_FAIL(BYTE_SIZE_32 * stringArray[i].size(), pos, nativeParcel_, maxCapacityToWrite_);
            std::u16string str(stringArray[i].begin(), stringArray[i].end());
            result = nativeParcel_->WriteString16(str);
            if (!result) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "write string16 failed");
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        }
    }

    void WriteParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        uint32_t arrayLength = parcelableArray.size();
        if (arrayLength == 0) {
            ZLOGE(LOG_LABEL, "arrayLength is 0");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        size_t pos = nativeParcel_->GetWritePosition();
        if (!(nativeParcel_->WriteUint32(arrayLength))) {
            ZLOGE(LOG_LABEL, "write array length failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        for (size_t i = 0; i < arrayLength; i++) {
            nativeParcel_->WriteInt32(1);
            parcelableArray[i]->Marshalling(*jsObjRef_);
            if (taihe::has_error()) {
                nativeParcel_->RewindWrite(pos);
                ZLOGE(LOG_LABEL, "call marshalling failed, element index:%{public}zu", i);
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        }
    }

    int32_t ReadInt()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
        return nativeParcel_->ReadInt32();
    }

    int64_t ReadLong()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
        return nativeParcel_->ReadInt64();
    }

    bool ReadBoolean()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, false);
        return static_cast<bool>(nativeParcel_->ReadInt8());
    }

    ::taihe::string ReadString()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "");
        return OHOS::Str16ToStr8(nativeParcel_->ReadString16());
    }

    void ReadParcelable(::ohos::rpc::rpc::weak::Parcelable dataIn)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        int32_t flags = nativeParcel_->ReadInt32();
        if (flags != 1) {
            ZLOGE(LOG_LABEL, "read parcelable failed, flags:%{public}d", flags);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        }
        dataIn->Unmarshalling(*jsObjRef_);
        if (taihe::has_error()) {
            ZLOGE(LOG_LABEL, "call marshalling failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CALL_JS_METHOD_ERROR);
        }
    }

    ::taihe::array<int32_t> ReadIntArrayImpl()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<int32_t>(nullptr, 0));
        int32_t arrayLength = nativeParcel_->ReadInt32();
        if (arrayLength <= 0) {
            ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
                (::taihe::array<int32_t>(nullptr, 0)));
        }
        CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_32,
            nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
        ::taihe::array<int32_t> res(arrayLength);
        for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
            if (!nativeParcel_->ReadInt32(res[i])) {
                ZLOGE(LOG_LABEL, "read int32 failed");
                RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                    (::taihe::array<int32_t>(nullptr, 0)));
            }
        }
        return res;
    }

    ::taihe::array<double> ReadDoubleArrayImpl()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<double>(nullptr, 0));
        int32_t arrayLength = nativeParcel_->ReadInt32();
        if (arrayLength <= 0) {
            ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
                (::taihe::array<double>(nullptr, 0)));
        }
        CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(double),
            nativeParcel_, (::taihe::array<double>(nullptr, 0)));
        ::taihe::array<double> res(arrayLength);
        for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
            if (!nativeParcel_->ReadDouble(res[i])) {
                ZLOGE(LOG_LABEL, "read double failed");
                RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                    (::taihe::array<double>(nullptr, 0)));
            }
        }
        return res;
    }

    ::taihe::array<bool> ReadBooleanArrayImpl()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<bool>(nullptr, 0));
        int32_t arrayLength = nativeParcel_->ReadInt32();
        if (arrayLength <= 0) {
            ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
                (::taihe::array<bool>(nullptr, 0)));
        }
        CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_32,
            nativeParcel_, (::taihe::array<bool>(nullptr, 0)));
        ::taihe::array<bool> res(arrayLength);
        int8_t val;
        for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
            if (!nativeParcel_->ReadInt8(val)) {
                ZLOGE(LOG_LABEL, "read bool failed");
                RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                    (::taihe::array<bool>(nullptr, 0)));
            }
            res[i] = (val != 0) ? true : false;
        }
        return res;
    }

    ::taihe::array<::taihe::string> ReadStringArrayImpl()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<::taihe::string>(nullptr, 0));
        int32_t arrayLength = nativeParcel_->ReadInt32();
        if (arrayLength <= 0) {
            ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
                (::taihe::array<::taihe::string>(nullptr, 0)));
        }
        CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_32,
            nativeParcel_, (::taihe::array<::taihe::string>(nullptr, 0)));
        std::vector<std::string> res;
        std::u16string val;
        for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
            if (nativeParcel_->GetReadableBytes() <= 0) {
                break;
            }
            if (!nativeParcel_->ReadString16(val)) {
                ZLOGE(LOG_LABEL, "read string16 failed");
                RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                    (::taihe::array<::taihe::string>(nullptr, 0)));
            }
            res.push_back(OHOS::Str16ToStr8(val));
        }
        return ::taihe::array<::taihe::string>(taihe::copy_data_t{}, res.data(), res.size());
    }

    void ReadParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        int32_t arrayLength = nativeParcel_->ReadInt32();
        if (arrayLength <= 0) {
            ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        CHECK_READ_LENGTH(static_cast<size_t>(arrayLength), BYTE_SIZE_8, nativeParcel_);
        int32_t flags;
        for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
            flags = nativeParcel_->ReadInt32();
            if (flags != 1) {
                ZLOGE(LOG_LABEL, "read parcelable failed, flags:%{public}d", flags);
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
            }
            parcelableArray[i]->Unmarshalling(*jsObjRef_);
            if (taihe::has_error()) {
                ZLOGE(LOG_LABEL, "call unmarshalling failed");
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
            }
        }
    }

    void WriteFileDescriptor(int32_t fd)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        bool result = nativeParcel_->WriteFileDescriptor(fd);
        if (!result) {
            ZLOGE(LOG_LABEL, "write file descriptor failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    int32_t ReadFileDescriptor()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
        int32_t result = nativeParcel_->ReadFileDescriptor();
        if (result < 0) {
            ZLOGE(LOG_LABEL, "read file descriptor failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
        }
        return result;
    }

    void WriteAshmem(::ohos::rpc::rpc::Ashmem ashmem)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        if (!nativeParcel_->WriteAshmem(reinterpret_cast<AshmemImpl*>(ashmem->GetImplPtr())->GetAshmem())) {
            ZLOGE(LOG_LABEL, "write ashmem failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ::ohos::rpc::rpc::Ashmem ReadAshmem()
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            (taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>()));
        OHOS::sptr<OHOS::Ashmem> nativeAshmem = nativeParcel_->ReadAshmem();
        if (nativeAshmem == nullptr) {
            ZLOGE(LOG_LABEL, "nativeAshmem is null");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>()));
        }
        return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(nativeAshmem);
    }

    void WriteRawDataBuffer(::taihe::array_view<uint8_t> rawData, int32_t size)
    {
        CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        if (!nativeParcel_->WriteRawData(static_cast<const void*>(rawData.data()), size)) {
            ZLOGE(LOG_LABEL, "write raw data failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }

    ::taihe::array<uint8_t> ReadRawDataBuffer(int32_t size)
    {
        CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
            OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<uint8_t>(nullptr, 0));
        if (size <= 0) {
            ZLOGE(LOG_LABEL, "invalid param size:%{public}d", size);
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
                (::taihe::array<uint8_t>(nullptr, 0)));
        }
        const void *rawData = nativeParcel_->ReadRawData(size);
        if (rawData == nullptr) {
            ZLOGE(LOG_LABEL, "rawData is null");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                ::taihe::array<uint8_t>(nullptr, 0));
        }
        const uint8_t* bytePtr = static_cast<const uint8_t*>(rawData);
        std::vector<uint8_t> res(size);
        std::copy(bytePtr, bytePtr + size, res.begin());
        return ::taihe::array<uint8_t>(res);
    }

    static ::ohos::rpc::rpc::MessageSequence CreateMessageSequence();
    static void CloseFileDescriptor(int32_t fd);

private:
    std::shared_ptr<OHOS::MessageParcel> nativeParcel_ = nullptr;
    size_t maxCapacityToWrite_;
    std::optional<::ohos::rpc::rpc::weak::MessageSequence> jsObjRef_;
};

class MessageOptionImpl {
public:
    MessageOptionImpl(int32_t syncFlags, int32_t waitTime)
    {
        messageOption_ = std::make_shared<OHOS::MessageOption>(syncFlags, waitTime);
    }

    bool IsAsync()
    {
        if (messageOption_ == nullptr) {
            ZLOGE(LOG_LABEL, "messageOption_ is null");
            taihe::set_error("failed to get native message option");
            return false;
        }
        int flags = messageOption_->GetFlags();
        return (flags & OHOS::MessageOption::TF_ASYNC) != 0;
    }

    void SetAsync(bool isAsync)
    {
        if (messageOption_ == nullptr) {
            ZLOGE(LOG_LABEL, "messageOption_ is null");
            taihe::set_error("failed to get native message option");
            return;
        }
        messageOption_->SetFlags(static_cast<int32_t>(isAsync));
    }

    static ::ohos::rpc::rpc::MessageOption CreateMessageOption_WithTwoParam(int32_t syncFlags, int32_t waitTime);
    static ::ohos::rpc::rpc::MessageOption CreateMessageOption_WithOneParam(bool isAsync);
    static ::ohos::rpc::rpc::MessageOption CreateMessageOption();

private:
    std::shared_ptr<OHOS::MessageOption> messageOption_ = nullptr;
};


class IPCSkeletonImpl {
public:
    IPCSkeletonImpl()
    {
    }

    static int32_t GetCallingPid();
    static int32_t GetCallingUid();
    static uint32_t GetCallingTokenId();
};

::ohos::rpc::rpc::MessageSequence MessageSequenceImpl::CreateMessageSequence()
{
    ::ohos::rpc::rpc::MessageSequence res =
        taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>();
    res->AddJsObjWeakRef(res);
    return res;
}

void MessageSequenceImpl::CloseFileDescriptor(int32_t fd)
{
    if (fd < 0) {
        ZLOGE(LOG_LABEL, "invalid fd:%{public}d", fd);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
    }
    close(fd);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption_WithTwoParam(int32_t syncFlags, int32_t waitTime)
{
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(syncFlags, waitTime);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption_WithOneParam(bool isAsync)
{
    int flags = isAsync ? OHOS::MessageOption::TF_ASYNC : OHOS::MessageOption::TF_SYNC;
    int waitTime = OHOS::MessageOption::TF_WAIT_TIME;
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(flags, waitTime);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption()
{
    int flags = OHOS::MessageOption::TF_SYNC;
    int waitTime = OHOS::MessageOption::TF_WAIT_TIME;
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(flags, waitTime);
}

::ohos::rpc::rpc::Ashmem AshmemImpl::CreateAshmem_WithTwoParam(::taihe::string_view name, int32_t size)
{
    return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(name.data(), size);
}

::ohos::rpc::rpc::Ashmem AshmemImpl::CreateAshmem_WithOneParam(::ohos::rpc::rpc::weak::Ashmem ashmem)
{
    auto inputAshmemPtr = reinterpret_cast<AshmemImpl*>(ashmem->GetImplPtr());
    return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(inputAshmemPtr->GetAshmem());
}

int32_t IPCSkeletonImpl::GetCallingPid()
{
    return OHOS::IPCSkeleton::GetCallingPid();
}

int32_t IPCSkeletonImpl::GetCallingUid()
{
    return OHOS::IPCSkeleton::GetCallingUid();
}

uint32_t IPCSkeletonImpl::GetCallingTokenId()
{
    return OHOS::IPCSkeleton::GetCallingTokenID();
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateMessageSequence(MessageSequenceImpl::CreateMessageSequence);
TH_EXPORT_CPP_API_CloseFileDescriptor(MessageSequenceImpl::CloseFileDescriptor);
TH_EXPORT_CPP_API_CreateMessageOption_WithTwoParam(MessageOptionImpl::CreateMessageOption_WithTwoParam);
TH_EXPORT_CPP_API_CreateMessageOption_WithOneParam(MessageOptionImpl::CreateMessageOption_WithOneParam);
TH_EXPORT_CPP_API_CreateMessageOption(MessageOptionImpl::CreateMessageOption);
TH_EXPORT_CPP_API_CreateAshmem_WithTwoParam(AshmemImpl::CreateAshmem_WithTwoParam);
TH_EXPORT_CPP_API_CreateAshmem_WithOneParam(AshmemImpl::CreateAshmem_WithOneParam);
TH_EXPORT_CPP_API_GetCallingPid(IPCSkeletonImpl::GetCallingPid);
TH_EXPORT_CPP_API_GetCallingUid(IPCSkeletonImpl::GetCallingUid);
TH_EXPORT_CPP_API_GetCallingTokenId(IPCSkeletonImpl::GetCallingTokenId);
// NOLINTEND

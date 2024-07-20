/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NAPI_IPC_OHOS_NAPI_RPC_COMMON_H
#define NAPI_IPC_OHOS_NAPI_RPC_COMMON_H

#include "napi_rpc_error.h"

namespace OHOS {
static NapiError napiErr;

#define CHECK_WRITE_POSITION(env, napiParcel)                                                                         \
    do {                                                                                                              \
        if ((napiParcel)->maxCapacityToWrite_ < (napiParcel)->nativeParcel_->GetWritePosition()) {                    \
            ZLOGE(LOG_LABEL, "invalid write position, maxCapacityToWrite_:%{public}zu, GetWritePosition:%{public}zu", \
                (napiParcel)->maxCapacityToWrite_, (napiParcel)->nativeParcel_->GetWritePosition());                  \
            return napiErr.ThrowError(env, errorDesc::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);                          \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_POSITION(env, napiParcel)                                                                 \
    do {                                                                                                     \
        if ((napiParcel)->nativeParcel_->GetDataSize() < (napiParcel)->nativeParcel_->GetReadPosition()) {   \
            ZLOGE(LOG_LABEL, "invalid read position, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",  \
                (napiParcel)->nativeParcel_->GetDataSize(), (napiParcel)->nativeParcel_->GetReadPosition()); \
            return napiErr.ThrowError(env, errorDesc::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);                \
        }                                                                                                    \
    } while (0)

#define CHECK_WRITE_CAPACITY(env, lenToWrite, napiParcel)                                                             \
    do {                                                                                                              \
        CHECK_WRITE_POSITION(env, napiParcel);                                                                        \
        size_t cap = (napiParcel)->maxCapacityToWrite_ - (napiParcel)->nativeParcel_->GetWritePosition();             \
        if (cap < (lenToWrite)) {                                                                                     \
            ZLOGE(LOG_LABEL, "No enough write capacity, cap:%{public}zu, lenToWrite:%{public}zu", cap, lenToWrite);   \
            napi_throw_range_error(env, nullptr, "No enough capacity to write");                                      \
        }                                                                                                             \
    } while (0)

#define REWIND_IF_WRITE_CHECK_FAIL(env, lenToWrite, pos, napiParcel)                                                  \
    do {                                                                                                              \
        CHECK_WRITE_POSITION(env, napiParcel);                                                                        \
        size_t cap = (napiParcel)->maxCapacityToWrite_ - (napiParcel)->nativeParcel_->GetWritePosition();             \
        if (cap < (lenToWrite)) {                                                                                     \
            ZLOGE(LOG_LABEL, "No enough write capacity, cap:%{public}zu, lenToWrite:%{public}zu", cap, lenToWrite);   \
            (napiParcel)->nativeParcel_->RewindWrite(pos);                                                            \
            napi_throw_range_error(env, nullptr, "No enough capacity to write");                                      \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_LENGTH(env, arrayLength, typeSize, napiParcel)                                                    \
    do {                                                                                                             \
        CHECK_READ_POSITION(env, napiParcel);                                                                        \
        size_t remainSize = (napiParcel)->nativeParcel_->GetDataSize() -                                             \
            (napiParcel)->nativeParcel_->GetReadPosition();                                                          \
        if (((arrayLength) < 0) || ((arrayLength) > remainSize) || (((arrayLength) * (typeSize)) > remainSize)) {    \
            ZLOGE(LOG_LABEL, "No enough data to read, arrayLength:%{public}zu, remainSize:%{public}zu,"              \
                "typeSize:%{public}zu, GetDataSize:%{public}zu, GetReadPosition:%{public}zu", arrayLength,           \
                remainSize, typeSize, (napiParcel)->nativeParcel_->GetDataSize(),                                    \
                (napiParcel)->nativeParcel_->GetReadPosition());                                                     \
            napi_throw_range_error(env, nullptr, "No enough data to read");                                          \
        }                                                                                                            \
    } while (0)

constexpr size_t MAX_CAPACITY_TO_WRITE = 200 * 1024;
constexpr size_t MAX_BYTES_LENGTH = 40960;
constexpr size_t BYTE_SIZE_8 = 1;
constexpr size_t BYTE_SIZE_16 = 2;
constexpr size_t BYTE_SIZE_32 = 4;
constexpr size_t BYTE_SIZE_64 = 8;
constexpr size_t ARGV_INDEX_0 = 0;
constexpr size_t ARGV_INDEX_1 = 1;
constexpr size_t ARGV_LENGTH_1 = 1;
constexpr size_t ARGV_LENGTH_2 = 2;
constexpr size_t REQUIRED_ARGS_COUNT_1 = 1;  // "requires 1 parameter"
constexpr size_t ENUM_TYPECODE_COUNT = 10;

enum TypeCode {
    INT8_ARRAY        = 0,
    UINT8_ARRAY       = 1,
    INT16_ARRAY       = 2,
    UINT16_ARRAY      = 3,
    INT32_ARRAY       = 4,
    UINT32_ARRAY      = 5,
    FLOAT32_ARRAY     = 6,
    FLOAT64_ARRAY     = 7,
    BIGINT64_ARRAY    = 8,
    BIGUINT64_ARRAY   = 9,
};

} // namespace OHOS
#endif //  NAPI_IPC_OHOS_NAPI_RPC_COMMON_H
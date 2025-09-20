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

#include "message_parcel.h"
#include "rpc_taihe_error.h"
#include "hilog/log.h"
#include "log_tags.h"

namespace OHOS {

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_OTHER, "RpcTaiheImpl" };

#define CHECK_WRITE_POSITION(nativeParcel, maxCapacityToWrite)                                                        \
    do {                                                                                                              \
        if ((maxCapacityToWrite) < (nativeParcel)->GetWritePosition()) {                                              \
            ZLOGE(LOG_LABEL, "invalid write position, maxCapacityToWrite:%{public}zu, GetWritePosition:%{public}zu",  \
                (maxCapacityToWrite), (nativeParcel)->GetWritePosition());                                            \
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);                           \
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
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);                          \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_POSITION_RETVAL(nativeParcel, retVal)                                                              \
    do {                                                                                                              \
        if ((nativeParcel)->GetDataSize() < (nativeParcel)->GetReadPosition()) {                                      \
            ZLOGE(LOG_LABEL, "invalid read position, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",           \
                (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());                                    \
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, retVal);      \
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

}
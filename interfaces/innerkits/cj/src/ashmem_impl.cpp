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

#include "ashmem_impl.h"

#include <cinttypes>
#include <limits>
#include <unistd.h>

namespace OHOS {
static constexpr int MMAP_PROT_MAX = AshmemImpl::PROT_EXEC | AshmemImpl::PROT_READ | AshmemImpl::PROT_WRITE;

AshmemImpl::AshmemImpl(sptr<Ashmem> ashmem) : ashmem_(ashmem)
{
    if (ashmem == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
    }
}

void AshmemImpl::CloseAshmem()
{
    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        return;
    }
    ashmem_->CloseAshmem();
}

int32_t AshmemImpl::GetAshmemSize(int32_t* errCode)
{
    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        *errCode = errorDesc::CHECK_PARAM_ERROR;
        return 0;
    }
    return ashmem_->GetAshmemSize();
}

int32_t AshmemImpl::MapTypedAshmem(uint32_t mapType)
{
    if (mapType > MMAP_PROT_MAX) {
        ZLOGE(LOG_LABEL, "ashmem mapType error");
        return errorDesc::CHECK_PARAM_ERROR;
    }

    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        return errorDesc::OS_MMAP_ERROR;
    }
    ashmem_->MapAshmem(mapType);
    return 0;
}

int32_t AshmemImpl::MapReadWriteAshmem()
{
    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        return errorDesc::OS_MMAP_ERROR;
    }
    ashmem_->MapReadAndWriteAshmem();
    return 0;
}

int32_t AshmemImpl::MapReadonlyAshmem()
{
    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        return errorDesc::OS_MMAP_ERROR;
    }
    ashmem_->MapReadOnlyAshmem();
    return 0;
}

int32_t AshmemImpl::SetProtectionType(uint32_t protectionType)
{
    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        return errorDesc::OS_IOCTL_ERROR;
    }
    ashmem_->SetProtection(protectionType);
    return 0;
}

void AshmemImpl::UnmapAshmem()
{
    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        return;
    }
    ashmem_->UnmapAshmem();
}

int32_t AshmemImpl::WriteDataToAshmem(uint8_t* data, int64_t size, int64_t offset)
{
    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        return errorDesc::WRITE_TO_ASHMEM_ERROR;
    }
    if (data == nullptr) {
        return errorDesc::CHECK_PARAM_ERROR;
    }
    int64_t ashmemSize = static_cast<int64_t>(ashmem_->GetAshmemSize());
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() || offset < 0 ||
        offset > std::numeric_limits<int32_t>::max() || (size + offset) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}" PRId64 " offset:%{public}" PRId64, size, offset);
        return errorDesc::WRITE_TO_ASHMEM_ERROR;
    }
    if (!ashmem_->WriteToAshmem(data, size, offset)) {
        ZLOGE(LOG_LABEL, "WriteToAshmem fail");
        return errorDesc::WRITE_TO_ASHMEM_ERROR;
    }
    return 0;
}

uint8_t* AshmemImpl::ReadDataFromAshmem(int64_t size, int64_t offset, int32_t* errCode)
{
    if (ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem is null");
        *errCode = errorDesc::READ_FROM_ASHMEM_ERROR;
        return nullptr;
    }
    uint32_t ashmemSize = (uint32_t)ashmem_->GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() || offset < 0 ||
        offset > std::numeric_limits<int32_t>::max() || (size + offset) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}" PRId64 " offset:%{public}" PRId64, size, offset);
        *errCode = errorDesc::READ_FROM_ASHMEM_ERROR;
        return nullptr;
    }
    const void* result = ashmem_->ReadFromAshmem(size, offset);
    if (result == nullptr) {
        ZLOGE(LOG_LABEL, "ashmem->ReadFromAshmem returns null");
        *errCode = errorDesc::READ_FROM_ASHMEM_ERROR;
        return nullptr;
    }
    uint8_t* data = static_cast<uint8_t*>(malloc(size));
    if (data == nullptr) {
        *errCode = errorDesc::READ_FROM_ASHMEM_ERROR;
        return nullptr;
    }
    errno_t status = memcpy_s(data, size, result, size);
    if (status != EOK) {
        free(data);
        *errCode = errorDesc::READ_FROM_ASHMEM_ERROR;
        return nullptr;
    }
    return data;
}
} // namespace OHOS
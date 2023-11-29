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

#include "c_ashmem.h"
#include "c_ashmem_internal.h"
#include "log_tags.h"
#include "ipc_debug.h"

using namespace OHOS;
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC, "CAshmem" };

static bool IsValidCAshmem(const CAshmem *ashmem, const char *promot)
{
    if (ashmem == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: cashmem is null\n", promot);
        return false;
    }
    if (ashmem->ashmem_ == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: wrapper ashmem is null\n", promot);
        return false;
    }
    return true;
}

CAshmem::~CAshmem()
{
    if (ashmem_ != nullptr) {
        ashmem_->CloseAshmem();
        ashmem_ = nullptr;
    }
}

CAshmem *CreateCAshmem(const char *name, int32_t size)
{
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(name, size);
    if (ashmem == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: create native ashmem failed\n", __func__);
        return nullptr;
    }
    CAshmem *cashmem = new (std::nothrow) CAshmem(ashmem);
    if (cashmem == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: create cashmem failed\n", __func__);
        ashmem->CloseAshmem();
        return nullptr;
    }
    cashmem->IncStrongRef(nullptr);
    return cashmem;
}

void CAshmemIncStrongRef(CAshmem *ashmem)
{
    if (ashmem == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: ashmem is nullptr\n", __func__);
        return;
    }
    ashmem->IncStrongRef(nullptr);
}

void CAshmemDecStrongRef(CAshmem *ashmem)
{
    if (ashmem == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: ashmem is nullptr\n", __func__);
        return;
    }
    ashmem->DecStrongRef(nullptr);
}

void CloseCAshmem(CAshmem *ashmem)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return;
    }
    ashmem->ashmem_->CloseAshmem();
}

bool MapCAshmem(CAshmem *ashmem, int32_t mapType)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return false;
    }
    return ashmem->ashmem_->MapAshmem(mapType);
}

bool MapReadAndWriteCAshmem(CAshmem *ashmem)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return false;
    }
    return ashmem->ashmem_->MapReadAndWriteAshmem();
}

bool MapReadOnlyCAshmem(CAshmem *ashmem)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return false;
    }
    return ashmem->ashmem_->MapReadOnlyAshmem();
}

void UnmapCAshmem(CAshmem *ashmem)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return;
    }
    ashmem->ashmem_->UnmapAshmem();
}

bool SetCAshmemProtection(CAshmem *ashmem, int32_t protectionType)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return false;
    }
    return ashmem->ashmem_->SetProtection(protectionType);
}

int32_t GetCAshmemProtection(const CAshmem *ashmem)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return -1;
    }
    return ashmem->ashmem_->GetProtection();
}

int32_t GetCAshmemSize(const CAshmem *ashmem)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return 0;
    }
    return ashmem->ashmem_->GetAshmemSize();
}

bool WriteToCAshmem(CAshmem *ashmem, const uint8_t *data, int32_t size, int32_t offset)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return false;
    }
    return ashmem->ashmem_->WriteToAshmem(reinterpret_cast<const uint8_t *>(data), size, offset);
}

const uint8_t *ReadFromCAshmem(const CAshmem *ashmem, int32_t size, int32_t offset)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return nullptr;
    }
    return reinterpret_cast<const uint8_t *>(ashmem->ashmem_->ReadFromAshmem(size, offset));
}

int32_t GetCAshmemFd(const CAshmem *ashmem)
{
    if (!IsValidCAshmem(ashmem, __func__)) {
        return -1;
    }
    return ashmem->ashmem_->GetAshmemFd();
}
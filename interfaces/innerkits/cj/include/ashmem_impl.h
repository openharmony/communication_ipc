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
#ifndef ASHMEM_IMPL_H
#define ASHMEM_IMPL_H

#include "ashmem.h"
#include "ffi_remote_data.h"
#include "ipc_utils_ffi.h"
#include "securec.h"

namespace OHOS {
class AshmemImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(MessageSequenceImpl, OHOS::FFI::FFIData)
public:
    enum {
        PROT_EXEC = 4,
        PROT_NONE = 0,
        PROT_READ = 1,
        PROT_WRITE = 2,
    };
    explicit AshmemImpl(sptr<Ashmem> ashmem);
    ~AshmemImpl() = default;
    const sptr<Ashmem>& GetAshmem()
    {
        return ashmem_;
    }
    void SetAshmem(sptr<Ashmem>& ashmem)
    {
        ashmem_ = ashmem;
    }
    void CloseAshmem();
    int32_t GetAshmemSize(int32_t* errCode);
    int32_t MapTypedAshmem(uint32_t mapType);
    int32_t MapReadWriteAshmem();
    int32_t MapReadonlyAshmem();
    void UnmapAshmem();
    int32_t SetProtectionType(uint32_t protectionType);
    int32_t WriteDataToAshmem(uint8_t* data, int64_t size, int64_t offset);
    uint8_t* ReadDataFromAshmem(int64_t size, int64_t offset, int32_t* errCode);

private:
    sptr<Ashmem> ashmem_;
};
} // namespace OHOS

#endif
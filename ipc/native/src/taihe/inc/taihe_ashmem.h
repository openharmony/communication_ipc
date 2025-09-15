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

#ifndef OHOS_IPC_TAIHE_ASHMEM_H
#define OHOS_IPC_TAIHE_ASHMEM_H

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <cinttypes>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "ashmem.h"

namespace OHOS {

class AshmemImpl {
public:
    // only be used for returning invalid Ashmem.
    enum {
        PROT_EXEC = 4,
        PROT_NONE = 0,
        PROT_READ = 1,
        PROT_WRITE = 2,
    };

    explicit AshmemImpl();

    explicit AshmemImpl(const char *name, int32_t size);

    explicit AshmemImpl(OHOS::sptr<OHOS::Ashmem> ashmem);

    int64_t GetNativePtr();

    void MapReadWriteAshmem();

    int32_t GetAshmemSize();

    OHOS::sptr<OHOS::Ashmem> GetAshmem();

    void SetProtectionType(int32_t protectionType);

    void MapReadonlyAshmem();

    void MapTypedAshmem(int32_t mapType);

    void CloseAshmem();

    void UnmapAshmem();

    ::taihe::array<uint8_t> ReadDataFromAshmem(int32_t size, int32_t offset);

    void WriteDataToAshmem(::taihe::array_view<uint8_t> buf, int32_t size, int32_t offset);

    static ::ohos::rpc::rpc::Ashmem CreateAshmem_WithTwoParam(::taihe::string_view name, int32_t size);
    static ::ohos::rpc::rpc::Ashmem CreateAshmem_WithOneParam(::ohos::rpc::rpc::weak::Ashmem ashmem);

private:
    OHOS::sptr<OHOS::Ashmem> ashmem_ = nullptr;
};

} // namespace

#endif // OHOS_IPC_TAIHE_ASHMEM_H
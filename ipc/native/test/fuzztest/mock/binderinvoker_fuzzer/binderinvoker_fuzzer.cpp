/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "binderinvoker_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "sys_binder.h"

#define private public
#include "binder_invoker.h"
#undef private

namespace OHOS {

    void TransactionTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(binder_transaction_data_secctx)) {
            return;
        }

        BinderInvoker *invoker = new BinderInvoker();
        binder_transaction_data_secctx trSecctx = *(reinterpret_cast<const binder_transaction_data_secctx *>(data));
        trSecctx.transaction_data.target.ptr = 0;
        trSecctx.transaction_data.offsets_size = 0;
        trSecctx.transaction_data.flags = 0;
        trSecctx.secctx = 0;

        invoker->Transaction(trSecctx);
        delete invoker;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::TransactionTest(data, size);
    return 0;
}
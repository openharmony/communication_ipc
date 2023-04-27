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

    void OnTransactionTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(binder_transaction_data)) {
            return;
        }

        BinderInvoker *invoker = new BinderInvoker();
        const binder_transaction_data *tr = reinterpret_cast<const binder_transaction_data *>(data);
        binder_transaction_data trData = *tr;
        trData.target.ptr = 0;
        trData.offsets_size = 0;
        trData.flags = 0;
        invoker->OnTransaction(reinterpret_cast<const uint8_t*>(&trData));
        delete invoker;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::OnTransactionTest(data, size);
    return 0;
}
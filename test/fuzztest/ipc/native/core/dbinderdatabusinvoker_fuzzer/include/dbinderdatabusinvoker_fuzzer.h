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

#ifndef DBINDERDATABUSINVOKER_FUZZER_H
#define DBINDERDATABUSINVOKER_FUZZER_H

#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "dbinder_session_object.h"
#include "sys_binder.h"

#define FUZZ_PROJECT_NAME "dbinderdatabusinvoker_fuzzer"

static constexpr size_t MAX_STR_LEN = 100;
std::shared_ptr<OHOS::DBinderSessionObject> CreateDBinderSessionObject(FuzzedDataProvider &provider)
{
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string serverDeviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    return std::make_shared<OHOS::DBinderSessionObject>(serviceName, serverDeviceId, stubIndex, nullptr, tokenId);
}

dbinder_transaction_data CreateDbinderTransactionData(FuzzedDataProvider &provider)
{
    dbinder_transaction_data data;
    data.sizeOfSelf = sizeof(dbinder_transaction_data);
    data.magic = provider.ConsumeIntegral<__u32>();
    data.version = provider.ConsumeIntegral<__u32>();
    data.cmd = provider.ConsumeIntegral<int>();
    data.code = provider.ConsumeIntegral<__u32>();
    data.flags = provider.ConsumeIntegral<__u32>();
    data.cookie = provider.ConsumeIntegral<__u64>();
    data.seqNumber = provider.ConsumeIntegral<__u64>();
    data.buffer_size = provider.ConsumeIntegral<binder_size_t>();
    data.offsets_size = provider.ConsumeIntegral<binder_size_t>();
    data.offsets = provider.ConsumeIntegral<binder_uintptr_t>();
    return data;
}

#endif // DBINDERDATABUSINVOKER_FUZZER_H
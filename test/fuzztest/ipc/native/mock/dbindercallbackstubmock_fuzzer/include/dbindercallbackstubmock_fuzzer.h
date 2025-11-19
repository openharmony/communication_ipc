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

#ifndef DBINDERCALLBACKSTUBMOCK_FUZZER_H
#define DBINDERCALLBACKSTUBMOCK_FUZZER_H

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "binder_invoker.h"
#include "dbinder_callback_stub.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipc_thread_skeleton.h"

namespace OHOS {
static constexpr size_t MAX_STR_LEN = 100;

sptr<DBinderCallbackStub> CreateDBinderCallbackStub(FuzzedDataProvider &provider)
{
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::string service = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string device = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string localDevice = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    return sptr<DBinderCallbackStub>::MakeSptr(service, device, localDevice, stubIndex, handle, tokenId);
}
} // namespace OHOS

#define FUZZ_PROJECT_NAME "dbindercallbackstubmock_fuzzer"

#endif // DBINDERCALLBACKSTUBMOCK_FUZZER_H

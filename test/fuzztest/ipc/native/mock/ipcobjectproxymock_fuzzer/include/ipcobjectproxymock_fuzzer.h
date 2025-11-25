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
#ifndef IPCOBJECTPROXYMOCK_FUZZER_H
#define IPCOBJECTPROXYMOCK_FUZZER_H

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dbinder_databus_invoker.h"
#include "ipc_object_proxy.h"
#include "ipc_process_skeleton.h"
#include "ipc_thread_skeleton.h"
#include "string_ex.h"

namespace OHOS {
static constexpr size_t MAX_STR_LEN = 100;

sptr<IPCObjectProxy> CreateIPCObjectProxy(FuzzedDataProvider &provider)
{
    int handle = provider.ConsumeIntegral<int>();
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    return sptr<IPCObjectProxy>::MakeSptr(handle, descriptor16);
}
} // namespace OHOS

#define FUZZ_PROJECT_NAME "ipcobjectproxymock_fuzzer"

#endif
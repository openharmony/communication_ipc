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
#ifndef DBINDERDATABUSINVOKERMOCK_FUZZER_H
#define DBINDERDATABUSINVOKERMOCK_FUZZER_H

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dbinder_databus_invoker.h"
#include "string_ex.h"

namespace OHOS {
static constexpr size_t MAX_STR_LEN = 100;

std::shared_ptr<DBinderSessionObject> CreateDBinderSessionObject(FuzzedDataProvider &provider)
{
    const std::string serviceName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    const std::string serverDeviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    return std::make_shared<DBinderSessionObject>(serviceName, serverDeviceId, stubIndex, nullptr, tokenId);
}
}

#define FUZZ_PROJECT_NAME "dbinderdatabusinvokermock_fuzzer"

#endif
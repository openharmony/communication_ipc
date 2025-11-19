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

#include "binderconnector_fuzzer.h"
#include "binder_connector.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
void MapMemoryFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t featureSet = provider.ConsumeIntegral<uint64_t>();
    BinderConnector *connector = BinderConnector::GetInstance();
    if (connector == nullptr) {
        return;
    }
    connector->MapMemory(featureSet);
}

void WriteBinderFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t request = provider.ConsumeIntegral<uint64_t>();
    void *ptr = nullptr;
    BinderConnector *connector = BinderConnector::GetInstance();
    if (connector == nullptr) {
        return;
    }
    connector->WriteBinder(request, ptr);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::MapMemoryFuzzTest(provider);
    OHOS::WriteBinderFuzzTest(provider);
    return 0;
}

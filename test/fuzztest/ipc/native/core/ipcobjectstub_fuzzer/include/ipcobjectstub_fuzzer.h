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

#ifndef IPCOBJECTSTUB_FUZZER_H
#define IPCOBJECTSTUB_FUZZER_H

#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "ipc_skeleton.h"
#include "ipcobjectstub_fuzzer.h"
#include "message_parcel.h"
#include "process_skeleton.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {

static constexpr size_t STR_MAX_LEN = 100;

sptr<IPCObjectStub> CreateIPCObjectStub(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    std::u16string descriptor16(descriptor.begin(), descriptor.end());
    bool serialInvokeFlag = provider.ConsumeBool();
    return sptr<IPCObjectStub>::MakeSptr(descriptor16, serialInvokeFlag);
}
} // namespace OHOS

#define FUZZ_PROJECT_NAME "ipcobjectstub_fuzzer"

#endif // IPCOBJECTSTUB_FUZZER_H
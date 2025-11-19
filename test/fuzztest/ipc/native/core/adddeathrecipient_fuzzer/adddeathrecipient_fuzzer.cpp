/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "adddeathrecipient_fuzzer.h"

#include "fuzz_data_generator.h"
#include "ipc_object_stub.h"
#include "iremote_object.h"

namespace OHOS {
class MyDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    void OnRemoteDied(const wptr<IRemoteObject> &object) override {}
};

void AddDeathRecipientFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    DataGenerator::Write(data, size);

    std::string descriptor;
    bool serialInvokeFlag;
    if (!GenerateBool(serialInvokeFlag) || !GenerateStringByLength(descriptor)) {
        return;
    }

    std::u16string u16Descriptor(descriptor.begin(), descriptor.end());

    sptr<IPCObjectStub> stub = new IPCObjectStub(u16Descriptor, serialInvokeFlag);
    sptr<IRemoteObject::DeathRecipient> recipient = new MyDeathRecipient();
    stub->AddDeathRecipient(recipient);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AddDeathRecipientFuzzTest(data, size);
    return 0;
}

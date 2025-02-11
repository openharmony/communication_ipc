/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "sendrequest_fuzzer.h"
#include "message_parcel.h"
#include "message_option.h"
#include "ipc_object_stub.h"
#include "fuzz_data_generator.h"

namespace OHOS {
void SendRequestFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    DataGenerator::Write(data, size);

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    uint32_t code;

    int8_t flags = 0x00;
    int8_t waitTime = 0x8;
    if (!GenerateUint32(code) || !GenerateInt8(flags) || !GenerateInt8(waitTime)) {
        return;
    }
    MessageOption option(flags, waitTime);

    sptr<IRemoteObject> testStub = new IPCObjectStub(u"test");
    testStub->SendRequest(code, parcel, parcel, option);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SendRequestFuzzTest(data, size);
    return 0;
}

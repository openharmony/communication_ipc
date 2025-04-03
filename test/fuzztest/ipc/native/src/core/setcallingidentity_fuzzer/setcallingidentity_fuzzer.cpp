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

#include "setcallingidentity_fuzzer.h"
#include <string>
#include "ipc_skeleton.h"
#include "message_parcel.h"

namespace OHOS {
const std::string FUZZ_TEST_IDENTITY = "test<00000000010000000001456";

void SetCallingIdentityFuzzTest1(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }

    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string identity(bufData, length);
    IPCSkeleton::SetCallingIdentity(identity, false);
}

void SetCallingIdentityFuzzTest2(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool flag = parcel.ReadBool();
    std::string identity = FUZZ_TEST_IDENTITY;
    IPCSkeleton::SetCallingIdentity(identity, flag);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SetCallingIdentityFuzzTest1(data, size);
    OHOS::SetCallingIdentityFuzzTest2(data, size);
    return 0;
}

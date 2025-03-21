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

#include "messageoption_fuzzer.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
void MessageOptionFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int flags = parcel.ReadInt32();
    int waitTime = parcel.ReadInt32();
    MessageOption messageOption(flags, waitTime);
}

void SetFlagsFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int flags = parcel.ReadInt32();
    int flagsOther = parcel.ReadInt32();
    int waitTime = parcel.ReadInt32();
    MessageOption messageOption(flags, waitTime);
    messageOption.SetFlags(flagsOther);
}

void SetWaitTimeFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int flags = parcel.ReadInt32();
    int waitTime = parcel.ReadInt32();
    int waitTimeOther = parcel.ReadInt32();
    MessageOption messageOption(flags, waitTime);
    messageOption.SetWaitTime(waitTimeOther);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MessageOptionFuzzTest(data, size);
    OHOS::SetFlagsFuzzTest(data, size);
    OHOS::SetWaitTimeFuzzTest(data, size);
    return 0;
}

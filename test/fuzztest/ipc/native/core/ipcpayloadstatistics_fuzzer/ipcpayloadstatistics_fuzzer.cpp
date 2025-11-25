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

#include "ipcpayloadstatistics_fuzzer.h"
#include "ipc_payload_statistics.h"
#include "message_parcel.h"

namespace OHOS {
void GetCountFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    pid_t pid = parcel.ReadInt32();
    IPCPayloadStatistics::GetCount(pid);
}

void GetCostFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    pid_t pid = parcel.ReadInt32();
    IPCPayloadStatistics::GetCost(pid);
}

void GetDescriptorCodesFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    pid_t pid = parcel.ReadInt32();
    IPCPayloadStatistics::GetDescriptorCodes(pid);
}

void GetDescriptorCodeCostFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    pid_t pid = parcel.ReadInt32();
    int32_t code = parcel.ReadInt32();

    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return;
    }
    std::string desc_str(bufData, length);
    std::u16string desc(desc_str.begin(), desc_str.end());
    IPCPayloadStatistics::GetDescriptorCodeCost(pid, desc, code);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::GetCountFuzzTest(data, size);
    OHOS::GetCostFuzzTest(data, size);
    OHOS::GetDescriptorCodesFuzzTest(data, size);
    OHOS::GetDescriptorCodeCostFuzzTest(data, size);
    return 0;
}

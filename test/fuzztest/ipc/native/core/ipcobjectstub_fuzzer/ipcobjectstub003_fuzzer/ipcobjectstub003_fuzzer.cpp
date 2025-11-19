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

#include "ipcobjectstub_fuzzer.h"

namespace OHOS {
void NoticeServiceDieFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    MessageOption option;
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.NoticeServiceDie(parcel, reply, option);
}

void InvokerDataBusThreadFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.InvokerDataBusThread(parcel, reply);
}

void AddAuthInfoFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t code = parcel.ReadUint32();
    MessageParcel reply;
    IPCObjectStub ipcObjectStub;
    ipcObjectStub.AddAuthInfo(parcel, reply, code);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NoticeServiceDieFuzzTest(data, size);
    OHOS::InvokerDataBusThreadFuzzTest(data, size);
    OHOS::AddAuthInfoFuzzTest(data, size);
    return 0;
}

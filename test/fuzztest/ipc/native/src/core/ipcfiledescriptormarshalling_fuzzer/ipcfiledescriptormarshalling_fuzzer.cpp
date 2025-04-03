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

#include "ipcfiledescriptormarshalling_fuzzer.h"
#include "ipc_file_descriptor.h"
#include "parcel.h"

namespace OHOS {
void IPCFileDescriptorMarshallingFuzzTest1(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OHOS::Parcel parcel;
    parcel.WriteBuffer(data, size);

    IPCFileDescriptor fileDesc;
    (void)fileDesc.Marshalling(parcel);
}

void IPCFileDescriptorMarshallingFuzzTest2(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OHOS::Parcel parcel;
    parcel.WriteBuffer(data, size);
    int fd = parcel.ReadInt32();

    IPCFileDescriptor fileDesc;
    fileDesc.SetFd(fd);
    (void)fileDesc.Marshalling(parcel);
}

void IPCFileDescriptorMarshallingFuzzTest3(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OHOS::Parcel parcel;
    parcel.WriteBuffer(data, size);

    sptr<IPCFileDescriptor> fileDesc = new IPCFileDescriptor();
    (void)IPCFileDescriptor::Marshalling(parcel, fileDesc);
}

void IPCFileDescriptorMarshallingFuzzTest4(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OHOS::Parcel parcel;
    parcel.WriteBuffer(data, size);
    int fd = parcel.ReadInt32();

    sptr<IPCFileDescriptor> fileDesc = new IPCFileDescriptor();
    fileDesc->SetFd(fd);
    (void)IPCFileDescriptor::Marshalling(parcel, fileDesc);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::IPCFileDescriptorMarshallingFuzzTest1(data, size);
    OHOS::IPCFileDescriptorMarshallingFuzzTest2(data, size);
    OHOS::IPCFileDescriptorMarshallingFuzzTest3(data, size);
    OHOS::IPCFileDescriptorMarshallingFuzzTest4(data, size);
    return 0;
}

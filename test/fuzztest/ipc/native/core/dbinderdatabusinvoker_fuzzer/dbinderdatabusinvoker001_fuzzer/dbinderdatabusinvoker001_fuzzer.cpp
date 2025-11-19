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

#include "dbinderdatabusinvoker_fuzzer.h"
#include "dbinder_base_invoker_process.h"
#include "dbinder_databus_invoker.h"
#include "securec.h"

using OHOS::DatabusSocketListener;

namespace OHOS {

static void AcquireHandleFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t handle = -1;
    if (!parcel.ReadInt32(handle)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.AcquireHandle(handle);
}

static void ReleaseHandleFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t handle = -1;
    if (!parcel.ReadInt32(handle)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.ReleaseHandle(handle);
    invoker.StopWorkThread();
}

static void FlattenObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    DBinderDatabusInvoker invoker;
    invoker.FlattenObject(parcel, nullptr);
}

static void UnflattenObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    DBinderDatabusInvoker invoker;
    (void)invoker.UnflattenObject(parcel);
}

static void ReadFileDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    DBinderDatabusInvoker invoker;
    (void)invoker.ReadFileDescriptor(parcel);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AcquireHandleFuzzTest(data, size);
    OHOS::ReleaseHandleFuzzTest(data, size);
    OHOS::FlattenObjectFuzzTest(data, size);
    OHOS::UnflattenObjectFuzzTest(data, size);
    OHOS::ReadFileDescriptorFuzzTest(data, size);
    return 0;
}

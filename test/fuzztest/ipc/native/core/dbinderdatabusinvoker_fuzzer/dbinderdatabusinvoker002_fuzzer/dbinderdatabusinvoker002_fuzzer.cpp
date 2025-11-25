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

static void WriteFileDescriptorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(int32_t) + sizeof(bool))) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t fd = -1;
    if (!parcel.ReadInt32(fd)) {
        return;
    }

    bool takeOwnership = false;
    if (!parcel.ReadBool(takeOwnership)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.WriteFileDescriptor(parcel, fd, takeOwnership);
    invoker.GetCallerSid();
    invoker.GetCallerPid();
    invoker.GetCallerRealPid();
    invoker.GetCallerUid();
    invoker.GetCallerTokenID();
    invoker.GetSelfTokenID();
    invoker.GetSelfFirstCallerTokenID();
    invoker.GetStatus();
    invoker.GetClientFd();
    invoker.IsLocalCalling();
    invoker.GetLocalDeviceID();
    invoker.GetCallerDeviceID();
}

static void UpdateClientSessionFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 0) {
        return;
    }

    std::string serviceName(reinterpret_cast<const char *>(data), size);
    std::string deviceId(reinterpret_cast<const char *>(data), size);
    uint64_t stubIndex = 0;
    uint32_t tokenId = 0;
    auto dbinderSession = std::make_shared<DBinderSessionObject>(serviceName, deviceId, stubIndex, nullptr, tokenId);
    if (dbinderSession == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    (void)invoker.UpdateClientSession(dbinderSession);
}

static void QueryClientSessionObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    uint32_t databusHandle = -1;
    if (!parcel.ReadUint32(databusHandle)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.QueryClientSessionObject(databusHandle);
}

static void QueryServerSessionObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    uint32_t handle = -1;
    if (!parcel.ReadUint32(handle)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.QueryServerSessionObject(handle);
}


static void OnDatabusSessionServerSideClosedFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t socketId = -1;
    if (!parcel.ReadInt32(socketId)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.OnDatabusSessionServerSideClosed(socketId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::WriteFileDescriptorFuzzTest(data, size);
    OHOS::UpdateClientSessionFuzzTest(data, size);
    OHOS::QueryClientSessionObjectFuzzTest(data, size);
    OHOS::QueryServerSessionObjectFuzzTest(data, size);
    OHOS::OnDatabusSessionServerSideClosedFuzzTest(data, size);
    return 0;
}

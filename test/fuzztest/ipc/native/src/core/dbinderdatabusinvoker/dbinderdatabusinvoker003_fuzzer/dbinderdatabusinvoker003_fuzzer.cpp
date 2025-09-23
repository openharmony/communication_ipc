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

static void OnDatabusSessionClientSideClosedFuzzTest(const uint8_t *data, size_t size)
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
    (void)invoker.OnDatabusSessionClientSideClosed(socketId);
}

static void OnReceiveNewConnectionFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < (sizeof(int32_t) + sizeof(int) + sizeof(int))) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    int32_t socketId = -1;
    int32_t peerPid = -1;
    int32_t peerUid = -1;
    if (!parcel.ReadInt32(socketId) || !parcel.ReadInt32(peerPid) || !parcel.ReadInt32(peerUid)) {
        return;
    }

    std::string peerName;
    std::string networkId;
    size_t strSize = parcel.GetReadableBytes();
    if (strSize > 0) {
        const char *buf = reinterpret_cast<const char *>(parcel.ReadBuffer(strSize));
        if (buf != nullptr) {
            peerName.assign(buf, strSize);
            networkId.assign(buf, strSize);
        }
    }
    DBinderDatabusInvoker invoker;
    (void)invoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, networkId);
}

static void SetCallingIdentityFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(bool)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    bool flag = false;
    if (!parcel.ReadBool(flag)) {
        return;
    }

    std::string identity;
    size_t strSize = parcel.GetReadableBytes();
    if (strSize > 0) {
        const char *buf = reinterpret_cast<const char *>(parcel.ReadBuffer(strSize));
        if (buf != nullptr) {
            identity.assign(buf, strSize);
        }
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.SetCallingIdentity(identity, flag);
    (void)invoker.ResetCallingIdentity();
}

static void TriggerSystemIPCThreadReclaimFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(bool)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    bool enable = false;
    if (!parcel.ReadBool(enable)) {
        return;
    }

    DBinderDatabusInvoker invoker;
    invoker.TriggerSystemIPCThreadReclaim();
    invoker.EnableIPCThreadReclaim(enable);
}

static void MakeThreadProcessInfoFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    Parcel parcel;
    if (!parcel.WriteBuffer(data, size)) {
        return;
    }

    uint32_t handle = 0;
    if (!parcel.ReadUint32(handle)) {
        return;
    }

    std::string strData;
    size_t strSize = parcel.GetReadableBytes();
    if (strSize > 0) {
        const char *buf = reinterpret_cast<const char *>(parcel.ReadBuffer(strSize));
        if (buf != nullptr) {
            strData.assign(buf, strSize);
        }
    }

    DBinderDatabusInvoker invoker;
    (void)invoker.MakeThreadProcessInfo(handle, strData.c_str(), strData.size());
    (void)invoker.MakeThreadProcessInfo(handle, nullptr, 0);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::OnDatabusSessionClientSideClosedFuzzTest(data, size);
    OHOS::OnReceiveNewConnectionFuzzTest(data, size);
    OHOS::SetCallingIdentityFuzzTest(data, size);
    OHOS::TriggerSystemIPCThreadReclaimFuzzTest(data, size);
    OHOS::MakeThreadProcessInfoFuzzTest(data, size);
    return 0;
}

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

#include "ipcobjectproxy_fuzzer.h"

namespace OHOS {
IPCObjectProxy* CreateIPCObjectProxy(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return nullptr;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t handle = parcel.ReadInt32();
    int32_t proto = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        return nullptr;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        return nullptr;
    }
    std::string descriptor_str(bufData, length);
    std::u16string descriptor(descriptor_str.begin(), descriptor_str.end());
    IPCObjectProxy *proxy = new IPCObjectProxy(handle, descriptor, proto);
    return proxy;
}

void IPCObjectProxyFuzzTestTest(const uint8_t *data, size_t size)
{
    IPCObjectProxy *proxy = CreateIPCObjectProxy(data, size);
    delete proxy;
}

void SendRequestFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    IPCObjectProxy *proxy = CreateIPCObjectProxy(data, size);
    if (proxy == nullptr) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    uint32_t code = parcel.ReadUint32();
    MessageParcel reply_parcel;
    MessageOption option;
    proxy->SendRequest(code, parcel, reply_parcel, option);
    delete proxy;
}

void DumpFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    IPCObjectProxy *proxy = CreateIPCObjectProxy(data, size);
    if (proxy == nullptr) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    int32_t fd = parcel.ReadInt32();
    size_t length = parcel.GetReadableBytes();
    if (length == 0) {
        delete proxy;
        return;
    }
    const char *bufData = reinterpret_cast<const char *>(parcel.ReadBuffer(length));
    if (bufData == nullptr) {
        delete proxy;
        return;
    }
    std::string descriptor_str(bufData, length);
    std::u16string descriptor(descriptor_str.begin(), descriptor_str.end());
    std::vector<std::u16string> args;
    args.push_back(descriptor);
    proxy->Dump(fd, args);
    delete proxy;
}

void OnFirstStrongRefFuzzTest(const uint8_t *data, size_t size)
{
    IPCObjectProxy *proxy = CreateIPCObjectProxy(data, size);
    if (proxy == nullptr) {
        return;
    }
    proxy->OnFirstStrongRef(data);
    delete proxy;
}

void OnLastStrongRefFuzzTest(const uint8_t *data, size_t size)
{
    IPCObjectProxy *proxy = CreateIPCObjectProxy(data, size);
    if (proxy == nullptr) {
        return;
    }
    proxy->OnLastStrongRef(data);
    delete proxy;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::IPCObjectProxyFuzzTestTest(data, size);
    OHOS::SendRequestFuzzTest(data, size);
    OHOS::DumpFuzzTest(data, size);
    OHOS::OnFirstStrongRefFuzzTest(data, size);
    OHOS::OnLastStrongRefFuzzTest(data, size);
    return 0;
}

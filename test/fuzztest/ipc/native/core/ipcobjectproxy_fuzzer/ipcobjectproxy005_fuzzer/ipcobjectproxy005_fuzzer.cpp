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
void RemoveDeathRecipientFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    proxy->RemoveDeathRecipient(nullptr);
    sptr<MockDeathRecipient> recipient = nullptr;
    sptr<IPCObjectProxy::DeathRecipientAddrInfo> info =
        sptr<IPCObjectProxy::DeathRecipientAddrInfo>::MakeSptr(recipient);
    recipient = sptr<MockDeathRecipient>::MakeSptr();
    if (recipient == nullptr) {
        return;
    }
    info = sptr<IPCObjectProxy::DeathRecipientAddrInfo>::MakeSptr(recipient);
    if (info == nullptr) {
        return;
    }
    proxy->recipients_.push_back(info);
    proxy->RemoveDeathRecipient(recipient);
    proxy->SetObjectDied(true);
    proxy->RemoveDeathRecipient(recipient);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::RemoveDeathRecipientFuzzTest(provider);
    return 0;
}

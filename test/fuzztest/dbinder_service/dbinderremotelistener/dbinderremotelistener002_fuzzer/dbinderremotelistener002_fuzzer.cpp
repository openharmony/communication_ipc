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

#include "dbinderremotelistener_fuzzer.h"

namespace OHOS {
    void SendDataToRemoteTest(FuzzedDataProvider &provider)
    {
        std::string networkId = provider.ConsumeRandomLengthString();
        DHandleEntryTxRx msg;
        msg.head.len = sizeof(DHandleEntryTxRx);
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        dBinderRemoteListener->SendDataToRemote(networkId, nullptr);
        dBinderRemoteListener->SendDataToRemote(networkId, &msg);
    }

    void SendDataReplyTest(FuzzedDataProvider &provider)
    {
        std::string networkId = provider.ConsumeRandomLengthString();
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        dBinderRemoteListener->SendDataReply(networkId, nullptr);
        DHandleEntryTxRx msg;
        msg.head.len = sizeof(DHandleEntryTxRx);
        dBinderRemoteListener->SendDataReply(networkId, &msg);
    }

    void ShutdownSocketTest(FuzzedDataProvider &provider)
    {
        std::string networkId = provider.ConsumeRandomLengthString();
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        dBinderRemoteListener->ShutdownSocket(networkId);
        int32_t socket = provider.ConsumeIntegral<int32_t>();
        dBinderRemoteListener->clientSocketInfos_[networkId] = socket;
        dBinderRemoteListener->ShutdownSocket(networkId);
    }

    void OnBytesReceivedTest(FuzzedDataProvider &provider)
    {
        DHandleEntryTxRx msg;
        msg.transType = provider.ConsumeIntegral<uint32_t>();
        msg.dBinderCode = provider.ConsumeIntegral<uint32_t>();
        msg.fromPort = provider.ConsumeIntegral<uint16_t>();
        msg.toPort = provider.ConsumeIntegral<uint16_t>();
        msg.stubIndex = provider.ConsumeIntegral<uint64_t>();
        msg.seqNumber = provider.ConsumeIntegral<uint32_t>();
        msg.binderObject = provider.ConsumeIntegral<binder_uintptr_t>();
        msg.stub = provider.ConsumeIntegral<binder_uintptr_t>();
        msg.serviceNameLength = provider.ConsumeIntegral<uint16_t>();
        msg.pid = provider.ConsumeIntegral<uint32_t>();
        msg.uid = provider.ConsumeIntegral<uint32_t>();
        msg.head.len = sizeof(DHandleEntryTxRx);
        auto dBinderRemoteListener = std::make_shared<DBinderRemoteListener>();
        if (dBinderRemoteListener == nullptr) {
            return ;
        }
        int32_t socket = provider.ConsumeIntegral<int32_t>();
        dBinderRemoteListener->OnBytesReceived(socket, &msg, sizeof(DHandleEntryTxRx));
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SendDataToRemoteTest(provider);
    OHOS::SendDataReplyTest(provider);
    OHOS::ShutdownSocketTest(provider);
    OHOS::OnBytesReceivedTest(provider);
    return 0;
}

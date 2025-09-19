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

void OnReceiveNewConnectionFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    int peerPid = provider.ConsumeIntegral<int>();
    int peerUid = provider.ConsumeIntegral<int>();
    std::string peerName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    int32_t tokenId = provider.ConsumeIntegral<int32_t>();
    std::string deviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    sptr<IPCObjectStub> stub = sptr<IPCObjectStub>::MakeSptr();
    if (stub == nullptr) {
        return;
    }
    current->AttachCommAuthInfo(stub.GetRefPtr(), peerPid, peerUid, tokenId, deviceId);
    DBinderDatabusInvoker invoker;
    invoker.OnReceiveNewConnection(socketId, peerPid, peerUid, peerName, deviceId);
}

void OnRawDataAvailableFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_RAWDATA_SIZE);
    std::vector<char> bytes = provider.ConsumeBytes<char>(bytesSize);
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    uint64_t seqNumber = provider.ConsumeIntegral<uint64_t>();
    DBinderDatabusInvoker invoker;
    invoker.OnRawDataAvailable(socketId, seqNumber, bytes.data(), bytes.size());
}

void OnSendMessageFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = CreateDBinderSessionObject(provider);
    if (sessionOfPeer == nullptr) {
        return;
    }
    DBinderDatabusInvoker invoker;
    invoker.OnSendMessage(nullptr);
    invoker.OnSendMessage(sessionOfPeer);
}

void SendDataFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<BufferObject> sessionBuff = std::make_shared<BufferObject>();
    if (sessionBuff == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    DBinderDatabusInvoker invoker;
    invoker.SendData(sessionBuff, socketId);
}

void OnSendRawDataFuzzTest(FuzzedDataProvider &provider)
{
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(1, 50);
    std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(bytesSize);
    std::shared_ptr<DBinderSessionObject> session = CreateDBinderSessionObject(provider);
    if (session == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    session->SetSocketId(socketId);
    DBinderDatabusInvoker invoker;
    invoker.OnSendRawData(nullptr, bytes.data(), bytes.size());
    invoker.OnSendRawData(session, bytes.data(), bytes.size());
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    //5
    FuzzedDataProvider provider(data, size);
    OHOS::OnReceiveNewConnectionFuzzTest(provider);
    OHOS::OnRawDataAvailableFuzzTest(provider);
    OHOS::OnSendMessageFuzzTest(provider);
    OHOS::SendDataFuzzTest(provider);
    OHOS::OnSendRawDataFuzzTest(provider);
    return 0;
}

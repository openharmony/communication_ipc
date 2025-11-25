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

#include "databussocketlistener_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "databus_socket_listener.h"
#include "securec.h"

using OHOS::DatabusSocketListener;

namespace OHOS {
static constexpr size_t STR_MAX_LEN = 100;
static std::string TEST_SOCKET_NAME = "DBinder1_1";
static std::string TEST_SOCKET_PEER_NAME = "DBinderService";
static std::string TEST_SOCKET_PEER_NETWORKID = "wad213hkad213jh123jk213j1h2312h3jk12dadadeawd721hledhjlad22djhla";

static void ShutdownSocketFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size <= sizeof(int32_t)) {
        return;
    }

    int32_t socketId = -1;
    if (memcpy_s(&socketId, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        return;
    }

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }

    listener->ShutdownSocket(socketId);
}

static void EraseDeviceLockFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::string ownName(reinterpret_cast<const char *>(data), size);
    std::string peerName(reinterpret_cast<const char *>(data), size);
    std::string networkId(reinterpret_cast<const char *>(data), size);

    OHOS::DBinderSocketInfo info1(ownName, TEST_SOCKET_PEER_NAME, TEST_SOCKET_PEER_NETWORKID);
    OHOS::DBinderSocketInfo info2(TEST_SOCKET_NAME, peerName, TEST_SOCKET_PEER_NETWORKID);
    OHOS::DBinderSocketInfo info3(TEST_SOCKET_NAME, TEST_SOCKET_PEER_NAME, networkId);

    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    listener->EraseDeviceLock(info1);
    listener->EraseDeviceLock(info2);
    listener->EraseDeviceLock(info3);
    listener->RemoveSessionName();
}

static void ClientOnBindFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    int32_t socketId = provider.ConsumeIntegral<int32_t>();
    std::string name = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string networkId = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string pkgName = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    int32_t dataType = provider.ConsumeIntegral<int32_t>();
    PeerSocketInfo info = {
        .name = const_cast<char *>(name.c_str()),
        .networkId = const_cast<char *>(networkId.c_str()),
        .pkgName = const_cast<char *>(pkgName.c_str()),
        .dataType = static_cast<TransDataType>(dataType),
    };
    listener->ClientOnBind(socketId, info);
}

static void GetPidAndUidFromServiceNameFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<DatabusSocketListener> listener = DelayedSingleton<DatabusSocketListener>::GetInstance();
    if (listener == nullptr) {
        return;
    }
    std::string serviceName = provider.ConsumeRandomLengthString(STR_MAX_LEN);
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    listener->GetPidAndUidFromServiceName(serviceName, pid, uid);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ShutdownSocketFuzzTest(data, size);
    OHOS::EraseDeviceLockFuzzTest(data, size);

    FuzzedDataProvider provider(data, size);
    OHOS::ClientOnBindFuzzTest(provider);
    OHOS::GetPidAndUidFromServiceNameFuzzTest(provider);
    return 0;
}

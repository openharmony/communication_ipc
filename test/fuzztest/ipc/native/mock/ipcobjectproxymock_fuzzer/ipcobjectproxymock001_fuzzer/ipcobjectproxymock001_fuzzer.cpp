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

#include "ipcobjectproxymock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class IPCObjectProxyInterface {
public:
    IPCObjectProxyInterface() {};
    virtual ~IPCObjectProxyInterface() {};

    virtual bool WriteUint32(uint32_t value) = 0;
    virtual uint32_t ReadUint32() = 0;
    virtual bool WriteString(const std::string &value) = 0;
    virtual int SendRequestInner(bool isLocal, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) = 0;
};

class IPCObjectProxyInterfaceMock : public IPCObjectProxyInterface {
public:
    IPCObjectProxyInterfaceMock();
    ~IPCObjectProxyInterfaceMock() override;

    MOCK_METHOD(bool, WriteUint32, (uint32_t value), (override));
    MOCK_METHOD(uint32_t, ReadUint32, (), (override));
    MOCK_METHOD(bool, WriteString, (const std::string &value), (override));
    MOCK_METHOD(int, SendRequestInner,
        (bool isLocal, uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option), (override));
};

static void *g_interface = nullptr;

IPCObjectProxyInterfaceMock::IPCObjectProxyInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCObjectProxyInterfaceMock::~IPCObjectProxyInterfaceMock()
{
    g_interface = nullptr;
}

static IPCObjectProxyInterfaceMock *GetIPCObjectProxyInterfaceMock()
{
    return reinterpret_cast<IPCObjectProxyInterfaceMock *>(g_interface);
}

extern "C" {
bool Parcel::WriteUint32(uint32_t value)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetIPCObjectProxyInterfaceMock()->WriteUint32(value);
}

uint32_t Parcel::ReadUint32()
{
    if (g_interface == nullptr) {
        return 0;
    }
    return GetIPCObjectProxyInterfaceMock()->ReadUint32();
}

bool Parcel::WriteString(const std::string &value)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetIPCObjectProxyInterfaceMock()->WriteString(value);
}

int IPCObjectProxy::SendRequestInner(bool isLocal, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (g_interface == nullptr) {
        return 0;
    }
    return GetIPCObjectProxyInterfaceMock()->SendRequestInner(isLocal, code, data, reply, option);
}
}

void GetSessionNameForPidUidFuzzTest001(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    int pid = provider.ConsumeIntegral<int>();
    int uid = provider.ConsumeIntegral<int>();
    NiceMock<IPCObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, WriteUint32(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, SendRequestInner(_, _, _, _, _)).WillOnce(Return(ERR_NONE));
    EXPECT_CALL(mock, ReadUint32()).WillRepeatedly(Return(IRemoteObject::IF_PROT_DEFAULT));
    proxy->GetSessionNameForPidUid(pid, uid);
}

void RemoveSessionNameFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    NiceMock<IPCObjectProxyInterfaceMock> mock;
    EXPECT_CALL(mock, WriteString(_)).WillOnce(Return(false));
    const std::string sessionName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    proxy->RemoveSessionName(sessionName);
}

void WaitForInitFuzzTest(FuzzedDataProvider &provider)
{
    sptr<IPCObjectProxy> proxy = CreateIPCObjectProxy(provider);
    if (proxy == nullptr) {
        return;
    }
    proxy->isFinishInit_ = true;
    proxy->proto_ = IRemoteObject::IF_PROT_DATABUS;
    proxy->WaitForInit(nullptr);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetSessionNameForPidUidFuzzTest001(provider);
    OHOS::RemoveSessionNameFuzzTest(provider);
    OHOS::WaitForInitFuzzTest(provider);
    return 0;
}
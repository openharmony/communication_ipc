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

#include "dbinderdatabusinvokermock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterface() {};
    virtual ~DBinderDataBusInvokerInterface() {};

    virtual bool StrToUint64(const std::string &str, uint64_t &value) = 0;
};

class DBinderDataBusInvokerInterfaceMock : public DBinderDataBusInvokerInterface {
public:
    DBinderDataBusInvokerInterfaceMock();
    ~DBinderDataBusInvokerInterfaceMock() override;

    MOCK_METHOD(bool, StrToUint64, (const std::string &str, uint64_t &value), (override));
};

static void *g_interface = nullptr;

DBinderDataBusInvokerInterfaceMock::DBinderDataBusInvokerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

DBinderDataBusInvokerInterfaceMock::~DBinderDataBusInvokerInterfaceMock()
{
    g_interface = nullptr;
}

static DBinderDataBusInvokerInterfaceMock *GetDBinderDataBusInvokerInterfaceMock()
{
    return reinterpret_cast<DBinderDataBusInvokerInterfaceMock *>(g_interface);
}

extern "C" {
bool ProcessSkeleton::StrToUint64(const std::string &str, uint64_t &value)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetDBinderDataBusInvokerInterfaceMock()->StrToUint64(str, value);
}
}

void SetCallingIdentityFuzzTest001(FuzzedDataProvider &provider)
{
    DBinderDatabusInvoker invoker;
    size_t min = DBinderDatabusInvoker::ACCESS_TOKEN_MAX_LEN + DEVICEID_LENGTH;
    size_t len = provider.ConsumeIntegralInRange<size_t>(min, min + min);
    std::string deviceId = std::string(len, '1');
    uint64_t token = (static_cast<uint64_t>(1000) << PID_LEN) | 2000;
    std::string tokenStr = std::to_string(token);
    std::string identity = deviceId + tokenStr;

    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, StrToUint64(_, _)).WillRepeatedly(Return(true));
    invoker.SetCallingIdentity(identity, false);
}

void SetCallingIdentityFuzzTest002(FuzzedDataProvider &provider)
{
    DBinderDatabusInvoker invoker;
    size_t min = DBinderDatabusInvoker::ACCESS_TOKEN_MAX_LEN + DEVICEID_LENGTH;
    size_t len = provider.ConsumeIntegralInRange<size_t>(min, min + min);
    std::string deviceId = std::string(len, '1');
    uint64_t token = (static_cast<uint64_t>(1000) << PID_LEN) | 2000;
    std::string tokenStr = std::to_string(token);
    std::string identity = deviceId + tokenStr;
    NiceMock<DBinderDataBusInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, StrToUint64(_, _)).WillOnce(Return(false));
    invoker.SetCallingIdentity(identity, false);

    EXPECT_CALL(mock, StrToUint64(_, _)).WillOnce(Return(true)).WillOnce(Return(false));
    invoker.SetCallingIdentity(identity, false);

    EXPECT_CALL(mock, StrToUint64(_, _)).WillRepeatedly(Return(true));
    identity.resize(DEVICEID_LENGTH + 1, '1');
    invoker.SetCallingIdentity(identity, false);

    identity.resize(DBinderDatabusInvoker::ACCESS_TOKEN_MAX_LEN + DEVICEID_LENGTH, '1');
    invoker.SetCallingIdentity(identity, false);
}

void HasRawDataPackageFuzzTest(FuzzedDataProvider &provider)
{
    dbinder_transaction_data tr;
    tr.magic = provider.ConsumeIntegral<uint32_t>();
    tr.cmd = provider.ConsumeIntegral<int32_t>();
    ssize_t len = MAX_RAWDATA_SIZE + 1;
    tr.sizeOfSelf = len;
    DBinderDatabusInvoker invoker;
    invoker.HasRawDataPackage(reinterpret_cast<const char *>(&tr), len);

    tr.magic = DBINDER_MAGICWORD;
    tr.cmd = BC_SEND_RAWDATA;
    invoker.HasRawDataPackage(reinterpret_cast<const char *>(&tr), len);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SetCallingIdentityFuzzTest001(provider);
    OHOS::SetCallingIdentityFuzzTest002(provider);
    OHOS::HasRawDataPackageFuzzTest(provider);
    return 0;
}
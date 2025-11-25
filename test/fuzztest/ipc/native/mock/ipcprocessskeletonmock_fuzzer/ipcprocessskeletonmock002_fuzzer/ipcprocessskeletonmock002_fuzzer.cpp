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

#include "ipcprocessskeletonmock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class IPCProcessSkeletonInterface {
public:
    IPCProcessSkeletonInterface() {};
    virtual ~IPCProcessSkeletonInterface() {};

    virtual ProcessSkeleton *GetInstance() = 0;
};

class IPCProcessSkeletonInterfaceMock : public IPCProcessSkeletonInterface {
public:
    IPCProcessSkeletonInterfaceMock();
    ~IPCProcessSkeletonInterfaceMock() override;

    MOCK_METHOD(ProcessSkeleton *, GetInstance, (), (override));
};

static void *g_interface = nullptr;

IPCProcessSkeletonInterfaceMock::IPCProcessSkeletonInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IPCProcessSkeletonInterfaceMock::~IPCProcessSkeletonInterfaceMock()
{
    g_interface = nullptr;
}

static IPCProcessSkeletonInterface *GetIPCProcessSkeletonInterface()
{
    return reinterpret_cast<IPCProcessSkeletonInterface *>(g_interface);
}

extern "C" {
ProcessSkeleton *ProcessSkeleton::GetInstance()
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIPCProcessSkeletonInterface()->GetInstance();
}
}

void IsContainsObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    sptr<IPCObjectStub> object = new (std::nothrow) IPCObjectStub(descriptor16);
    if (current == nullptr || object == nullptr) {
        return;
    }
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).WillRepeatedly(Return(nullptr));
    current->IsContainsObject(object.GetRefPtr());
}

void DetachObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    sptr<IPCObjectStub> object = new (std::nothrow) IPCObjectStub(descriptor16);
    if (current == nullptr || object == nullptr) {
        return;
    }
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).WillRepeatedly(Return(nullptr));
    current->DetachObject(object.GetRefPtr());
}

void AttachObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    sptr<IPCObjectStub> object = new (std::nothrow) IPCObjectStub(descriptor16);
    if (current == nullptr || object == nullptr) {
        return;
    }
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).WillRepeatedly(Return(nullptr));
    bool lockFlag = provider.ConsumeBool();
    current->AttachObject(object.GetRefPtr(), lockFlag);
}

void QueryObjectFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).WillRepeatedly(Return(nullptr));
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    bool lockFlag = provider.ConsumeBool();
    current->QueryObject(descriptor16, lockFlag);
}

void SetIPCProxyLimitFuzzTest(FuzzedDataProvider &provider)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    NiceMock<IPCProcessSkeletonInterfaceMock> mock;
    EXPECT_CALL(mock, GetInstance()).WillRepeatedly(Return(nullptr));
    uint64_t num = provider.ConsumeIntegral<uint64_t>();
    current->SetIPCProxyLimit(num, nullptr);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::IsContainsObjectFuzzTest(provider);
    OHOS::DetachObjectFuzzTest(provider);
    OHOS::AttachObjectFuzzTest(provider);
    OHOS::QueryObjectFuzzTest(provider);
    OHOS::SetIPCProxyLimitFuzzTest(provider);
    return 0;
}

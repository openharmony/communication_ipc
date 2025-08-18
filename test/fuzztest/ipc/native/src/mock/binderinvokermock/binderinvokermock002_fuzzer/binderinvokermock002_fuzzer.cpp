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

#include "binderinvokermock_fuzzer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class BinderInvokerInterface {
public:
    BinderInvokerInterface() {};
    virtual ~BinderInvokerInterface() {};

    virtual bool WriteUint32(uint32_t value) = 0;
    virtual bool RewindWrite(size_t newPosition) = 0;
    virtual bool WritePointer(uintptr_t value) = 0;
    virtual int FlushCommands(IRemoteObject *object) = 0;
    virtual int SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) = 0;
    virtual bool SetAllocator(Allocator *allocator) = 0;
};

class BinderInvokerInterfaceMock : public BinderInvokerInterface {
public:
    BinderInvokerInterfaceMock();
    ~BinderInvokerInterfaceMock() override;

    MOCK_METHOD(bool, WriteUint32, (uint32_t value), (override));
    MOCK_METHOD(bool, RewindWrite, (size_t newPosition), (override));
    MOCK_METHOD(bool, WritePointer, (uintptr_t value), (override));
    MOCK_METHOD(int, FlushCommands, (IRemoteObject * object), (override));
    MOCK_METHOD(int, SendRequest, (int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option), (override));
    MOCK_METHOD(bool, SetAllocator, (Allocator * allocator), (override));
};

static void *g_interface = nullptr;

BinderInvokerInterfaceMock::BinderInvokerInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

BinderInvokerInterfaceMock::~BinderInvokerInterfaceMock()
{
    g_interface = nullptr;
}

static BinderInvokerInterfaceMock *GetBinderInvokerInterfaceMock()
{
    return reinterpret_cast<BinderInvokerInterfaceMock *>(g_interface);
}

extern "C" {
bool Parcel::WriteUint32(uint32_t value)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->WriteUint32(value);
}

bool Parcel::RewindWrite(size_t newPosition)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->RewindWrite(newPosition);
}

bool Parcel::WritePointer(uintptr_t value)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->WritePointer(value);
}

int BinderInvoker::FlushCommands(IRemoteObject *object)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->FlushCommands(object);
}

int BinderInvoker::SendRequest(int handle, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (g_interface == nullptr) {
        return false;
    }
    return GetBinderInvokerInterfaceMock()->SendRequest(handle, code, data, reply, option);
}

bool Parcel::SetAllocator(Allocator *allocator)
{
    if (g_interface == nullptr) {
        return true;
    }
    return GetBinderInvokerInterfaceMock()->SetAllocator(allocator);
}
}

static void FreeBufferFuzzTest(FuzzedDataProvider &provider)
{
    std::string data = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, WriteUint32).WillOnce(Return(false));
    BinderInvoker invoker;
    invoker.FreeBuffer(const_cast<char*>(data.c_str()));

    EXPECT_CALL(mock, WriteUint32).WillOnce(Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(Return(false));
    EXPECT_CALL(mock, RewindWrite).WillOnce(Return(false));
    invoker.FreeBuffer(const_cast<char*>(data.c_str()));

    EXPECT_CALL(mock, WriteUint32).WillOnce(Return(true));
    EXPECT_CALL(mock, WritePointer).WillOnce(Return(true));
    EXPECT_CALL(mock, FlushCommands(_)).WillRepeatedly(testing::Return(-1));
    invoker.FreeBuffer(const_cast<char*>(data.c_str()));
}

static void AddCommAuthFuzzTest(FuzzedDataProvider &provider)
{
    int32_t handle = 0;
    flat_binder_object flat;
    BinderInvoker invoker;
    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, SendRequest(handle, GET_PID_UID, _, _, _)).WillRepeatedly(Return(ERR_NONE));
    invoker.AddCommAuth(handle, &flat);

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        return;
    }
    std::string serviceName = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string serverDeviceId = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    uint64_t stubIndex = provider.ConsumeIntegral<uint64_t>();
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DBinderSessionObject> session =
        std::make_shared<DBinderSessionObject>(serviceName, serverDeviceId, stubIndex, nullptr, tokenId);
    flat.handle = handle;
    current->ProxyAttachDBinderSession(handle, session);
    invoker.AddCommAuth(handle, &flat);
}

static void HandleReplyFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel reply;
    bool isStubRet = provider.ConsumeBool();
    BinderInvoker invoker;
    binder_transaction_data data;
    invoker.input_.WriteBuffer(&data, sizeof(data));
    invoker.HandleReply(nullptr, isStubRet);

    invoker.input_.WriteBuffer(&data, sizeof(data));
    NiceMock<BinderInvokerInterfaceMock> mock;
    EXPECT_CALL(mock, SetAllocator(_)).WillOnce(Return(false));
    invoker.HandleReply(&reply, isStubRet);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FreeBufferFuzzTest(provider);
    OHOS::AddCommAuthFuzzTest(provider);
    OHOS::HandleReplyFuzzTest(provider);
    return 0;
}
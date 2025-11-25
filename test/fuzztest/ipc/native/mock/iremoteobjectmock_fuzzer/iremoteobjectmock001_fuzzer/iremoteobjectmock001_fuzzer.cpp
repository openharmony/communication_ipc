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

#include "iremoteobjectmock_fuzzer.h"

#include "binder_invoker.h"
#include "ipc_object_stub.h"
#include "ipc_thread_skeleton.h"
#include "iremote_invoker.h"
#include "message_parcel.h"
#include "string_ex.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static constexpr size_t MAX_STR_LEN = 100;

class IRemoteObjectInterface {
public:
    IRemoteObjectInterface() {};
    virtual ~IRemoteObjectInterface() {};

    virtual IRemoteInvoker *GetRemoteInvoker(int) = 0;
};

class IRemoteObjectInterfaceMock : public IRemoteObjectInterface {
public:
    IRemoteObjectInterfaceMock();
    ~IRemoteObjectInterfaceMock() override;

    MOCK_METHOD1(GetRemoteInvoker, IRemoteInvoker *(int));
};

static void *g_interface = nullptr;

IRemoteObjectInterfaceMock::IRemoteObjectInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

IRemoteObjectInterfaceMock::~IRemoteObjectInterfaceMock()
{
    g_interface = nullptr;
}

static IRemoteObjectInterface *GetIRemoteObjectInterface()
{
    return reinterpret_cast<IRemoteObjectInterface *>(g_interface);
}

extern "C" {
IRemoteInvoker *IPCThreadSkeleton::GetRemoteInvoker(int proto)
{
    if (g_interface == nullptr) {
        return nullptr;
    }
    return GetIRemoteObjectInterface()->GetRemoteInvoker(proto);
}
}

void MarshallingFuzzTest001(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    sptr<IRemoteObject> object = sptr<IPCObjectStub>::MakeSptr(descriptor16);
    if (object == nullptr) {
        return;
    }
    NiceMock<IRemoteObjectInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(Return(nullptr));
    Parcel parcel;
    object->Marshalling(parcel);
}

void MarshallingFuzzTest002(FuzzedDataProvider &provider)
{
    std::string descriptor = provider.ConsumeRandomLengthString(MAX_STR_LEN);
    std::u16string descriptor16 = Str8ToStr16(descriptor);
    sptr<IRemoteObject> object = sptr<IPCObjectStub>::MakeSptr(descriptor16);
    if (object == nullptr) {
        return;
    }
    NiceMock<IRemoteObjectInterfaceMock> mock;
    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(Return(nullptr));
    Parcel parcel;
    object->Marshalling(parcel, object);
    IRemoteInvoker *invoker = new (std::nothrow) BinderInvoker();
    if (invoker == nullptr) {
        return;
    }
    EXPECT_CALL(mock, GetRemoteInvoker).WillRepeatedly(Return(invoker));
    object->Marshalling(parcel, object);
    delete invoker;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::MarshallingFuzzTest001(provider);
    OHOS::MarshallingFuzzTest002(provider);
    return 0;
}

/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "binderinvoker_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "fuzz_data_generator.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "sys_binder.h"

#define private public
#include "binder_invoker.h"
#undef private

namespace OHOS {

    void TransactionTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(binder_transaction_data_secctx)) {
            return;
        }

        BinderInvoker *invoker = new BinderInvoker();
        binder_transaction_data_secctx trSecctx = *(reinterpret_cast<const binder_transaction_data_secctx *>(data));
        trSecctx.transaction_data.target.ptr = 0;
        trSecctx.transaction_data.offsets_size = 0;
        trSecctx.transaction_data.flags = 0;
        trSecctx.secctx = 0;

        invoker->Transaction(trSecctx);
        delete invoker;
    }

    class MyDeathRecipient : public IPCObjectProxy::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject> &object) override {}
    };

    void AddDeathRecipientTest()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        int handle;
        int proto;
        GenerateInt32(handle);
        GenerateInt32(proto);
        sptr<IPCObjectProxy> proxy = new IPCObjectProxy(handle, u"proxyTest", proto);
        sptr<IRemoteObject::DeathRecipient> recipient = new MyDeathRecipient();
        proxy->AddDeathRecipient(recipient);
        proxy->RemoveDeathRecipient(recipient);
        delete invoker;
    }

    void WriteFileDescriptorTest()
    {
        Parcel parcel;
        int fd;
        bool takeOwnership;
        GenerateInt32(fd);
        GenerateBool(takeOwnership);
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        invoker->WriteFileDescriptor(parcel, fd, takeOwnership);
        invoker->ReadFileDescriptor(parcel);
        delete invoker;
    }

    void FlattenObjectTest()
    {
        Parcel parcel;
        int handle;
        int proto;
        GenerateInt32(handle);
        GenerateInt32(proto);
        sptr<IRemoteObject> obj = new IPCObjectProxy(handle, u"proxyTest", proto);
        IRemoteObject *object = obj.GetRefPtr();
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        invoker->FlattenObject(parcel, object);
        invoker->UnflattenObject(parcel);
        delete invoker;
    }

    void GetCallerInfoTest()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        invoker->GetCallerSid();
        invoker->GetCallerPid();
        invoker->GetCallerRealPid();
        invoker->GetCallerUid();
        invoker->GetCallerTokenID();
        invoker->GetFirstCallerTokenID();
        invoker->GetSelfTokenID();
        invoker->GetSelfFirstCallerTokenID();
        invoker->IsLocalCalling();
        uint32_t status;
        GenerateUint32(status);
        invoker->SetStatus(status);
        invoker->GetStatus();
        invoker->GetLocalDeviceID();
        invoker->GetCallerDeviceID();
        invoker->ExitCurrentThread();
        delete invoker;
    }

    void SetCallingIdentityTest()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        bool flag;
        GenerateBool(flag);
        std::string identity;
        GenerateString(identity);
        invoker->SetCallingIdentity(identity, flag);
        invoker->ResetCallingIdentity();
        delete invoker;
    }

    void GetStrongRefCountForStubTest()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        uint32_t handle;
        GenerateUint32(handle);
        invoker->GetStrongRefCountForStub(handle);
        delete invoker;
    }

    void SetRegistryObjectTest001()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        sptr<IRemoteObject> object = nullptr;
        invoker->SetRegistryObject(object);
        delete invoker;
    }

    void SetRegistryObjectTest002()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        int handle;
        GenerateInt32(handle);
        sptr<IRemoteObject> object = new IPCObjectProxy(handle, u"proxyTest", 0);
        invoker->SetRegistryObject(object);
        delete invoker;
    }

    void SetRegistryObjectTest003()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        sptr<IRemoteObject> object = new IPCObjectStub(u"stubTest");
        invoker->SetRegistryObject(object);
        delete invoker;
    }

#ifndef CONFIG_IPC_SINGLE
    void TranslateIRemoteObjectTest001()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        int32_t cmd;
        GenerateInt32(cmd);
        sptr<IRemoteObject> obj = nullptr;
        invoker->TranslateIRemoteObject(cmd, obj);
        delete invoker;
    }

    void TranslateIRemoteObjectTest002()
    {
        BinderInvoker *invoker = new BinderInvoker();
        if (invoker == nullptr) {
            return;
        }
        int32_t cmd;
        int handle;
        int proto;
        GenerateInt32(cmd);
        GenerateInt32(handle);
        GenerateInt32(proto);
        sptr<IRemoteObject> obj = new IPCObjectProxy(handle, u"", proto);
        invoker->TranslateIRemoteObject(cmd, obj);
        delete invoker;
    }
#endif
    void FuzzTestInner1(const uint8_t* data, size_t size)
    {
        DataGenerator::Write(data, size);
        OHOS::TransactionTest(data, size);
        AddDeathRecipientTest();
        FlattenObjectTest();
        WriteFileDescriptorTest();
        GetCallerInfoTest();
        SetCallingIdentityTest();
        GetStrongRefCountForStubTest();
        SetRegistryObjectTest001();
        SetRegistryObjectTest002();
        SetRegistryObjectTest003();
#ifndef CONFIG_IPC_SINGLE
        TranslateIRemoteObjectTest001();
        TranslateIRemoteObjectTest002();
#endif
        DataGenerator::Clear();
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestInner1(data, size);
    return 0;
}
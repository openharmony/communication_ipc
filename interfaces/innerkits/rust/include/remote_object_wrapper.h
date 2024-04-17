/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef IPC_RUST_CXX_REMOTE_OBJECT_H
#define IPC_RUST_CXX_REMOTE_OBJECT_H

#include <cstdint>
#include <memory>
#include <string>

#include "cxx.h"
#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"
#include "refbase.h"

namespace OHOS {

typedef sptr<IRemoteObject> SptrIRemoteObject;

namespace IpcRust {
struct RemoteObj;
struct RemoteStubWrapper;
struct DeathRecipientRemoveHandler;

class IRemoteObjectWrapper {
public:
    IRemoteObjectWrapper();

    ~IRemoteObjectWrapper() = default;

    int32_t SendRequest(const uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) const;
    rust::string GetInterfaceDescriptor() const;
    rust::string GetObjectDescriptor() const;
    int32_t GetObjectRefCount() const;
    bool IsProxyObject() const;
    bool IsObjectDead() const;
    bool CheckObjectLegality() const;
    int Dump(int fd, const rust::Slice<const rust::string> args) const;

    std::unique_ptr<DeathRecipientRemoveHandler> AddDeathRecipient(rust::Fn<void(rust::Box<RemoteObj>)>) const;

    IRemoteObject *GetInner() const;

    bool is_raw_ = false;
    sptr<IRemoteObject> sptr_;
    IRemoteObject *raw_;
};

struct DeathRecipientWrapper : public virtual IRemoteObject::DeathRecipient {
public:
    DeathRecipientWrapper(rust::Fn<void(rust::Box<RemoteObj>)> cb);
    virtual void OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object) override;

private:
    rust::Fn<void(rust::Box<RemoteObj>)> inner_;
};

struct DeathRecipientRemoveHandler {
public:
    DeathRecipientRemoveHandler(sptr<IRemoteObject> remote, sptr<IRemoteObject::DeathRecipient> recipient);
    void remove() const;

private:
    sptr<IRemoteObject> remote_;
    sptr<IRemoteObject::DeathRecipient> inner_;
};

struct RemoteServiceStub : public IPCObjectStub {
public:
    explicit RemoteServiceStub(RemoteStubWrapper *stub, std::u16string);
    ~RemoteServiceStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int Dump(int fd, const std::vector<std::u16string> &args) override;

private:
    RemoteStubWrapper *inner_;
};

std::unique_ptr<IRemoteObjectWrapper> FromSptrRemote(std::unique_ptr<sptr<IRemoteObject>> remote);

std::unique_ptr<IRemoteObjectWrapper> CloneRemoteObj(const IRemoteObjectWrapper &remote);

std::unique_ptr<IRemoteObjectWrapper> FromRemoteStub(rust::Box<RemoteStubWrapper> stub);

std::unique_ptr<IRemoteObjectWrapper> FromCIRemoteObject(IRemoteObject *stub);

} // namespace IpcRust
} // namespace OHOS

#endif
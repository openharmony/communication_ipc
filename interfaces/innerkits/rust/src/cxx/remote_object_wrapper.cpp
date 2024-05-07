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

#include "remote_object_wrapper.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "cxx.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "refbase.h"
#include "remote/wrapper.rs.h"
#include "string_ex.h"

namespace OHOS {
namespace IpcRust {
IRemoteObjectWrapper::IRemoteObjectWrapper(): raw_(nullptr)
{
}

int32_t IRemoteObjectWrapper::SendRequest(
    const uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) const
{
    return GetInner()->SendRequest(code, data, reply, option);
}

IRemoteObject *IRemoteObjectWrapper::GetInner() const
{
    if (is_raw_) {
        return raw_;
    } else {
        return sptr_;
    }
}

rust::string IRemoteObjectWrapper::GetInterfaceDescriptor() const
{
    return GetInner()->GetInterfaceDescriptor().data();
}

rust::string IRemoteObjectWrapper::GetObjectDescriptor() const
{
    return GetInner()->GetObjectDescriptor().data();
}

std::unique_ptr<DeathRecipientRemoveHandler> IRemoteObjectWrapper::AddDeathRecipient(
    rust::Fn<void(rust::Box<RemoteObj>)> callback) const
{
    sptr<IRemoteObject::DeathRecipient> recipient(new DeathRecipientWrapper(callback));
    bool res = sptr_->AddDeathRecipient(recipient);
    if (!res) {
        return nullptr;
    }
    return std::make_unique<DeathRecipientRemoveHandler>(sptr(sptr_), sptr(recipient));
}

int32_t IRemoteObjectWrapper::GetObjectRefCount() const
{
    return GetInner()->GetObjectRefCount();
}

bool IRemoteObjectWrapper::IsProxyObject() const
{
    return GetInner()->IsProxyObject();
}
bool IRemoteObjectWrapper::IsObjectDead() const
{
    return GetInner()->IsObjectDead();
}
bool IRemoteObjectWrapper::CheckObjectLegality() const
{
    return GetInner()->CheckObjectLegality();
}

int IRemoteObjectWrapper::Dump(int fd, const rust::Slice<const rust::string> args) const
{
    std::vector<std::u16string> res;
    for (auto rust_s : args) {
        std::u16string s_u16 = Str8ToStr16(std::string(rust_s));
        res.push_back(s_u16);
    }
    return GetInner()->Dump(fd, res);
}

DeathRecipientWrapper::DeathRecipientWrapper(rust::Fn<void(rust::Box<RemoteObj>)> cb)
{
    this->inner_ = cb;
}

void DeathRecipientWrapper::OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object)
{
    auto obj = object.promote();
    if (obj == nullptr) {
        return;
    }

    auto wrapper = std::make_unique<IRemoteObjectWrapper>();

    wrapper->is_raw_ = false;
    wrapper->sptr_ = obj;

    auto rust_remote_obj = new_remote_obj(std::move(wrapper));
    inner_(std::move(rust_remote_obj));
}

DeathRecipientRemoveHandler::DeathRecipientRemoveHandler(
    sptr<IRemoteObject> remote, sptr<IRemoteObject::DeathRecipient> recipient)
{
    this->remote_ = std::move(remote);
    this->inner_ = std::move(recipient);
}

void DeathRecipientRemoveHandler::remove() const
{
    remote_->RemoveDeathRecipient(inner_);
}

RemoteServiceStub::RemoteServiceStub(RemoteStubWrapper *ability, std::u16string descriptor) : IPCObjectStub(descriptor)
{
    this->inner_ = ability;
}

RemoteServiceStub::~RemoteServiceStub()
{
    auto ability = rust::Box<RemoteStubWrapper>::from_raw(this->inner_);
}

int RemoteServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return inner_->on_remote_request(code, data, reply);
}

int RemoteServiceStub::Dump(int fd, const std::vector<std::u16string> &args)
{
    auto v = rust::vec<rust::string>();
    for (auto arg : args) {
        v.push_back(rust::string(arg.data()));
    }
    return inner_->dump(fd, v);
}

std::unique_ptr<IRemoteObjectWrapper> FromSptrRemote(std::unique_ptr<sptr<IRemoteObject>> remote)
{
    if (remote == nullptr) {
        return nullptr;
    }
    auto wrapper = std::make_unique<IRemoteObjectWrapper>();

    wrapper->is_raw_ = false;
    wrapper->sptr_ = std::move(*remote.release());

    return wrapper;
}

std::unique_ptr<IRemoteObjectWrapper> CloneRemoteObj(const IRemoteObjectWrapper &remote)
{
    if (remote.is_raw_) {
        auto raw_ptr = remote.raw_;
        if (raw_ptr == nullptr) {
            return nullptr;
        }
        return FromCIRemoteObject(raw_ptr);
    } else {
        auto sptr = remote.sptr_;
        if (sptr == nullptr) {
            return nullptr;
        }
        auto wrapper = std::make_unique<IRemoteObjectWrapper>();

        wrapper->is_raw_ = false;
        wrapper->sptr_ = sptr;
        return wrapper;
    }
}

std::unique_ptr<IRemoteObjectWrapper> FromRemoteStub(rust::Box<RemoteStubWrapper> stub)
{
    auto raw = stub.into_raw();
    auto rust_s = raw->descriptor();
    std::string s = std::string(rust_s);
    std::u16string descriptor = Str8ToStr16(s);

    auto stub_sptr = sptr<RemoteServiceStub>::MakeSptr(raw, descriptor);

    auto wrapper = std::make_unique<IRemoteObjectWrapper>();

    wrapper->is_raw_ = false;
    wrapper->sptr_ = stub_sptr;

    return wrapper;
}

std::unique_ptr<IRemoteObjectWrapper> FromCIRemoteObject(IRemoteObject *stub)
{
    if (stub == nullptr) {
        return nullptr;
    }
    auto wrapper = std::make_unique<IRemoteObjectWrapper>();

    wrapper->is_raw_ = true;
    wrapper->raw_ = stub;

    return wrapper;
}

} // namespace IpcRust
} // namespace OHOS
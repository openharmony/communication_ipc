/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "c_remote_object.h"

#include <string_ex.h>
#include "c_parcel_internal.h"
#include "c_remote_object_internal.h"

using namespace OHOS;

RemoteServiceHolderStub::RemoteServiceHolderStub(CRemoteObject *holder, std::u16string &desc, OnRemoteRequestCb callback)
    : IPCObjectStub(desc), holder_(holder), callback_(callback)
{
}

RemoteServiceHolderStub::~RemoteServiceHolderStub()
{
}

int RemoteServiceHolderStub::OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data,
    OHOS::MessageParcel &reply, OHOS::MessageOption &option)
{
    (void)option;
    printf("%s: OnRemoteRequest code: %u\n", __func__, code);
    if (callback_ == nullptr || holder_ == nullptr) {
        printf("%s: callback is null for code: %u\n", __func__, code);
        return -1;
    }
    CParcel parcelData(&data);
    CParcel parcelReply(&reply);
    return callback_(holder_, code, &parcelData, &parcelReply);
}

CRemoteStubHolder::CRemoteStubHolder(const void *userData, OnRemoteObjectDestroyCb onRemoteObjectDestroy)
    : userData_(userData), onRemoteObjectDestroy_(onRemoteObjectDestroy)
{
}

CRemoteStubHolder::~CRemoteStubHolder()
{
    if (onRemoteObjectDestroy_) {
        onRemoteObjectDestroy_(GetUserData());
    }
    onRemoteObjectDestroy_ = nullptr;
}

CDeathRecipient::CDeathRecipient(OnDeathRecipientCb onDeathRecipient,
    OnDeathRecipientDestroyCb onDestroy, const void *userData)
    : userData_(userData)
    , onDeathRecipient_(onDeathRecipient)
    , onDestroy_(onDestroy)
{
}

CDeathRecipient::~CDeathRecipient()
{
    if (onDestroy_ != nullptr) {
        onDestroy_(userData_);
    }
    onDestroy_ = nullptr;
    onDeathRecipient_ = nullptr;
}

void CDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    (void)object;
    if (onDeathRecipient_ != nullptr) {
        onDeathRecipient_(userData_);
    }
}

CRemoteProxyHolder::CRemoteProxyHolder()
{
}

CRemoteProxyHolder::~CRemoteProxyHolder()
{
}

bool IsValidRemoteObject(const CRemoteObject *object, const char *promot)
{
    if (object == nullptr) {
        printf("[%s] RemoteObject is null\n", promot);
        return false;
    }
    if (object->remote_ == nullptr) {
        printf("[%s]wrapper RemoteObject is null\n", promot);
        return false;
    }
    return true;
}

CRemoteObject *CreateRemoteStub(const char *desc, OnRemoteRequestCb callback,
    OnRemoteObjectDestroyCb destroy, const void *userData)
{
    if (desc == nullptr || callback == nullptr || destroy == nullptr) {
        return nullptr;
    }
    auto holder = new (std::nothrow) CRemoteStubHolder(userData, destroy);
    if (holder == nullptr) {
        printf("%s: new CRemoteStubHolder failed\n", __func__);
        return nullptr;
    }
    std::u16string descriptor = Str8ToStr16(std::string(desc));
    holder->remote_ = new (std::nothrow) RemoteServiceHolderStub(holder, descriptor, callback);
    if (holder->remote_ == nullptr) {
        printf("%s: new RemoteServiceHolderStub failed\n", __func__);
        delete holder;
        return nullptr;
    }
    holder->IncStrongRef(nullptr);
    return holder;
}

void RemoteObjectIncStrongRef(CRemoteObject *object)
{
    if (object == nullptr) {
        printf("%s: unexpected CRemoteObject\n", __func__);
        return;
    }
    object->IncStrongRef(nullptr);
}

void RemoteObjectDecStrongRef(CRemoteObject *object)
{
    if (object == nullptr) {
        printf("%s: unexpected CRemoteObject\n", __func__);
        return;
    }
    object->DecStrongRef(nullptr);
}

const void *RemoteObjectGetUserData(CRemoteObject *object)
{
    if (object == nullptr) {
        printf("%s: unexpected CRemoteObject\n", __func__);
        return nullptr;
    }
    return object->GetUserData();
}

int RemoteObjectSendRequest(const CRemoteObject *object, uint32_t code,
    const CParcel *data, CParcel *reply, bool isAsync)
{
    if (!IsValidRemoteObject(object, __func__) || data == nullptr) {
        printf("%s: object and data must be not null\n", __func__);
        return -EINVAL;
    }
    MessageOption option(isAsync ? MessageOption::TF_ASYNC : MessageOption::TF_SYNC);
    return object->remote_->SendRequest(code, *data->parcel_, *reply->parcel_, option);
}

CDeathRecipient *CreateDeathRecipient(OnDeathRecipientCb onDeathRecipient,
    OnDeathRecipientDestroyCb onDestroy, const void *userData)
{
    if (onDeathRecipient == nullptr || onDestroy == nullptr || userData == nullptr) {
        printf("%s: args must not be null\n", __func__);
        return nullptr;
    }
    CDeathRecipient *recipient = new (std::nothrow) CDeathRecipient(onDeathRecipient,
        onDestroy, userData);
    if (userData == nullptr) {
        printf("%s: create CDeathRecipient object failed\n", __func__);
        return nullptr;
    }
    recipient->IncStrongRef(nullptr);
    return recipient;
}

void DeathRecipientIncStrongRef(CDeathRecipient *recipient)
{
    if (recipient == nullptr) {
        printf("%s: unexpected CDeathRecipient\n", __func__);
        return;
    }
    recipient->IncStrongRef(nullptr);
}

void DeathRecipientDecStrongRef(CDeathRecipient *recipient)
{
    if (recipient == nullptr) {
        printf("%s: unexpected CDeathRecipient\n", __func__);
        return;
    }
    recipient->DecStrongRef(nullptr);
}

bool AddDeathRecipient(CRemoteObject *object, CDeathRecipient *recipient)
{
    if (!IsValidRemoteObject(object, __func__) || recipient == nullptr) {
        return false;
    }
    if (!object->remote_->IsProxyObject()) {
        printf("%s: this is not a proxy object", __func__);
        return false;
    }
    struct CRemoteProxyHolder *proxy = reinterpret_cast<struct CRemoteProxyHolder *>(object);
    sptr<IRemoteObject::DeathRecipient> callback(recipient);
    return proxy->remote_->AddDeathRecipient(callback);
}

bool RemoveDeathRecipient(CRemoteObject *object, CDeathRecipient *recipient)
{
    if (!IsValidRemoteObject(object, __func__) || recipient == nullptr) {
        printf("%s: recipient is null\n", __func__);
        return false;
    }
    if (!object->remote_->IsProxyObject()) {
        printf("%s: this is not a proxy object\n", __func__);
        return false;
    }
    struct CRemoteProxyHolder *proxy = reinterpret_cast<struct CRemoteProxyHolder *>(object);
    sptr<IRemoteObject::DeathRecipient> callback(recipient);
    return proxy->remote_->RemoveDeathRecipient(callback);
}

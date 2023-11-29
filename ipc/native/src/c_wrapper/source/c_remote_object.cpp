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

#include <securec.h>
#include <string_ex.h>
#include "c_parcel_internal.h"
#include "c_remote_object_internal.h"
#include "log_tags.h"
#include "ipc_debug.h"

using namespace OHOS;
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_OTHER, "CRemoteObject" };

RemoteServiceHolderStub::RemoteServiceHolderStub(std::u16string &desc, OnRemoteRequestCb callback,
    const void *userData, OnRemoteObjectDestroyCb destroy, OnRemoteDumpCb dumpCallback)
    : IPCObjectStub(desc), callback_(callback), dumpCallback_(dumpCallback)
    , userData_(userData), destroy_(destroy)
{
}

RemoteServiceHolderStub::~RemoteServiceHolderStub()
{
    if (destroy_) {
        destroy_(userData_);
    }
    destroy_ = nullptr;
}

int RemoteServiceHolderStub::OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data,
    OHOS::MessageParcel &reply, OHOS::MessageOption &option)
{
    (void)option;
    if (callback_ == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: callback is null for code: %u\n", __func__, code);
        return -1;
    }
    CParcel parcelData(&data);
    CParcel parcelReply(&reply);
    return callback_(userData_, code, &parcelData, &parcelReply);
}

int RemoteServiceHolderStub::OnRemoteDump(uint32_t code, OHOS::MessageParcel &data,
    OHOS::MessageParcel &reply, OHOS::MessageOption &option)
{
    (void)option;
    (void)reply;
    if (dumpCallback_ == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: dumpCallback_ is null for code: %u\n", __func__, code);
        return -1;
    }
    CParcel parcelData(&data);
    return dumpCallback_(userData_, &parcelData);
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

bool IsValidRemoteObject(const CRemoteObject *object, const char *promot)
{
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "[%{public}s] RemoteObject is null\n", promot);
        return false;
    }
    if (object->remote_ == nullptr) {
        ZLOGE(LOG_LABEL, "[%{public}s]wrapper RemoteObject is null\n", promot);
        return false;
    }
    return true;
}

CRemoteObject *CreateRemoteStub(const char *desc, OnRemoteRequestCb callback,
    OnRemoteObjectDestroyCb destroy, const void *userData, OnRemoteDumpCb dumpCallback)
{
    if (desc == nullptr || callback == nullptr || destroy == nullptr) {
        return nullptr;
    }
    auto holder = new (std::nothrow) CRemoteObjectHolder();
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: new CRemoteObjectHolder failed\n", __func__);
        return nullptr;
    }
    std::u16string descriptor = Str8ToStr16(std::string(desc));
    holder->remote_ = new (std::nothrow) RemoteServiceHolderStub(
        descriptor, callback, userData, destroy, dumpCallback);
    if (holder->remote_ == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: new RemoteServiceHolderStub failed\n", __func__);
        delete holder;
        return nullptr;
    }
    holder->IncStrongRef(nullptr);
    return holder;
}

void RemoteObjectIncStrongRef(CRemoteObject *object)
{
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: unexpected CRemoteObject\n", __func__);
        return;
    }
    object->IncStrongRef(nullptr);
}

void RemoteObjectDecStrongRef(CRemoteObject *object)
{
    if (object == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: unexpected CRemoteObject\n", __func__);
        return;
    }
    object->DecStrongRef(nullptr);
}

bool RemoteObjectLessThan(const CRemoteObject *lhs, const CRemoteObject *rhs)
{
    if (!IsValidRemoteObject(lhs, __func__) || !IsValidRemoteObject(rhs, __func__)) {
        return false;
    }
    return lhs->remote_.GetRefPtr() < rhs->remote_.GetRefPtr();
}

int RemoteObjectSendRequest(const CRemoteObject *object, uint32_t code,
    const CParcel *data, CParcel *reply, bool isAsync)
{
    if (!IsValidRemoteObject(object, __func__) || data == nullptr || reply == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: object and data must be not null\n", __func__);
        return -EINVAL;
    }
    MessageOption option(isAsync ? MessageOption::TF_ASYNC : MessageOption::TF_SYNC);
    return object->remote_->SendRequest(code, *data->parcel_, *reply->parcel_, option);
}

CDeathRecipient *CreateDeathRecipient(OnDeathRecipientCb onDeathRecipient,
    OnDeathRecipientDestroyCb onDestroy, const void *userData)
{
    if (onDeathRecipient == nullptr || onDestroy == nullptr || userData == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: args must not be null\n", __func__);
        return nullptr;
    }
    CDeathRecipient *recipient = new (std::nothrow) CDeathRecipient(onDeathRecipient,
        onDestroy, userData);
    if (recipient == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: create CDeathRecipient object failed\n", __func__);
        return nullptr;
    }
    recipient->IncStrongRef(nullptr);
    return recipient;
}

void DeathRecipientIncStrongRef(CDeathRecipient *recipient)
{
    if (recipient == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: unexpected CDeathRecipient\n", __func__);
        return;
    }
    recipient->IncStrongRef(nullptr);
}

void DeathRecipientDecStrongRef(CDeathRecipient *recipient)
{
    if (recipient == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: unexpected CDeathRecipient\n", __func__);
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
        ZLOGE(LOG_LABEL, "%{public}s: this is not a proxy object", __func__);
        return false;
    }
    sptr<IRemoteObject::DeathRecipient> callback(recipient);
    return object->remote_->AddDeathRecipient(callback);
}

bool RemoveDeathRecipient(CRemoteObject *object, CDeathRecipient *recipient)
{
    if (!IsValidRemoteObject(object, __func__) || recipient == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: recipient is null\n", __func__);
        return false;
    }
    if (!object->remote_->IsProxyObject()) {
        ZLOGE(LOG_LABEL, "%{public}s: this is not a proxy object\n", __func__);
        return false;
    };
    sptr<IRemoteObject::DeathRecipient> callback(recipient);
    return object->remote_->RemoveDeathRecipient(callback);
}


bool IsProxyObject(CRemoteObject *object)
{
    if (!IsValidRemoteObject(object, __func__)) {
        ZLOGE(LOG_LABEL, "%{public}s: recipient is null\n", __func__);
        return false;
    }
    return object->remote_->IsProxyObject();
}

int Dump(CRemoteObject *object, int fd, CParcel *parcel)
{
    if (!IsValidRemoteObject(object, __func__) || parcel == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: recipient is null\n", __func__);
        return -1;
    }
    if (fd < 0) {
        ZLOGE(LOG_LABEL, "%{public}s: fd is invalid", __func__);
        return -1;
    }
    std::vector<std::u16string> string16Vector;
    parcel->parcel_->ReadString16Vector(&string16Vector);

    return object->remote_->Dump(fd, string16Vector);
}

bool IsObjectDead(CRemoteObject *object)
{
    if (!IsValidRemoteObject(object, __func__)) {
        ZLOGE(LOG_LABEL, "%{public}s: recipient is null\n", __func__);
        return false;
    }
    if (!IsProxyObject(object)) {
        return false;
    }
    return object->remote_->IsObjectDead();
}

bool GetInterfaceDescriptor(CRemoteObject *object, void *value, On16BytesAllocator allocator)
{
    if (!IsValidRemoteObject(object, __func__)) {
        ZLOGE(LOG_LABEL, "%{public}s: recipient is null\n", __func__);
        return false;
    }
    if (!IsProxyObject(object)) {
        return false;
    }

    std::u16string str(object->remote_->GetInterfaceDescriptor());
    uint16_t *buffer = nullptr;
    bool isSuccess = allocator(value, &buffer, str.length());
    if (!isSuccess) {
        ZLOGE(LOG_LABEL, "%{public}s: allocate string buffer is null\n", __func__);
        return false;
    }

    int32_t size = sizeof(char16_t) * str.length();
    if (str.length() > 0 && memcpy_s(buffer, size, str.data(), size) != EOK) {
        ZLOGE(LOG_LABEL, "%{public}s: memcpy string failed\n", __func__);
        return false;
    }
    return true;
}

CRemoteObject *CreateCRemoteObject(void *obj)
{
    if (obj == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: recipient is null\n", __func__);
        return nullptr;
    }

    CRemoteObject *holder = new (std::nothrow) CRemoteObjectHolder();
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "%{public}s: create proxy holder failed\n", __func__);
        return nullptr;
    }
    sptr<IRemoteObject> sa = reinterpret_cast<IRemoteObject* >(obj);
    holder->IncStrongRef(nullptr);
    holder->remote_ = sa;

    return holder;
}

void *GetCIRemoteObject(CRemoteObject* obj)
{
    if (!IsValidRemoteObject(obj, __func__)) {
        ZLOGE(LOG_LABEL, "%{public}s: recipient is null\n", __func__);
        return nullptr;
    }

    if (obj->remote_ == nullptr) {
        ZLOGI(LOG_LABEL, "%{public}s: The pointer inside CRemoteObject is a null pointer\n", __func__);
        return nullptr;
    }
    return obj->remote_.GetRefPtr();
}
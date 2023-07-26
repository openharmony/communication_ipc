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

#ifndef IPC_C_REMOTE_OBJECT_INTERNAL_H
#define IPC_C_REMOTE_OBJECT_INTERNAL_H

#include <vector>
#include <mutex>
#include <refbase.h>
#include "c_remote_object.h"
#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"

struct CRemoteObjectHolder : public virtual OHOS::RefBase {
    CRemoteObjectHolder() = default;
    virtual ~CRemoteObjectHolder() = default;

    OHOS::sptr<OHOS::IRemoteObject> remote_;
};

struct CDeathRecipient: public virtual OHOS::IRemoteObject::DeathRecipient {
public:
    CDeathRecipient(OnDeathRecipientCb onDeathRecipient,
        OnDeathRecipientDestroyCb onDeathRecipientDestroy, const void *userData);
    ~CDeathRecipient();

    virtual void OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object) override;

private:
    const void *userData_;
    OnDeathRecipientCb onDeathRecipient_;
    OnDeathRecipientDestroyCb onDestroy_;
};

class RemoteServiceHolderStub: public OHOS::IPCObjectStub {
public:
    explicit RemoteServiceHolderStub(std::u16string &desc, OnRemoteRequestCb callback,
        const void *userData, OnRemoteObjectDestroyCb destroy, OnRemoteDumpCb dump);
    ~RemoteServiceHolderStub();

    int OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data,
        OHOS::MessageParcel &reply, OHOS::MessageOption &option) override;

    int OnRemoteDump(uint32_t code, OHOS::MessageParcel &data,
        OHOS::MessageParcel &reply, OHOS::MessageOption &option) override;
private:
    OnRemoteRequestCb callback_;
    OnRemoteDumpCb dumpCallback_;
    const void *userData_;
    OnRemoteObjectDestroyCb destroy_;
};

bool IsValidRemoteObject(const CRemoteObject *object, const char *promot);
#endif /* IPC_C_REMOTE_OBJECT_INTERNAL_H */

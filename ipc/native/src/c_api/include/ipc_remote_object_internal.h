/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IPC_REMOTE_OBJECT_INTERNAL_H
#define IPC_REMOTE_OBJECT_INTERNAL_H

#include "ipc_cremote_object.h"
#include "iremote_object.h"
#include "ipc_object_stub.h"
#include "ipc_error_code.h"

static inline bool IsUserDefinedError(int error)
{
    return (error >= OH_IPC_USER_ERROR_CODE_MIN) && (error <= OH_IPC_USER_ERROR_CODE_MAX);
}

static inline bool IsIpcErrorCode(int error)
{
    return (error >= OH_IPC_ERROR_CODE_BASE) && (error <= OH_IPC_INNER_ERROR);
}

struct IPCDeathRecipient : public OHOS::IRemoteObject::DeathRecipient {
public:
    IPCDeathRecipient(OH_OnDeathRecipientCallback deathRecipientCallback,
        OH_OnDeathRecipientDestroyCallback destroyCallback, void *userData);
    ~IPCDeathRecipient();

    virtual void OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object) override;

private:
    OH_OnDeathRecipientCallback deathRecipientCallback_;
    OH_OnDeathRecipientDestroyCallback destroyCallback_;
    void *userData_;
};

struct OHIPCDeathRecipient {
    OHOS::sptr<IPCDeathRecipient> recipient;
};

class OHIPCRemoteServiceStub : public OHOS::IPCObjectStub {
public:
    OHIPCRemoteServiceStub(std::u16string &desc, OH_OnRemoteRequestCallback requestCallback,
        OH_OnRemoteDestroyCallback destroyCallback, void *userData);
    ~OHIPCRemoteServiceStub();

    int OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data,
        OHOS::MessageParcel &reply, OHOS::MessageOption &option) override;

private:
    OH_OnRemoteRequestCallback requestCallback_;
    OH_OnRemoteDestroyCallback destroyCallback_;
    void *userData_;
};

#endif

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

#include "ipc_remote_object_internal.h"
#include "ipc_inner_object.h"
#include "message_parcel.h"
#include "log_tags.h"
#include "ipc_debug.h"
#include "ipc_error_code.h"

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_CAPI, "IPCRemoteObject" };

IPCDeathRecipient::IPCDeathRecipient(OH_OnDeathRecipientCallback deathRecipientCallback,
    OH_OnDeathRecipientDestroyCallback destroyCallback, void *userData)
    : deathRecipientCallback_(deathRecipientCallback), destroyCallback_(destroyCallback), userData_(userData)
{
}

IPCDeathRecipient::~IPCDeathRecipient()
{
    if (destroyCallback_ != nullptr) {
        destroyCallback_(userData_);
    }
    deathRecipientCallback_ = nullptr;
    destroyCallback_ = nullptr;
    userData_ = nullptr;
}

void IPCDeathRecipient::OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject>&)
{
    if (deathRecipientCallback_ != nullptr) {
        deathRecipientCallback_(userData_);
    }
}

OHIPCRemoteServiceStub::OHIPCRemoteServiceStub(std::u16string &desc, OH_OnRemoteRequestCallback requestCallback,
    OH_OnRemoteDestroyCallback destroyCallback, void *userData)
    : IPCObjectStub(desc), requestCallback_(requestCallback), destroyCallback_(destroyCallback), userData_(userData)
{
}

OHIPCRemoteServiceStub::~OHIPCRemoteServiceStub()
{
    if (destroyCallback_ != nullptr) {
        (void)destroyCallback_(userData_);
    }
    destroyCallback_ = nullptr;
    userData_ = nullptr;
    requestCallback_ = nullptr;
}

int OHIPCRemoteServiceStub::OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data,
    OHOS::MessageParcel &reply, OHOS::MessageOption &)
{
    if (requestCallback_ == nullptr) {
        ZLOGE(LOG_LABEL, "Callback is null for code: %{public}u", code);
        return OH_IPC_INNER_ERROR;
    }
    OHIPCParcel parcelData{ &data };
    OHIPCParcel parcelReply{ &reply };
    int err = requestCallback_(code, &parcelData, &parcelReply, userData_);
    if (err != OH_IPC_SUCCESS
        && !IsIpcErrorCode(err)
        && !IsUserDefinedError(err)) {
        ZLOGE(LOG_LABEL, "user define error code:%{public}d out of range[%{public}d, %{public}d]",
            err, OH_IPC_USER_ERROR_CODE_MIN, OH_IPC_USER_ERROR_CODE_MAX);
        err = OH_IPC_INVALID_USER_ERROR_CODE;
    }
    return err;
}

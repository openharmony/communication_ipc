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

#include "ipc_cremote_object.h"
#include "ipc_inner_object.h"
#include "ipc_internal_utils.h"
#include "ipc_remote_object_internal.h"
#include "log_tags.h"
#include "ipc_debug.h"
#include "ipc_error_code.h"
#include "ipc_types.h"
#include "sys_binder.h"

#include <securec.h>

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_CAPI, "IPCRemoteObject" };

static constexpr uint32_t MIN_SEND_REQUEST_CODE = 0x01;
static constexpr uint32_t MAX_SEND_REQUEST_CODE = 0x00ffffff;

OHIPCRemoteStub* OH_IPCRemoteStub_Create(const char *descriptor, OH_OnRemoteRequestCallback requestCallback,
    OH_OnRemoteDestroyCallback destroyCallback, void *userData)
{
    if (descriptor == nullptr || requestCallback == nullptr) {
        ZLOGE(LOG_LABEL, "check param error!");
        return nullptr;
    }
    int len = strlen(descriptor);
    if (len == 0 || len > MAX_PARCEL_LEN) {
        ZLOGE(LOG_LABEL, "descriptor len:%{public}d is invalid!", len);
        return nullptr;
    }
    std::u16string desc = OHOS::Str8ToStr16(std::string(descriptor));
    if (desc.length() == 0 && len != 0) {
        ZLOGE(LOG_LABEL, "convert descriptor to u16string failed: %{public}d", len);
        return nullptr;
    }
    OHOS::sptr<OHIPCRemoteServiceStub> serviceStub(new (std::nothrow) OHIPCRemoteServiceStub(desc,
        requestCallback, destroyCallback, userData));
    if (serviceStub == nullptr) {
        ZLOGE(LOG_LABEL, "new OHIPCRemoteServiceStub failed");
        return nullptr;
    }
    OHIPCRemoteStub *stub = new (std::nothrow) OHIPCRemoteStub();
    if (stub == nullptr) {
        ZLOGE(LOG_LABEL, "new OHIPCRemoteStub failed");
        return nullptr;
    }
    stub->remote = serviceStub;
    return stub;
}

void OH_IPCRemoteStub_Destroy(OHIPCRemoteStub *stub)
{
    if (stub != nullptr) {
        stub->remote = nullptr;
        delete stub;
    }
}

void OH_IPCRemoteProxy_Destroy(OHIPCRemoteProxy *proxy)
{
    if (proxy != nullptr) {
        proxy->remote = nullptr;
        delete proxy;
    }
}

static int GetMessageFlag(OH_IPC_RequestMode mode)
{
    return (mode == OH_IPC_REQUEST_MODE_ASYNC) ?
        OHOS::MessageOption::TF_ASYNC : OHOS::MessageOption::TF_SYNC;
}

static constexpr struct {
    int innerErrorCode;
    int error;
} ERROR_MAP[] = {
    {OHOS::IPC_PROXY_DEAD_OBJECT_ERR, OH_IPC_DEAD_REMOTE_OBJECT},
    {OHOS::IPC_INVOKER_CONNECT_ERR, OH_IPC_INNER_ERROR},
    {OHOS::IPC_PROXY_INVALID_CODE_ERR, OH_IPC_CODE_OUT_OF_RANGE},
    {OHOS::IPC_STUB_WRITE_PARCEL_ERR, OH_IPC_PARCEL_WRITE_ERROR},
    {OH_IPC_INVALID_USER_ERROR_CODE, OH_IPC_INVALID_USER_ERROR_CODE},
    {BR_DEAD_REPLY, OH_IPC_DEAD_REMOTE_OBJECT},
    {BR_FAILED_REPLY, OH_IPC_INNER_ERROR},
};

static int ConvertSendRequestError(int error)
{
    if (error == OHOS::ERR_NONE) {
        return OH_IPC_SUCCESS;
    }
    if (IsUserDefinedError(error) || IsIpcErrorCode(error)) {
        return error;
    }

    static size_t arraySize = sizeof(ERROR_MAP) / sizeof(ERROR_MAP[0]);
    for (size_t i = 0; i < arraySize; ++i) {
        if (ERROR_MAP[i].innerErrorCode == error) {
            return ERROR_MAP[i].error;
        }
    }

    return OH_IPC_INNER_ERROR;
}

static bool IsCodeValid(uint32_t code)
{
    return (code >= MIN_SEND_REQUEST_CODE) && (code <= MAX_SEND_REQUEST_CODE);
}

int OH_IPCRemoteProxy_SendRequest(const OHIPCRemoteProxy *proxy, uint32_t code, const OHIPCParcel *data,
    OHIPCParcel *reply, const OH_IPC_MessageOption *option)
{
    if (!IsIPCRemoteProxyValid(proxy, __func__)
        || !IsIPCParcelValid(data, __func__)
        || (option != nullptr && option->reserved != nullptr)) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }
    if (!IsCodeValid(code)) {
        ZLOGE(LOG_LABEL, "send request code:%{public}d out of range[%{public}d, %{public}d]",
            code, MIN_SEND_REQUEST_CODE, MAX_SEND_REQUEST_CODE);
        return OH_IPC_CODE_OUT_OF_RANGE;
    }

    OH_IPC_RequestMode mode = (option != nullptr) ? option->mode : OH_IPC_REQUEST_MODE_SYNC;
    int ret = OH_IPC_SUCCESS;
    OHOS::MessageOption msgOption(GetMessageFlag(mode));
    if (IsIPCParcelValid(reply, __func__)) {
        ret = proxy->remote->SendRequest(code, *data->msgParcel, *reply->msgParcel, msgOption);
    } else if (mode == OH_IPC_REQUEST_MODE_SYNC) {
        return OH_IPC_CHECK_PARAM_ERROR;
    } else {
        OHOS::MessageParcel msgReply;
        ret = proxy->remote->SendRequest(code, *data->msgParcel, msgReply, msgOption);
    }
    return ConvertSendRequestError(ret);
}

int OH_IPCRemoteProxy_GetInterfaceDescriptor(OHIPCRemoteProxy *proxy, char **descriptor, int32_t *len,
    OH_IPC_MemAllocator allocator)
{
    if (!IsIPCRemoteProxyValid(proxy, __func__)
        || !IsMemoryParamsValid(descriptor, len, allocator, __func__)) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    std::u16string u16string(proxy->remote->GetInterfaceDescriptor());
    std::string value = OHOS::Str16ToStr8(u16string);
    if (u16string.length() != 0 && value.length() == 0) {
        ZLOGE(LOG_LABEL, "Str16ToStr8 failed! u16string len: %{public}u, string len: %{public}u",
            static_cast<uint32_t>(u16string.length()), static_cast<uint32_t>(value.length()));
        return OH_IPC_PARCEL_READ_ERROR;
    }

    int memLength = static_cast<int>(value.length()) + 1;
    *descriptor = static_cast<char*>(allocator(memLength));
    if (*descriptor == nullptr) {
        ZLOGE(LOG_LABEL, "memory allocator failed!");
        return OH_IPC_MEM_ALLOCATOR_ERROR;
    }
    if (memcpy_s(*descriptor, memLength, value.c_str(), memLength) != EOK) {
        ZLOGE(LOG_LABEL, "memcpy string failed");
        return OH_IPC_PARCEL_READ_ERROR;
    }
    *len = memLength;
    return OH_IPC_SUCCESS;
}

OHIPCDeathRecipient* OH_IPCDeathRecipient_Create(OH_OnDeathRecipientCallback deathRecipientCallback,
    OH_OnDeathRecipientDestroyCallback destroyCallback, void *userData)
{
    if (deathRecipientCallback == nullptr) {
        ZLOGE(LOG_LABEL, "args must not be null");
        return nullptr;
    }
    OHOS::sptr<IPCDeathRecipient> recipient(new (std::nothrow) IPCDeathRecipient(
        deathRecipientCallback, destroyCallback, userData));
    if (recipient == nullptr) {
        ZLOGE(LOG_LABEL, "create IPCDeathRecipient object failed");
        return nullptr;
    }
    OHIPCDeathRecipient *deathRecipient = new (std::nothrow) OHIPCDeathRecipient();
    if (deathRecipient == nullptr) {
        ZLOGE(LOG_LABEL, "create OHIPCDeathRecipient failed");
        return nullptr;
    }
    deathRecipient->recipient = recipient;
    return deathRecipient;
}

void OH_IPCDeathRecipient_Destroy(OHIPCDeathRecipient *recipient)
{
    if (recipient != nullptr) {
        recipient->recipient = nullptr;
        delete recipient;
    }
}

int OH_IPCRemoteProxy_AddDeathRecipient(OHIPCRemoteProxy *proxy, OHIPCDeathRecipient *recipient)
{
    if (!IsIPCRemoteProxyValid(proxy, __func__)
        || recipient == nullptr
        || recipient->recipient == nullptr) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    return proxy->remote->AddDeathRecipient(recipient->recipient) ? OH_IPC_SUCCESS : OH_IPC_INNER_ERROR;
}

int OH_IPCRemoteProxy_RemoveDeathRecipient(OHIPCRemoteProxy *proxy, OHIPCDeathRecipient *recipient)
{
    if (!IsIPCRemoteProxyValid(proxy, __func__)
        || recipient == nullptr
        || recipient->recipient == nullptr) {
        return OH_IPC_CHECK_PARAM_ERROR;
    }

    return proxy->remote->RemoveDeathRecipient(recipient->recipient) ? OH_IPC_SUCCESS : OH_IPC_INNER_ERROR;
}

int OH_IPCRemoteProxy_IsRemoteDead(const OHIPCRemoteProxy *proxy)
{
    if (!IsIPCRemoteProxyValid(proxy, __func__)) {
        return 1;
    }

    return proxy->remote->IsObjectDead() ? 1 : 0;
}

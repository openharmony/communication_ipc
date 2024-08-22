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

#include <hitrace_meter.h>
#include <string_ex.h>

#include "cj_lambda.h"
#include "ipc_utils_ffi.h"
#include "message_option.h"
#include "remote_proxy_holder_impl.h"

static std::atomic<int32_t> bytraceId = 1000;
namespace OHOS {
RemoteProxyHolderImpl::RemoteProxyHolderImpl() : object_(nullptr) {}

RemoteProxyHolderImpl::~RemoteProxyHolderImpl()
{
    object_ = nullptr;
}

CJDeathRecipient::CJDeathRecipient(int64_t funcId)
{
    funcId_ = funcId;
}

void CJDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    auto func = reinterpret_cast<void (*)()>(funcId_);
    auto handler = CJLambda::Create(func);
    if (handler == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get property onRemoteDied");
        return;
    }
    handler();
}

bool CJDeathRecipient::Matches(int64_t funcId)
{
    return funcId_ == funcId;
}

CJDeathRecipientList::CJDeathRecipientList() {}

CJDeathRecipientList::~CJDeathRecipientList()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    set_.clear();
}

bool CJDeathRecipientList::Add(const sptr<CJDeathRecipient>& recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    auto ret = set_.insert(recipient);
    return ret.second;
}

bool CJDeathRecipientList::Remove(const sptr<CJDeathRecipient>& recipient)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return (set_.erase(recipient) > 0);
}

sptr<CJDeathRecipient> CJDeathRecipientList::Find(int64_t funcId)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    for (auto it = set_.begin(); it != set_.end(); it++) {
        if ((*it)->Matches(funcId)) {
            return *it;
        }
    }
    return nullptr;
}

int32_t RemoteProxyHolderImpl::SendMessageRequest(
    uint32_t code, int64_t dataId, int64_t replyId, MessageOption option, int64_t funcId)
{
    auto data = FFIData::GetData<MessageSequenceImpl>(dataId);
    if (!data) {
        ZLOGE(LOG_LABEL, "[RPC] failed to get data message parcel");
        return errorDesc::CHECK_PARAM_ERROR;
    }
    auto reply = FFIData::GetData<MessageSequenceImpl>(replyId);
    if (!reply) {
        ZLOGE(LOG_LABEL, "[RPC] failed to get reply message parcel");
        return errorDesc::CHECK_PARAM_ERROR;
    }
    if (object_ == nullptr) {
        ZLOGE(LOG_LABEL, "invalid proxy object");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    std::string remoteDescriptor = Str16ToStr8(object_->GetObjectDescriptor());
    if (!remoteDescriptor.empty()) {
        std::string traceValue = remoteDescriptor + std::to_string(code);
        int32_t traceId = bytraceId.fetch_add(1, std::memory_order_seq_cst);
        StartAsyncTrace(HITRACE_TAG_RPC, traceValue.c_str(), traceId);
    }
    int32_t errCode =
        object_->SendRequest(code, *(data->GetMessageParcel().get()), *(reply->GetMessageParcel().get()), option);
    auto callback = CJLambda::Create(reinterpret_cast<void (*)(RequestResult)>(funcId));
    if (!callback) {
        ZLOGI(LOG_LABEL, "callback started");
        RequestResult result = RequestResult { .errCode = errCode, .code = code, .data = dataId, .reply = replyId };
        callback(result);
    }
    return 0;
}

char* RemoteProxyHolderImpl::GetDescriptor(int32_t* errCode)
{
    if (object_ == nullptr) {
        ZLOGE(LOG_LABEL, "proxy object is nullptr");
        *errCode = errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        return nullptr;
    }
    std::u16string remoteDescriptor = object_->GetInterfaceDescriptor();
    if (remoteDescriptor == std::u16string()) {
        ZLOGE(LOG_LABEL, "failed to get interface descriptor");
        *errCode = errorDesc::COMMUNICATION_ERROR;
        return nullptr;
    }
    return MallocCString(Str16ToStr8(remoteDescriptor));
}

bool RemoteProxyHolderImpl::IsObjectDead()
{
    if (object_ == nullptr) {
        ZLOGE(LOG_LABEL, "Invalid proxy object");
        return false;
    }
    return object_->IsObjectDead();
}

int32_t RemoteProxyHolderImpl::RegisterDeathRecipient(int64_t funcId, int32_t flag)
{
    if ((object_ == nullptr) || !object_->IsProxyObject()) {
        ZLOGE(LOG_LABEL, "could not add recipient from invalid target");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    sptr<CJDeathRecipient> nativeRecipient = new (std::nothrow) CJDeathRecipient(funcId);
    if (nativeRecipient == nullptr) {
        ZLOGE(LOG_LABEL, "new CJDeathRecipient failed");
        return errorDesc::CHECK_PARAM_ERROR;
    }
    bool ret = object_->AddDeathRecipient(nativeRecipient);
    if (ret) {
        list_->Add(nativeRecipient);
    }
    ZLOGI(LOG_LABEL, "%{public}s", ret ? "succ" : "fail");
    return 0;
}

int32_t RemoteProxyHolderImpl::UnregisterDeathRecipient(int64_t funcId, int32_t flag)
{
    if ((object_ == nullptr) || !object_->IsProxyObject()) {
        ZLOGE(LOG_LABEL, "could not remove recipient from invalid target");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    sptr<CJDeathRecipient> nativeRecipient = list_->Find(funcId);
    if (nativeRecipient == nullptr) {
        ZLOGE(LOG_LABEL, "recipient not found");
        return 0;
    }
    object_->RemoveDeathRecipient(nativeRecipient);
    bool ret = list_->Remove(nativeRecipient);
    ZLOGI(LOG_LABEL, "%{public}s", ret ? "succ" : "fail");
    return 0;
}
} // namespace OHOS
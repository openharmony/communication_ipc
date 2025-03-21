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

#include "remote_object_impl.h"

#include <cinttypes>
#include <hitrace_meter.h>
#include <string_ex.h>

#include "cj_lambda.h"
#include "ipc_utils_ffi.h"
#include "iremote_invoker.h"
#include "remote_object_internal_impl.h"
#include "remote_proxy_holder_impl.h"

using namespace OHOS::FFI;

namespace OHOS {
static const uint64_t HITRACE_TAG_RPC = (1ULL << 46); // RPC and IPC tag.

static std::atomic<int32_t> bytraceId = 1000;

RemoteObjectImpl::RemoteObjectImpl(std::thread::id jsThreadId, const std::u16string& descriptor)
    : IPCObjectStub(descriptor)
{
    jsThreadId_ = jsThreadId;
}

CjRemoteObjectImpl::CjRemoteObjectImpl(RemoteObjectHolderImpl* holder)
{
    holder_ = holder;
}

CjRemoteObjectImpl::~CjRemoteObjectImpl()
{
    if (holder_ == nullptr) {
        ZLOGW(LOG_LABEL, "~CjRemoteObjectImpl null holder");
        return;
    }
    holder_->Lock();
    int32_t curAttachCount = holder_->DecAttachCount();
    holder_->Unlock();
    ZLOGD(LOG_LABEL, "~CjRemoteObjectImpl, curAttachCount:%{public}d", curAttachCount);
    if (curAttachCount == 0) {
        delete holder_;
    }
}

char* CjRemoteObjectImpl::GetDescriptor(int32_t* errCode)
{
    if (holder_ == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get napi remote object holder");
        *errCode = errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        return nullptr;
    }
    sptr<IRemoteObject> nativeObject = holder_->Get();
    if (nativeObject == nullptr) {
        ZLOGE(LOG_LABEL, "native stub object is nullptr");
        *errCode = errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
        return nullptr;
    }
    std::u16string descriptor = nativeObject->GetObjectDescriptor();
    std::string str = Str16ToStr8(descriptor);
    return MallocCString(str);
}

int32_t CjRemoteObjectImpl::ModifyLocalInterface(char* stringValue)
{
    size_t maxLen = 40960;
    if (strlen(stringValue) >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        return errorDesc::CHECK_PARAM_ERROR;
    }
    if (holder_ == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get napi remote object holder");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    std::string descriptor = stringValue;
    holder_->attachLocalInterface(descriptor);
    return 0;
}

void StubExecuteSendRequest(CJSendRequestParam* param)
{
    if (param == nullptr) {
        ZLOGE(LOG_LABEL, "param is null");
        return;
    }
    param->errCode =
        param->target->SendRequest(param->code, *(param->data.get()), *(param->reply.get()), param->option);
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count());
    ZLOGI(LOG_LABEL, "sendRequest done, errCode:%{public}d time:%{public}" PRIu64, param->errCode, curTime);
    if (param->traceId != 0) {
        FinishAsyncTrace(HITRACE_TAG_RPC, (param->traceValue).c_str(), param->traceId);
    }
    auto callback = CJLambda::Create(reinterpret_cast<void (*)(RequestResult)>(param->callback));
    if (callback) {
        ZLOGI(LOG_LABEL, "callback started");
        RequestResult result = RequestResult {
            .errCode = param->errCode, .code = param->code, .data = param->cjDataRef, .reply = param->cjReplyRef
        };
        callback(result);
    }
    delete param;
}

int32_t CjRemoteObjectImpl::SendMessageRequest(
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
    if (holder_ == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get napi remote object holder");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    sptr<IRemoteObject> target = holder_->Get();
    if (target == nullptr) {
        ZLOGE(LOG_LABEL, "native stub object is nullptr");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    CJSendRequestParam* sendRequestParam = new (std::nothrow) CJSendRequestParam {
        .target = target,
        .code = code,
        .data = data->GetMessageParcel(),
        .reply = reply->GetMessageParcel(),
        .option = option,
        .errCode = -1,
        .cjDataRef = dataId,
        .cjReplyRef = replyId,
        .callback = funcId,
        .traceId = 0,
    };
    if (sendRequestParam == nullptr) {
        ZLOGE(LOG_LABEL, "new SendRequestParam failed");
        return errorDesc::PROXY_OR_REMOTE_OBJECT_INVALID_ERROR;
    }
    std::string remoteDescriptor = Str16ToStr8(target->GetObjectDescriptor());
    if (!remoteDescriptor.empty()) {
        std::string traceValue = remoteDescriptor + std::to_string(code);
        int32_t traceId = bytraceId.fetch_add(1, std::memory_order_seq_cst);
        StartAsyncTrace(HITRACE_TAG_RPC, traceValue.c_str(), traceId);
    }
    std::thread t(StubExecuteSendRequest, sendRequestParam);
    t.detach();
    return 0;
}

RemoteObjectHolderImpl* CjRemoteObjectImpl::GetHolder()
{
    return holder_;
}

bool CjRemoteObjectImpl::IsProxyObject()
{
    if (holder_ == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get napi remote object holder");
        return false;
    }
    sptr<IRemoteObject> target = holder_->Get();
    if (target == nullptr) {
        ZLOGE(LOG_LABEL, "native stub object is nullptr");
        return false;
    }
    return target->IsProxyObject();
}

sptr<IRemoteObject> CjRemoteObjectImpl::GetRemoteObject()
{
    if (holder_ == nullptr) {
        ZLOGE(LOG_LABEL, "failed to get napi remote object holder");
        return nullptr;
    }
    return holder_->Get();
}

int64_t CreateStubRemoteObject(const sptr<IRemoteObject> target)
{
    std::u16string descriptor = target->GetObjectDescriptor();
    RemoteObjectHolderImpl* holder = new (std::nothrow) RemoteObjectHolderImpl(descriptor);
    if (holder == nullptr) {
        return 0;
    }
    holder->Set(target);
    auto remotrObject = FFIData::Create<CjRemoteObjectImpl>(holder);
    if (!remotrObject) {
        delete holder;
        return 0;
    }
    return remotrObject->GetID();
}

int64_t CreateProxyRemoteObject(const sptr<IRemoteObject> target)
{
    auto proxyHolder = FFIData::Create<RemoteProxyHolderImpl>();
    if (proxyHolder == nullptr) {
        return 0;
    }
    proxyHolder->object_ = target;
    proxyHolder->list_ = new (std::nothrow) CJDeathRecipientList();
    if (proxyHolder->list_ == nullptr) {
        ZLOGE(LOG_LABEL, "new NAPIDeathRecipientList failed");
        FFIData::Release(proxyHolder->GetID());
        return 0;
    }
    return proxyHolder->GetID();
}

int64_t CJ_rpc_CreateRemoteObject(const sptr<IRemoteObject> target)
{
    if (target == nullptr) {
        uint64_t curTime = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
                .count());
        ZLOGE(LOG_LABEL, "RemoteObject is null time:%{public}" PRIu64, curTime);
        return 0;
    }
    if (!target->IsProxyObject()) {
        IPCObjectStub* tmp = static_cast<IPCObjectStub*>(target.GetRefPtr());
        uint32_t objectType = static_cast<uint32_t>(tmp->GetObjectType());
        ZLOGD(LOG_LABEL, "create js object, type:%{public}d", objectType);
        if (objectType == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT || objectType == IPCObjectStub::OBJECT_TYPE_NATIVE) {
            return CreateStubRemoteObject(target);
        }
    }

    return CreateProxyRemoteObject(target);
}

sptr<IRemoteObject> CJ_rpc_getNativeRemoteObject(int64_t object)
{
    auto remoteObject = FFIData::GetData<CjIRemoteObjectImpl>(object);
    if (!remoteObject) {
        ZLOGE(LOG_LABEL, "get stub constructor failed");
        return nullptr;
    }
    return remoteObject->GetRemoteObject();
}

extern "C" {
FFI_EXPORT int64_t OHOS_CallCreateRemoteObject(void* param)
{
    auto remoteObject = reinterpret_cast<sptr<IRemoteObject>*>(param);
    if (remoteObject == nullptr) {
        return 0;
    }
    return CJ_rpc_CreateRemoteObject(*remoteObject);
}

FFI_EXPORT void OHOS_CallGetNativeRemoteObject(int64_t object, void* param)
{
    if (param == nullptr) {
        return;
    }
    auto ret = CJ_rpc_getNativeRemoteObject(object);
    auto remoteObject = reinterpret_cast<sptr<IRemoteObject>*>(param);
    *remoteObject = ret;
    return;
}
}
} // namespace OHOS
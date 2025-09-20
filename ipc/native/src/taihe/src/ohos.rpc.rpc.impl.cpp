/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ohos.rpc.rpc.proj.hpp"
#include "ohos.rpc.rpc.impl.hpp"
#include "taihe/runtime.hpp"
#include "ohos.rpc.rpc.TypeCode.proj.1.hpp"
#include "stdexcept"

#include <cinttypes>
#include <unistd.h>

#include "ashmem.h"
#include "ipc_debug.h"
#include "ipc_skeleton.h"
#include "hilog/log.h"
#include "log_tags.h"
#include "message_option.h"
#include "refbase.h"
#include "rpc_taihe_error.h"
#include "remote_object_taihe_ani.h"

#include "taihe_ani_remote_object.h"
#include "taihe_ashmem.h"
#include "taihe_deathrecipient.h"
#include "taihe_ipc_skeleton.h"
#include "taihe_iremote_broker.h"
#include "taihe_message_option.h"
#include "taihe_message_sequence.h"
#include "taihe_parcelable.h"
#include "taihe_remote_object.h"
#include "taihe_remote_proxy.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "napi/native_api.h"
#include "napi_message_sequence.h"
#include "ohos.rpc.rpc.check.h"

#include "napi_ashmem.h"
#include "napi_remote_object_holder.h"
#include "napi_remote_proxy_holder.h"
#include "message_option.h"
namespace OHOS {

static constexpr int MAP_PROT_MAX = AshmemImpl::PROT_EXEC | AshmemImpl::PROT_READ | AshmemImpl::PROT_WRITE;

// DeathRecipientImpl
DeathRecipientImpl::DeathRecipientImpl(::ohos::rpc::rpc::DeathRecipient jsObjRef) : jsObjRef_(jsObjRef)
{
}

void DeathRecipientImpl::OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object)
{
    jsObjRef_->OnRemoteDied();
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call onRemoteDied failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
    }
}

// ANIRemoteObject
ANIRemoteObject::ANIRemoteObject(const std::u16string &descriptor, ::ohos::rpc::rpc::weak::RemoteObject jsObj)
    : OHOS::IPCObjectStub(descriptor), jsObjRef_(jsObj)
{
}

ANIRemoteObject::~ANIRemoteObject()
{
}

int ANIRemoteObject::OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
    OHOS::MessageOption &option)
{
    auto jsData = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(&data);
    jsData->AddJsObjWeakRef(jsData);
    auto jsReply = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(&reply);
    jsReply->AddJsObjWeakRef(jsReply);
    auto jsOption = taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(option.GetFlags(),
        option.GetWaitTime());
    auto ret = jsObjRef_.value()->OnRemoteMessageRequest(code, jsData, jsReply, jsOption);
    return ret ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
}

int ANIRemoteObject::GetObjectType() const
{
    return OBJECT_TYPE_JAVASCRIPT;
}

::ohos::rpc::rpc::RemoteObject ANIRemoteObject::GetJsObject()
{
    return jsObjRef_.value();
}

// IRemoteBrokerImpl
::ohos::rpc::rpc::IRemoteObjectUnion IRemoteBrokerImpl::AsObject()
{
    TH_THROW(std::runtime_error, "asObject should be implemented in ets");
}

// RemoteProxyImpl
RemoteProxyImpl::RemoteProxyImpl(uintptr_t nativePtr, bool isCreateJsRemoteObj)
{
    if (reinterpret_cast<void*>(nativePtr) == nullptr) {
        ZLOGE(LOG_LABEL, "nativePtr is null");
        TH_THROW(std::runtime_error, "RemoteProxyImpl nativePtr is nullptr");
        return;
    }
    if (isCreateJsRemoteObj) {
        auto proxy = reinterpret_cast<RemoteObjectTaiheAni *>(nativePtr);
        if (proxy == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast nativePtr failed");
            TH_THROW(std::runtime_error, "RemoteProxyImpl reinterpret_cast nativePtr failed");
            return;
        }
        auto ipcObjectProxy = reinterpret_cast<OHOS::IPCObjectProxy *>((proxy->nativeObject_).GetRefPtr());
        if (ipcObjectProxy == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast nativeObject failed");
            TH_THROW(std::runtime_error, "RemoteProxyImpl reinterpret_cast nativeObject failed");
            return;
        }
        cachedObject_ = ipcObjectProxy;
        return;
    }
    auto proxy = reinterpret_cast<OHOS::IPCObjectProxy *>(nativePtr);
    if (proxy == nullptr) {
        ZLOGE(LOG_LABEL, "reinterpret_cast nativePtr failed");
        TH_THROW(std::runtime_error, "RemoteProxyImpl reinterpret_cast nativePtr failed");
        return;
    }
    cachedObject_ = proxy;
}

::ohos::rpc::rpc::IRemoteBroker RemoteProxyImpl::GetLocalInterface(::taihe::string_view descriptor)
{
    ZLOGE(LOG_LABEL, "only RemoteObject permitted");
    auto jsBroker = taihe::make_holder<IRemoteBrokerImpl, ::ohos::rpc::rpc::IRemoteBroker>();
    RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_ONLY_REMOTE_OBJECT_PERMITTED_ERROR, jsBroker);
}

::ohos::rpc::rpc::RequestResult RemoteProxyImpl::SendMessageRequestSync(
    int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data,
    ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options)
{
    auto nativeData = reinterpret_cast<OHOS::MessageParcel *>(data->GetNativePtr());
    auto nativeReply = reinterpret_cast<OHOS::MessageParcel *>(reply->GetNativePtr());
    auto nativeOptions = reinterpret_cast<OHOS::MessageOption *>(options->GetNativePtr());
    int32_t ret = cachedObject_->SendRequest(code, *nativeData, *nativeReply, *nativeOptions);
    return { ret, code, data, reply };
}

void RemoteProxyImpl::RegisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient recipient, int32_t flags)
{
    OHOS::sptr<DeathRecipientImpl> nativeDeathRecipient = new (std::nothrow) DeathRecipientImpl(recipient);
    if (!cachedObject_->AddDeathRecipient(nativeDeathRecipient)) {
        ZLOGE(LOG_LABEL, "AddDeathRecipient failed");
        return;
    }

    deathRecipientMap_.emplace(&recipient, nativeDeathRecipient);
}

void RemoteProxyImpl::UnregisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient recipient, int32_t flags)
{
    auto it = deathRecipientMap_.find(&recipient);
    if (it != deathRecipientMap_.end()) {
        if (!cachedObject_->RemoveDeathRecipient(it->second)) {
            ZLOGE(LOG_LABEL, "RemoveDeathRecipient failed");
        }
        deathRecipientMap_.erase(&recipient);
    } else {
        ZLOGE(LOG_LABEL, "DeathRecipient not found");
    }
    return;
}

::taihe::string RemoteProxyImpl::GetDescriptor()
{
    return OHOS::Str16ToStr8(cachedObject_->GetInterfaceDescriptor());
}

bool RemoteProxyImpl::IsObjectDead()
{
    return cachedObject_->IsObjectDead();
}

int64_t RemoteProxyImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(cachedObject_.GetRefPtr());
}

::ohos::rpc::rpc::RemoteProxy RemoteProxyImpl::RpcTransferStaticProxy(uintptr_t input)
{
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(taihe::get_env(), reinterpret_cast<ani_object>(input), &nativePtr) ||
        !nativePtr) {
        ZLOGE(LOG_LABEL, "arkts_esvalue_unwrap failed");
        return taihe::make_holder<RemoteProxyImpl, ::ohos::rpc::rpc::RemoteProxy>(0);
    }
    auto *napiRemoteProxy = reinterpret_cast<NAPIRemoteObjectHolder *>(nativePtr);
    if (!napiRemoteProxy) {
        ZLOGE(LOG_LABEL, "napiRemoteProxy is nullptr");
        return taihe::make_holder<RemoteProxyImpl, ::ohos::rpc::rpc::RemoteProxy>(0);
    }
    auto remoteProxyptr = napiRemoteProxy->Get();
    auto jsref = taihe::make_holder<RemoteProxyImpl,
        ::ohos::rpc::rpc::RemoteProxy>(reinterpret_cast<uintptr_t>(remoteProxyptr.GetRefPtr()));
    jsref->AddJsObjWeakRef(jsref);
    return jsref;
}

uintptr_t RemoteProxyImpl::RpcTransferDynamicProxy(::ohos::rpc::rpc::RemoteProxy obj)
{
    int64_t impRawPtr = obj->GetNativePtr();
    auto *proxy = reinterpret_cast<OHOS::IPCObjectProxy *>(impRawPtr);
    if (!proxy) {
        ZLOGE(LOG_LABEL, "impl or objectProxy is nullptr");
        return 0;
    }
    napi_env jsenv;
    if (!arkts_napi_scope_open(taihe::get_env(), &jsenv)) {
        ZLOGE(LOG_LABEL, "arkts_napi_scope_open failed");
        return 0;
    }
    napi_value global = nullptr;
    napi_status status = napi_get_global(jsenv, &global);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_get_global failed");
        return 0;
    }
    napi_value constructor = nullptr;
    status = napi_get_named_property(jsenv, global, "IPCProxyConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "Get constructor failed");
        return 0;
    }
 
    napi_value jsRemoteProxy = nullptr;
    status = napi_new_instance(jsenv, constructor, 0, nullptr, &jsRemoteProxy);
 
    auto proxyHolder = new (std::nothrow) NAPIRemoteProxyHolder();
    if (!proxyHolder) {
        return 0;
    }
    proxyHolder->object_ = proxy;
    // connect native object to js thisVar
    status = napi_wrap(
        jsenv, jsRemoteProxy, proxyHolder,
        [](napi_env env, void *data, void *hint) {
            NAPIRemoteProxyHolder *remoteproxy = reinterpret_cast<NAPIRemoteProxyHolder *>(data);
            if (remoteproxy) {
                delete remoteproxy;
            }
        }, nullptr, nullptr);
    uintptr_t result = 0;
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_wrap js RemoteProxy and native option failed");
        delete proxyHolder;
    } else {
        arkts_napi_scope_close_n(jsenv, 1, &jsRemoteProxy, reinterpret_cast<ani_ref *>(&result));
    }
    return result;
}

void RemoteProxyImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::RemoteProxy obj)
{
    jsObjRef_ = std::optional<::ohos::rpc::rpc::weak::RemoteProxy>(std::in_place, obj);
}

::ohos::rpc::rpc::RemoteProxy RemoteProxyImpl::CreateRemoteProxyFromNative(uintptr_t nativePtr)
{
    ::ohos::rpc::rpc::RemoteProxy obj = taihe::make_holder<RemoteProxyImpl, ::ohos::rpc::rpc::RemoteProxy>(nativePtr);
    obj->AddJsObjWeakRef(obj);
    return obj;
}

// ParcelableImpl
bool ParcelableImpl::Marshalling(::ohos::rpc::rpc::weak::MessageSequence dataOut)
{
    TH_THROW(std::runtime_error, "mashalling not implemented");
}

bool ParcelableImpl::Unmarshalling(::ohos::rpc::rpc::weak::MessageSequence dataIn)
{
    TH_THROW(std::runtime_error, "unmarshalling not implemented");
}

// AshmemImpl
// only be used for returning invalid Ashmem.
AshmemImpl::AshmemImpl()
{
}

AshmemImpl::AshmemImpl(const char *name, int32_t size)
{
    ashmem_ = OHOS::Ashmem::CreateAshmem(name, size);
}

AshmemImpl::AshmemImpl(OHOS::sptr<OHOS::Ashmem> ashmem)
{
    int32_t fd = ashmem->GetAshmemFd();
    int32_t size = ashmem->GetAshmemSize();
    if (fd < 0 || size == 0) {
        ZLOGE(LOG_LABEL, "fd < 0 or size == 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        ZLOGE(LOG_LABEL, "fail to dup fd:%{public}d", dupFd);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_OS_DUP_ERROR);
    }
    OHOS::sptr<OHOS::Ashmem> newAshmem(new (std::nothrow) OHOS::Ashmem(dupFd, size));
    if (newAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "fail to create new Ashmem");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_PARCEL_MEMORY_ALLOC_ERROR);
    }
    ashmem_ = newAshmem;
}

int64_t AshmemImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(ashmem_.GetRefPtr());
}

::ohos::rpc::rpc::Ashmem AshmemImpl::RpcTransferStaticAshmem(uintptr_t input)
{
    ZLOGE(LOG_LABEL, "RpcTransferStaticImpl start");
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(taihe::get_env(), reinterpret_cast<ani_object>(input), &nativePtr) ||
        !nativePtr) {
        ZLOGE(LOG_LABEL, "arkts_esvalue_unwrap failed");
        return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>();
    }
 
    auto *napiAshmem = reinterpret_cast<NAPIAshmem *>(nativePtr);
    if (!napiAshmem) {
        ZLOGE(LOG_LABEL, "napiAshmem is nullptr");
        return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>();
    }
 
    OHOS::sptr<OHOS::Ashmem> ashmemImpl = napiAshmem->GetAshmem();
    if (!ashmemImpl) {
        ZLOGE(LOG_LABEL, "ashmemImpl is nullptr");
        return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>();
    }
 
    auto jsref = taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(ashmemImpl);
    return jsref;
}

uintptr_t AshmemImpl::RpcTransferDynamicAshmem(::ohos::rpc::rpc::Ashmem obj)
{
    int64_t impRawPtr = obj->GetNativePtr();
    auto *ashmem = reinterpret_cast<Ashmem *>(impRawPtr);
    if (!ashmem) {
        ZLOGE(LOG_LABEL, "ashmem is nullptr");
        return 0;
    }
    napi_env jsenv;
    if (!arkts_napi_scope_open(taihe::get_env(), &jsenv)) {
        ZLOGE(LOG_LABEL, "arkts_napi_scope_open failed");
        return 0;
    }
    napi_value global = nullptr;
    napi_status status = napi_get_global(jsenv, &global);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_get_global failed");
        return 0;
    }
    napi_value constructor = nullptr;
    status = napi_get_named_property(jsenv, global, "AshmemConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "Get Ashmem constructor failed");
        return 0;
    }
    return TransferDynamicAshmem(ashmem, jsenv, constructor);
}

uintptr_t AshmemImpl::TransferDynamicAshmem(Ashmem* ashmem, napi_env jsenv, napi_value constructor)
{
    if (!ashmem) {
        ZLOGE(LOG_LABEL, "ashmem is nullptr");
        return 0;
    }
    int fd = ashmem->GetAshmemFd();
    int32_t size = ashmem->GetAshmemSize();
    if (fd <= 0 || size == 0) {
        ZLOGE(LOG_LABEL, "fd <= 0 or size == 0");
        return 0;
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        ZLOGE(LOG_LABEL, "Fail to dup fd:%{public}d", dupFd);
        close(dupFd);
        return 0;
    }
    napi_value jsAshmem = nullptr;
    napi_status status = napi_new_instance(jsenv, constructor, 0, nullptr, &jsAshmem);
    if (status != napi_ok) {
        close(dupFd);
        ZLOGE(LOG_LABEL, "Failed to  construct js Ashmem");
        return 0;
    }
    auto newAshmem = new (std::nothrow) Ashmem(dupFd, size);
    if (newAshmem == nullptr) {
        close(dupFd);
        ZLOGE(LOG_LABEL, "newAshmem is null");
        return 0;
    }
    status = napi_wrap(
        jsenv, jsAshmem, newAshmem,
        [](napi_env env, void *data, void *hint) {
            Ashmem *ashmem = reinterpret_cast<Ashmem *>(data);
            delete ashmem;
        },
        nullptr, nullptr);
    uintptr_t result = 0;
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "wrap js AshmemImpl and native option failed");
        delete newAshmem;
    } else {
        arkts_napi_scope_close_n(jsenv, 1, &jsAshmem, reinterpret_cast<ani_ref *>(&result));
    }
    return result;
}

void AshmemImpl::MapReadWriteAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    ashmem_->MapReadAndWriteAshmem();
}

int32_t AshmemImpl::GetAshmemSize()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR, 0);
    return ashmem_->GetAshmemSize();
}

void AshmemImpl::SetProtectionType(int32_t protectionType)
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_IOCTL_ERROR);
    ashmem_->SetProtection(protectionType);
}

void AshmemImpl::MapReadonlyAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    ashmem_->MapReadOnlyAshmem();
}

void AshmemImpl::MapTypedAshmem(int32_t mapType)
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    if (mapType > MAP_PROT_MAX) {
        ZLOGE(LOG_LABEL, "napiAshmem mapType error");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    ashmem_->MapAshmem(mapType);
}

void AshmemImpl::CloseAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    ashmem_->CloseAshmem();
}

void AshmemImpl::UnmapAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    ashmem_->UnmapAshmem();
}

::taihe::array<uint8_t> AshmemImpl::ReadDataFromAshmem(int32_t size, int32_t offset)
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(ashmem_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_FROM_ASHMEM_ERROR, ::taihe::array<uint8_t>(nullptr, 0));
    uint32_t ashmemSize = (uint32_t)GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() ||
        offset < 0 || offset > std::numeric_limits<int32_t>::max() ||
        (size + offset) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}d offset:%{public}d", size, offset);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    const void *rawData = ashmem_->ReadFromAshmem(size, offset);
    if (rawData == nullptr) {
        ZLOGE(LOG_LABEL, "rawData is null");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    const uint8_t* bytePtr = static_cast<const uint8_t*>(rawData);
    std::vector<uint8_t> res(size);
    std::copy(bytePtr, bytePtr + size, res.begin());
    return ::taihe::array<uint8_t>(res);
}

void AshmemImpl::WriteDataToAshmem(::taihe::array_view<uint8_t> buf, int32_t size, int32_t offset)
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::TAIHE_OS_MMAP_ERROR);
    uint32_t ashmemSize = (uint32_t)GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() ||
        offset < 0 || offset > std::numeric_limits<int32_t>::max() ||
        (size + offset) > ashmemSize) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}d offset:%{public}d", size, offset);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
        return;
    }
    if (!ashmem_->WriteToAshmem(static_cast<const void*>(buf.data()), size, offset)) {
        ZLOGE(LOG_LABEL, "write data failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

OHOS::sptr<OHOS::Ashmem> AshmemImpl::GetAshmem()
{
    return ashmem_;
}

::ohos::rpc::rpc::Ashmem AshmemImpl::CreateAshmem_WithTwoParam(::taihe::string_view name, int32_t size)
{
    return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(name.data(), size);
}

::ohos::rpc::rpc::Ashmem AshmemImpl::CreateAshmem_WithOneParam(::ohos::rpc::rpc::weak::Ashmem ashmem)
{
    OHOS::sptr<OHOS::Ashmem> nativeAshmem = reinterpret_cast<OHOS::Ashmem *>(ashmem->GetNativePtr());
    return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(nativeAshmem);
}

// RemoteObjectImpl
// ETS to ANI
RemoteObjectImpl::RemoteObjectImpl(::taihe::string_view descriptor) : desc_(descriptor)
{
}

// ANI to ETS
RemoteObjectImpl::RemoteObjectImpl(uintptr_t nativePtr) : desc_("")
{
    if (reinterpret_cast<void*>(nativePtr) == nullptr) {
        ZLOGE(LOG_LABEL, "nativePtr is null");
        TH_THROW(std::runtime_error, "nativePtr is null");
        return;
    }
    
    auto stub = reinterpret_cast<OHOS::IPCObjectStub *>(nativePtr);
    if (stub == nullptr) {
        ZLOGE(LOG_LABEL, "reinterpret_cast nativePtr failed");
        TH_THROW(std::runtime_error, "reinterpret_cast nativePtr failed");
        return;
    }
    desc_ = OHOS::Str16ToStr8(stub->GetObjectDescriptor());
    sptrCachedObject_ = stub;
}

int32_t RemoteObjectImpl::GetCallingPid()
{
    return OHOS::IPCSkeleton::GetCallingPid();
}

int32_t RemoteObjectImpl::GetCallingUid()
{
    return OHOS::IPCSkeleton::GetCallingUid();
}

void RemoteObjectImpl::ModifyLocalInterface(::ohos::rpc::rpc::weak::IRemoteBroker localInterface,
    ::taihe::string_view descriptor)
{
    jsLocalInterface_ = localInterface;
    desc_ = descriptor;
}

::ohos::rpc::rpc::IRemoteBroker RemoteObjectImpl::GetLocalInterface(::taihe::string_view descriptor)
{
    if (descriptor != desc_) {
        ZLOGE(LOG_LABEL, "descriptor: %{public}s mispatch, expected: %{public}s", descriptor.data(), desc_.data());
        TH_THROW(std::runtime_error, "descriptor mispatch");
    }
    return jsLocalInterface_.value();
}

::ohos::rpc::rpc::RequestResult RemoteObjectImpl::SendMessageRequestSync(
    int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data,
    ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options)
{
    auto ret = jsObjRef_.value()->OnRemoteMessageRequest(code, data, reply, options);
    int32_t retVal = ret ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
    return { retVal, code, data, reply };
}

bool RemoteObjectImpl::OnRemoteMessageRequest(int32_t code, ::ohos::rpc::rpc::weak::MessageSequence data,
    ::ohos::rpc::rpc::weak::MessageSequence reply, ::ohos::rpc::rpc::weak::MessageOption options)
{
    TH_THROW(std::runtime_error, "OnRemoteMessageRequest should be implemented int ets");
}

void RemoteObjectImpl::RegisterDeathRecipient(::ohos::rpc::rpc::weak::DeathRecipient recipient, int32_t flags)
{
    ZLOGI(LOG_LABEL, "only RemoteProxy needed");
}

void RemoteObjectImpl::UnregisterDeathRecipient(::ohos::rpc::rpc::weak::DeathRecipient recipient, int32_t flags)
{
    ZLOGI(LOG_LABEL, "only RemoteProxy needed");
}

::taihe::string RemoteObjectImpl::GetDescriptor()
{
    return desc_;
}

bool RemoteObjectImpl::IsObjectDead()
{
    return false;
}

OHOS::sptr<OHOS::IPCObjectStub> RemoteObjectImpl::GetNativeObject()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    // grab an strong reference to the object,
    // so it will not be freed util this reference released.
    if (sptrCachedObject_ != nullptr) {
        return sptrCachedObject_;
    }
    OHOS::sptr<OHOS::IPCObjectStub> tmp = wptrCachedObject_.promote();
    if (tmp == nullptr) {
        std::u16string descStr16(desc_.begin(), desc_.end());
        tmp = new (std::nothrow) ANIRemoteObject(descStr16, jsObjRef_.value());
        if (tmp == nullptr) {
            ZLOGE(LOG_LABEL, "new ANIRemoteObject failed");
            return nullptr;
        }
        wptrCachedObject_ = tmp;
    }
    return tmp;
}

::ohos::rpc::rpc::RemoteObject RemoteObjectImpl::RpcTransferStaticObject(uintptr_t input)
{
    ZLOGE(LOG_LABEL, "RpcTransferStaticImpl start");
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(taihe::get_env(), reinterpret_cast<ani_object>(input), &nativePtr)) {
        ZLOGE(LOG_LABEL, "arkts_esvalue_unwrap failed");
        return taihe::make_holder<RemoteObjectImpl, ::ohos::rpc::rpc::RemoteObject>(0);
    }
 
    auto *napiRemoteObjectHolder = reinterpret_cast<NAPIRemoteObjectHolder *>(nativePtr);
 
    if (!napiRemoteObjectHolder) {
        ZLOGE(LOG_LABEL, "napiRemoteObjectHolder is nullptr");
        return taihe::make_holder<RemoteObjectImpl, ::ohos::rpc::rpc::RemoteObject>(0);
    }
    
    auto remoteObjectptr = napiRemoteObjectHolder->Get();
    auto jsref = taihe::make_holder<RemoteObjectImpl,
        ::ohos::rpc::rpc::RemoteObject>(reinterpret_cast<uintptr_t>(remoteObjectptr.GetRefPtr()));
    return jsref;
}

uintptr_t RemoteObjectImpl::RpcTransferDynamicObject(::ohos::rpc::rpc::RemoteObject obj)
{
    int64_t impRawPtr = obj->GetNativePtr();
    auto *remoteObject = reinterpret_cast<IRemoteObject *>(impRawPtr);
    if (!remoteObject) {
        ZLOGE(LOG_LABEL, "remoteObject is nullptr");
        return 0;
    }
 
    napi_env jsenv;
    if (!arkts_napi_scope_open(taihe::get_env(), &jsenv)) {
        ZLOGE(LOG_LABEL, "arkts_napi_scope_open failed");
        return 0;
    }
    napi_value global = nullptr;
    napi_status status = napi_get_global(jsenv, &global);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_get_global failed");
        return 0;
    }
    napi_value constructor = nullptr;
    status = napi_get_named_property(jsenv, global, "IPCStubConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "Get constructor failed");
        return 0;
    }
    return TransferDynamicObject(remoteObject, jsenv, constructor);
}

uintptr_t RemoteObjectImpl::TransferDynamicObject(IRemoteObject* remoteObject, napi_env jsenv, napi_value constructor)
{
    if (!remoteObject) {
        ZLOGE(LOG_LABEL, "remoteObject is nullptr");
        return 0;
    }
    auto descriptor = remoteObject->GetInterfaceDescriptor();
    std::u16string descStr16(descriptor.begin(), descriptor.end());
    const std::string descStr8 = Str16ToStr8(descStr16);
 
    napi_value jsRemoteObject = nullptr;
    napi_value jsDesc = nullptr;
    napi_create_string_utf8(jsenv, descStr8.c_str(), descStr8.length(), &jsDesc);
    napi_value argv[1] = {jsDesc};
    napi_status status = napi_new_instance(jsenv, constructor, 1, argv, &jsRemoteObject);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_new_instance failed");
        return 0;
    }
 
    auto holder = new (std::nothrow) NAPIRemoteObjectHolder(jsenv, OHOS::Str8ToStr16(descStr8), jsRemoteObject);
    if (holder == nullptr) {
        ZLOGE(LOG_LABEL, "new NAPIRemoteObjectHolder failed");
        return 0;
    }
 
    status = napi_wrap(
        jsenv, jsRemoteObject, holder,
        [](napi_env env, void *data, void *hint) {
            NAPIRemoteObjectHolder *remoteObject = reinterpret_cast<NAPIRemoteObjectHolder *>(data);
            delete remoteObject;
        },
        nullptr, nullptr);
    uintptr_t result = 0;
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_wrap failed");
        delete holder;
        return 0;
    } else {
        arkts_napi_scope_close_n(jsenv, 1, &jsRemoteObject, reinterpret_cast<ani_ref *>(&result));
    }
    return result;
}

int64_t RemoteObjectImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(sptrCachedObject_ != nullptr ?
        sptrCachedObject_.GetRefPtr() : wptrCachedObject_.GetRefPtr());
}

void RemoteObjectImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::RemoteObject obj, bool isNative)
{
    jsObjRef_ = std::optional<::ohos::rpc::rpc::RemoteObject>(std::in_place, obj);
    std::u16string descStr16(desc_.begin(), desc_.end());
    if (!isNative) {
        wptrCachedObject_ = new (std::nothrow) ANIRemoteObject(descStr16, jsObjRef_.value());
    } else {
        sptrCachedObject_ = new (std::nothrow) ANIRemoteObject(descStr16, jsObjRef_.value());
    }
}

::ohos::rpc::rpc::RemoteObject RemoteObjectImpl::CreateRemoteObject(::ohos::rpc::rpc::weak::RemoteObject jsSelf,
    ::taihe::string_view descriptor)
{
    ::ohos::rpc::rpc::RemoteObject obj = taihe::make_holder<RemoteObjectImpl,
        ::ohos::rpc::rpc::RemoteObject>(descriptor);
    obj->AddJsObjWeakRef(jsSelf, true);
    return obj;
}

::ohos::rpc::rpc::RemoteObject RemoteObjectImpl::CreateRemoteObjectFromNative(uintptr_t nativePtr)
{
    ::ohos::rpc::rpc::RemoteObject obj = taihe::make_holder<RemoteObjectImpl,
        ::ohos::rpc::rpc::RemoteObject>(nativePtr);
    obj->AddJsObjWeakRef(obj, false);
    return obj;
}





int64_t unwrapRemoteObject(::ohos::rpc::rpc::IRemoteObjectUnion const& obj)
{
    if (obj.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
        auto &remoteStub = obj.get_remoteObject_ref();
        int64_t objectptr = remoteStub->GetNativePtr();
        return objectptr;
    }
    if (obj.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
        auto &remoteProxy = obj.get_remoteProxy_ref();
        int64_t proxyptr = remoteProxy->GetNativePtr();
        return proxyptr;
    }
    return 0;
}

::ohos::rpc::rpc::IRemoteObjectUnion wrapRemoteObject(int64_t nativePtr)
{
    if (reinterpret_cast<void*>(nativePtr) == nullptr) {
        ZLOGE(LOG_LABEL, "nativePtr is nullptr");
        TH_THROW(std::runtime_error, "nativePtr is null");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::ohos::rpc::rpc::IRemoteObjectUnion::make_errRet());
    }
    ::ohos::rpc::rpc::RemoteProxy obj = taihe::make_holder<RemoteProxyImpl,
        ::ohos::rpc::rpc::RemoteProxy>(nativePtr, true);
    return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteProxy(obj);
}

// MessageOptionImpl
MessageOptionImpl::MessageOptionImpl(int32_t syncFlags, int32_t waitTime)
{
    messageOption_ = std::make_shared<OHOS::MessageOption>(syncFlags, waitTime);
}

bool MessageOptionImpl::IsAsync()
{
    if (messageOption_ == nullptr) {
        ZLOGE(LOG_LABEL, "messageOption_ is null");
        taihe::set_error("failed to get native message option");
        return false;
    }
    int flags = messageOption_->GetFlags();
    return (flags & OHOS::MessageOption::TF_ASYNC) != 0;
}

void MessageOptionImpl::SetAsync(bool isAsync)
{
    if (messageOption_ == nullptr) {
        ZLOGE(LOG_LABEL, "messageOption_ is null");
        taihe::set_error("failed to get native message option");
        return;
    }
    messageOption_->SetFlags(static_cast<int32_t>(isAsync));
}

int64_t MessageOptionImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(messageOption_.get());
}

int32_t MessageOptionImpl::GetFlags()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(messageOption_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return messageOption_->GetFlags();
}

void MessageOptionImpl::SetFlags(int32_t flags)
{
    CHECK_NATIVE_OBJECT(messageOption_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    messageOption_->SetFlags(flags);
}

int32_t MessageOptionImpl::GetWaitTime()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(messageOption_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return messageOption_->GetWaitTime();
}

void MessageOptionImpl::SetWaitTime(int32_t waitTime)
{
    CHECK_NATIVE_OBJECT(messageOption_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    messageOption_->SetWaitTime(waitTime);

::ohos::rpc::rpc::MessageOption MessageOptionImpl::RpcTransferStaticOption(uintptr_t input)
{
    ZLOGE(LOG_LABEL, "RpcTransferStaticImpl start");
    void *nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(taihe::get_env(), reinterpret_cast<ani_object>(input), &nativePtr) ||
        !nativePtr) {
        ZLOGE(LOG_LABEL, "arkts_esvalue_unwrap failed");
        return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(OHOS::MessageOption::TF_SYNC,
            OHOS::MessageOption::TF_WAIT_TIME);
    }
 
    auto *tempMessageOption = reinterpret_cast<MessageOption *>(nativePtr);
    if (!tempMessageOption) {
        ZLOGE(LOG_LABEL, "tempMessageOption is nullptr");
        return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(OHOS::MessageOption::TF_SYNC,
            OHOS::MessageOption::TF_WAIT_TIME);
    }
    auto jsref = taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(tempMessageOption->GetFlags(),
        tempMessageOption->GetWaitTime());
    jsref->AddJsObjWeakRef(jsref);
    return jsref;
}

uintptr_t MessageOptionImpl::RpcTransferDynamicOption(::ohos::rpc::rpc::MessageOption obj)
{
    int64_t impRawPtr = obj->GetNativePtr();
    auto *messageOption = reinterpret_cast<MessageOption *>(impRawPtr);
    if (!messageOption) {
        ZLOGE(LOG_LABEL, "messageOptionTemp is nullptr");
        return 0;
    }
 
    napi_env jsenv;
    if (!arkts_napi_scope_open(taihe::get_env(), &jsenv)) {
        ZLOGE(LOG_LABEL, "arkts_napi_scope_open failed");
        return 0;
    }
    napi_value global = nullptr;
    napi_status status = napi_get_global(jsenv, &global);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_get_global failed");
        return 0;
    }
    napi_value constructor = nullptr;
    status = napi_get_named_property(jsenv, global, "IPCOptionConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get constructor failed");
        return 0;
    }
    napi_value jsMessageOption = nullptr;
    status = napi_new_instance(jsenv, constructor, 0, nullptr, &jsMessageOption);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_new_instance failed");
        return 0;
    }
    return TransferDynamicOption(messageOption, jsenv, jsMessageOption);
}

uintptr_t MessageOptionImpl::TransferDynamicOption(MessageOption* messageOpt, napi_env jsenv,
    napi_value jsMessageOption)
{
    if (!messageOpt) {
        ZLOGE(LOG_LABEL, "messageOpt is nullptr");
        return 0;
    }
    int flag = messageOpt->GetFlags();
    int waitTime = messageOpt->GetWaitTime();
    auto messageOption = new (std::nothrow) MessageOption(flag, waitTime);
    napi_status status = napi_wrap(
        jsenv, jsMessageOption, messageOption,
        [](napi_env env, void *data, void *hint) {
            ZLOGD(LOG_LABEL, "NAPIMessageOption destructed by js callback");
            delete (reinterpret_cast<MessageOption *>(data));
        },
        nullptr, nullptr);
    uintptr_t result = 0;
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "wrap js MessageOption and native option failed");
        delete messageOption;
    } else {
        arkts_napi_scope_close_n(jsenv, 1, &jsMessageOption, reinterpret_cast<ani_ref *>(&result));
    }
    return result;
}

void MessageOptionImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::MessageOption obj)
{
    jsObjRef_ = std::optional<::ohos::rpc::rpc::MessageOption>(std::in_place, obj);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption_WithTwoParam(int32_t syncFlags,
    int32_t waitTime)
{
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(syncFlags, waitTime);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption_WithOneParam(bool isAsync)
{
    int flags = isAsync ? OHOS::MessageOption::TF_ASYNC : OHOS::MessageOption::TF_SYNC;
    int waitTime = OHOS::MessageOption::TF_WAIT_TIME;
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(flags, waitTime);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption()
{
    int flags = OHOS::MessageOption::TF_SYNC;
    int waitTime = OHOS::MessageOption::TF_WAIT_TIME;
    return taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(flags, waitTime);
}

// IPCSkeletonImpl
int32_t IPCSkeletonImpl::GetCallingPid()
{
    return OHOS::IPCSkeleton::GetCallingPid();
}

int32_t IPCSkeletonImpl::GetCallingUid()
{
    return OHOS::IPCSkeleton::GetCallingUid();
}

int64_t IPCSkeletonImpl::GetCallingTokenId()
{
    return static_cast<int64_t>(OHOS::IPCSkeleton::GetCallingTokenID());
}

::taihe::string IPCSkeletonImpl::ResetCallingIdentity()
{
    return static_cast<::taihe::string>(OHOS::IPCSkeleton::ResetCallingIdentity());
}

void IPCSkeletonImpl::RestoreCallingIdentity(::taihe::string_view identity)
{
    std::string temp = std::string(identity);
    size_t maxLen = 40960;
    if (temp.size() >= maxLen) {
        ZLOGE(LOG_LABEL, "string length too large");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    OHOS::IPCSkeleton::SetCallingIdentity(temp);
}

void IPCSkeletonImpl::FlushCmdBuffer(::ohos::rpc::rpc::IRemoteObjectUnion const& object)
{
    if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
        auto &remoteStub = object.get_remoteObject_ref();
        OHOS::sptr<OHOS::IRemoteObject> nativeStub =
            reinterpret_cast<OHOS::IRemoteObject *>(remoteStub->GetNativePtr());
        if (nativeStub == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast to IRemoteObject failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
        }
        OHOS::IPCSkeleton::FlushCommands(nativeStub);
    } else if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
        auto &remoteProxy = object.get_remoteProxy_ref();
        auto nativeProxy = reinterpret_cast<OHOS::IPCObjectProxy *>(remoteProxy->GetNativePtr());
        if (nativeProxy == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast to IPCObjectProxy failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
        }
        OHOS::IPCSkeleton::FlushCommands(nativeProxy);
    } else {
        ZLOGE(LOG_LABEL, "unknown tag: %{public}d", object.get_tag());
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
}

::taihe::string IPCSkeletonImpl::GetCallingDeviceID()
{
    return static_cast<::taihe::string>(OHOS::IPCSkeleton::GetCallingDeviceID());
}

::taihe::string IPCSkeletonImpl::GetLocalDeviceID()
{
    return static_cast<::taihe::string>(OHOS::IPCSkeleton::GetLocalDeviceID());
}

bool IPCSkeletonImpl::IsLocalCalling()
{
    return OHOS::IPCSkeleton::IsLocalCalling();
}

::ohos::rpc::rpc::IRemoteObjectUnion IPCSkeletonImpl::GetContextObject()
{
    auto object = OHOS::IPCSkeleton::GetContextObject();
    uintptr_t addr = reinterpret_cast<uintptr_t>(object.GetRefPtr());
    auto jsProxy = RemoteProxyImpl::CreateRemoteProxyFromNative(addr);
    return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteProxy(jsProxy);
}

}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateRemoteObject(OHOS::RemoteObjectImpl::CreateRemoteObject);
TH_EXPORT_CPP_API_CreateRemoteObjectFromNative(OHOS::RemoteObjectImpl::CreateRemoteObjectFromNative);
TH_EXPORT_CPP_API_RpcTransferStaticObject(OHOS::RemoteObjectImpl::RpcTransferStaticObject);
TH_EXPORT_CPP_API_RpcTransferDynamicObject(OHOS::RemoteObjectImpl::RpcTransferDynamicObject);
TH_EXPORT_CPP_API_CreateRemoteProxyFromNative(OHOS::RemoteProxyImpl::CreateRemoteProxyFromNative);
TH_EXPORT_CPP_API_RpcTransferStaticProxy(OHOS::RemoteProxyImpl::RpcTransferStaticProxy);
TH_EXPORT_CPP_API_RpcTransferDynamicProxy(OHOS::RemoteProxyImpl::RpcTransferDynamicProxy);
TH_EXPORT_CPP_API_CreateMessageOption_WithTwoParam(OHOS::MessageOptionImpl::CreateMessageOption_WithTwoParam);
TH_EXPORT_CPP_API_CreateMessageOption_WithOneParam(OHOS::MessageOptionImpl::CreateMessageOption_WithOneParam);
TH_EXPORT_CPP_API_CreateMessageOption(OHOS::MessageOptionImpl::CreateMessageOption);
TH_EXPORT_CPP_API_RpcTransferStaticOption(OHOS::MessageOptionImpl::RpcTransferStaticOption);
TH_EXPORT_CPP_API_RpcTransferDynamicOption(OHOS::MessageOptionImpl::RpcTransferDynamicOption);
TH_EXPORT_CPP_API_CreateAshmem_WithTwoParam(OHOS::AshmemImpl::CreateAshmem_WithTwoParam);
TH_EXPORT_CPP_API_CreateAshmem_WithOneParam(OHOS::AshmemImpl::CreateAshmem_WithOneParam);
TH_EXPORT_CPP_API_RpcTransferStaticAshmem(OHOS::AshmemImpl::RpcTransferStaticAshmem);
TH_EXPORT_CPP_API_RpcTransferDynamicAshmem(OHOS::AshmemImpl::RpcTransferDynamicAshmem);
TH_EXPORT_CPP_API_GetCallingPid(OHOS::IPCSkeletonImpl::GetCallingPid);
TH_EXPORT_CPP_API_GetCallingUid(OHOS::IPCSkeletonImpl::GetCallingUid);
TH_EXPORT_CPP_API_GetCallingTokenId(OHOS::IPCSkeletonImpl::GetCallingTokenId);
TH_EXPORT_CPP_API_GetContextObject(OHOS::IPCSkeletonImpl::GetContextObject);
TH_EXPORT_CPP_API_ResetCallingIdentity(OHOS::IPCSkeletonImpl::ResetCallingIdentity);
TH_EXPORT_CPP_API_RestoreCallingIdentity(OHOS::IPCSkeletonImpl::RestoreCallingIdentity);
TH_EXPORT_CPP_API_FlushCmdBuffer(OHOS::IPCSkeletonImpl::FlushCmdBuffer);
TH_EXPORT_CPP_API_GetCallingDeviceID(OHOS::IPCSkeletonImpl::GetCallingDeviceID);
TH_EXPORT_CPP_API_GetLocalDeviceID(OHOS::IPCSkeletonImpl::GetLocalDeviceID);
TH_EXPORT_CPP_API_IsLocalCalling(OHOS::IPCSkeletonImpl::IsLocalCalling);
TH_EXPORT_CPP_API_unwrapRemoteObject(OHOS::unwrapRemoteObject);
TH_EXPORT_CPP_API_wrapRemoteObject(OHOS::wrapRemoteObject);
// NOLINTEND
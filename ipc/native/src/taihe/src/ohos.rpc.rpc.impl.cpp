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

#include "napi_ashmem.h"
#include "napi_remote_object_holder.h"
#include "napi_remote_proxy_holder.h"
#include "message_option.h"
namespace OHOS {

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_OTHER, "RpcTaiheImpl" };
static constexpr int MAP_PROT_MAX = AshmemImpl::PROT_EXEC | AshmemImpl::PROT_READ | AshmemImpl::PROT_WRITE;
constexpr size_t MAX_BYTES_LENGTH = 40960;
constexpr size_t BYTE_SIZE_64 = 8;
constexpr size_t BYTE_SIZE_32 = 4;
constexpr size_t BYTE_SIZE_16 = 2;
constexpr size_t BYTE_SIZE_8 = 1;

#define CHECK_WRITE_POSITION(nativeParcel, maxCapacityToWrite)                                                        \
    do {                                                                                                              \
        if ((maxCapacityToWrite) < (nativeParcel)->GetWritePosition()) {                                              \
            ZLOGE(LOG_LABEL, "invalid write position, maxCapacityToWrite:%{public}zu, GetWritePosition:%{public}zu",  \
                (maxCapacityToWrite), (nativeParcel)->GetWritePosition());                                            \
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);                           \
        }                                                                                                             \
    } while (0)

#define CHECK_WRITE_CAPACITY(lenToWrite, nativeParcel, maxCapacityToWrite)                                            \
    do {                                                                                                              \
        CHECK_WRITE_POSITION(nativeParcel, maxCapacityToWrite);                                                       \
        size_t cap = (maxCapacityToWrite) - (nativeParcel)->GetWritePosition();                                       \
        if (cap < (lenToWrite)) {                                                                                     \
            ZLOGE(LOG_LABEL, "No enough write capacity, cap:%{public}zu, lenToWrite:%{public}zu", cap, lenToWrite);   \
            taihe::set_error("No enough capacity to write");                                                          \
            return;                                                                                                   \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_POSITION(nativeParcel)                                                                             \
    do {                                                                                                              \
        if ((nativeParcel)->GetDataSize() < (nativeParcel)->GetReadPosition()) {                                      \
            ZLOGE(LOG_LABEL, "invalid read position, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",           \
                (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());                                    \
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);                          \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_POSITION_RETVAL(nativeParcel, retVal)                                                              \
    do {                                                                                                              \
        if ((nativeParcel)->GetDataSize() < (nativeParcel)->GetReadPosition()) {                                      \
            ZLOGE(LOG_LABEL, "invalid read position, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",           \
                (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());                                    \
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, retVal);      \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_LENGTH(arrayLength, typeSize, nativeParcel)                                                        \
    do {                                                                                                              \
        CHECK_READ_POSITION(nativeParcel);                                                                            \
        size_t remainSize = (nativeParcel)->GetDataSize() - (nativeParcel)->GetReadPosition();                        \
        if (((arrayLength) < 0) || ((arrayLength) > remainSize) || (((arrayLength) * (typeSize)) > remainSize)) {     \
            ZLOGE(LOG_LABEL, "No enough data to read, arrayLength:%{public}zu, remainSize:%{public}zu,"               \
                "typeSize:%{public}zu, GetDataSize:%{public}zu, GetReadPosition:%{public}zu", arrayLength,            \
                remainSize, typeSize, (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());              \
            taihe::set_error("No enough data to read");                                                               \
            return;                                                                                                   \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_LENGTH_RETVAL(arrayLength, typeSize, nativeParcel, retVal)                                         \
    do {                                                                                                              \
        CHECK_READ_POSITION_RETVAL(nativeParcel, retVal);                                                             \
        size_t remainSize = (nativeParcel)->GetDataSize() - (nativeParcel)->GetReadPosition();                        \
        if (((arrayLength) < 0) || ((arrayLength) > remainSize) || (((arrayLength) * (typeSize)) > remainSize)) {     \
            ZLOGE(LOG_LABEL, "No enough data to read, arrayLength:%{public}zu, remainSize:%{public}zu,"               \
                "typeSize:%{public}zu, GetDataSize:%{public}zu, GetReadPosition:%{public}zu", arrayLength,            \
                remainSize, typeSize, (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());              \
            taihe::set_error("No enough data to read");                                                               \
            return retVal;                                                                                            \
        }                                                                                                             \
    } while (0)

#define REWIND_IF_WRITE_CHECK_FAIL(lenToWrite, pos, nativeParcel, maxCapacityToWrite)                                 \
    do {                                                                                                              \
        CHECK_WRITE_POSITION(nativeParcel, maxCapacityToWrite);                                                       \
        size_t cap = (maxCapacityToWrite) - (nativeParcel)->GetWritePosition();                                       \
        if (cap < (lenToWrite)) {                                                                                     \
            ZLOGE(LOG_LABEL, "No enough write capacity, cap:%{public}zu, lenToWrite:%{public}zu", cap, lenToWrite);   \
            (nativeParcel)->RewindWrite(pos);                                                                         \
            taihe::set_error("No enough data to read");                                                               \
            return;                                                                                                   \
        }                                                                                                             \
    } while (0)

#define CHECK_NATIVE_OBJECT(object, errorCode)                                                                        \
    do {                                                                                                              \
        if ((object) == nullptr) {                                                                                    \
            ZLOGE(LOG_LABEL, "native object is null");                                                                \
            RPC_TAIHE_ERROR(errorCode);                                                                               \
        }                                                                                                             \
    } while (0)

#define CHECK_NATIVE_OBJECT_WITH_RETVAL(object, errorCode, retval)                                                    \
    do {                                                                                                              \
        if ((object) == nullptr) {                                                                                    \
            ZLOGE(LOG_LABEL, "native object is null");                                                                \
            RPC_TAIHE_ERROR_WITH_RETVAL(errorCode, retval);                                                           \
        }                                                                                                             \
    } while (0)

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

// MessageSequenceImpl
MessageSequenceImpl::MessageSequenceImpl()
{
    nativeParcel_ = new (std::nothrow) OHOS::MessageParcel();
    if (nativeParcel_ == nullptr) {
        ZLOGE(LOG_LABEL, "create MessageParcel failed");
        taihe::set_error("create MessageParcel failed");
    }
    sharedNativeParcel_ = std::make_shared<OHOS::MessageParcel>();
    if (sharedNativeParcel_ == nullptr) {
        ZLOGE(LOG_LABEL, "create MessageParcelShared failed");
        taihe::set_error("create MessageParcelShared failed");
    }
    isOwner_ = true;
}

MessageSequenceImpl::MessageSequenceImpl(std::shared_ptr<OHOS::MessageParcel> messageparcel)
{
    sharedNativeParcel_ = messageparcel;
    isOwner_ = false;
}

MessageSequenceImpl::MessageSequenceImpl(OHOS::MessageParcel* messageparcel)
{
    nativeParcel_ = messageparcel;
    isOwner_ = false;
}

MessageSequenceImpl::~MessageSequenceImpl()
{
    Reclaim();
}

void MessageSequenceImpl::Reclaim()
{
    if (isOwner_ && nativeParcel_ != nullptr) {
        delete nativeParcel_;
    }
    nativeParcel_ = nullptr;
    sharedNativeParcel_ = nullptr;
}

int64_t MessageSequenceImpl::GetMessageSequenceImpl()
{
    return reinterpret_cast<int64_t>(this);
}

::ohos::rpc::rpc::MessageSequence MessageSequenceImpl::RpcTransferStaicImpl(uintptr_t input)
{
    ZLOGE(LOG_LABEL, "RpcTransferStaicImpl start");
    void* nativePtr = nullptr;
    if (!arkts_esvalue_unwrap(taihe::get_env(), reinterpret_cast<ani_object>(input), &nativePtr) ||
        !nativePtr) {
        ZLOGE(LOG_LABEL, "arkts_esvalue_unwrap failed");
        return taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>();
    }

    auto* napiMessageSequence = reinterpret_cast<NAPI_MessageSequence*>(nativePtr);
    if (!napiMessageSequence) {
        ZLOGE(LOG_LABEL, "napiMessageSequence is nullptr");
        return taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>();
    }

    std::shared_ptr<OHOS::MessageParcel> parcel = napiMessageSequence->GetMessageParcel();
    if (!parcel) {
        ZLOGE(LOG_LABEL, "parcel is nullptr");
        return taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>();
    }

    auto jsref = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(parcel);
    jsref->AddJsObjWeakRef(jsref);
    return jsref;
}

uintptr_t MessageSequenceImpl::RpcTransferDynamicImpl(::ohos::rpc::rpc::MessageSequence obj)
{
    ZLOGE(LOG_LABEL, "RpcTransferDynamicImpl start");
    int64_t impRawPtr = obj->GetMessageSequenceImpl();
    auto* impl = reinterpret_cast<MessageSequenceImpl*>(impRawPtr);
    if (!impl || !impl->GetNativeParcel()) {
        ZLOGE(LOG_LABEL, "impl or parcel is nullptr");
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
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        return 0;
    }

    napi_value jsMessageSequence = nullptr;
    CreateJsMessageSequence(jsenv, status, global, &jsMessageSequence);
    if (jsMessageSequence == nullptr) {
        ZLOGE(LOG_LABEL, "CreateJsMessageSequence failed");
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        return 0;
    }

    auto messageSequence = new (std::nothrow) NAPI_MessageSequence(jsenv, jsMessageSequence, impl->GetNativeParcel());
    status = napi_wrap(
        jsenv,
        jsMessageSequence,
        messageSequence,
        [](napi_env env, void *data, void *hint) {
            NAPI_MessageSequence *messageSequence = reinterpret_cast<NAPI_MessageSequence *>(data);
            delete messageSequence;
        },
        nullptr,
        nullptr);

    uintptr_t result = 0;
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_wrap failed");
        delete messageSequence;
        arkts_napi_scope_close_n(jsenv, 0, nullptr, nullptr);
        return 0;
    } else {
        arkts_napi_scope_close_n(jsenv, 1, &jsMessageSequence, reinterpret_cast<ani_ref*>(&result));
    }
    return result;
}

void MessageSequenceImpl::CreateJsMessageSequence(napi_env jsenv, napi_status status, napi_value global,
    napi_value* jsMessageSequence)

{
    napi_value constructor = nullptr;
    status = napi_get_named_property(jsenv, global, "IPCSequenceConstructor_", &constructor);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "get constructor failed");
        return;
    }

    status = napi_new_instance(jsenv, constructor, 0, nullptr, jsMessageSequence);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_new_instance failed");
        return;
    }
}

void MessageSequenceImpl::WriteRemoteObject(::ohos::rpc::rpc::IRemoteObjectUnion const& object)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
        auto &remoteStub = object.get_remoteObject_ref();
        OHOS::sptr<OHOS::IRemoteObject> nativeStub =
            reinterpret_cast<OHOS::IRemoteObject *>(remoteStub->GetNativePtr());
        if (nativeStub == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast to IRemoteObject failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        bool result = nativeParcel_->WriteRemoteObject(nativeStub);
        if (!result) {
            ZLOGE(LOG_LABEL, "write RemoteObject failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        return;
    } else if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
        auto &remoteProxy = object.get_remoteProxy_ref();
        auto nativeProxy = reinterpret_cast<OHOS::IPCObjectProxy *>(remoteProxy->GetNativePtr());
        bool result = nativeParcel_->WriteRemoteObject(nativeProxy);
        if (!result) {
            ZLOGE(LOG_LABEL, "write RemoteProxy failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        return;
    } else {
        ZLOGE(LOG_LABEL, "unknown tag: %{public}d", object.get_tag());
        TH_THROW(std::runtime_error, "unknown tag");
    }
}

::ohos::rpc::rpc::IRemoteObjectUnion MessageSequenceImpl::ReadRemoteObject()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::ohos::rpc::rpc::IRemoteObjectUnion::make_errRet());
    OHOS::sptr<OHOS::IRemoteObject> obj = nativeParcel_->ReadRemoteObject();
    if (obj == nullptr) {
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::ohos::rpc::rpc::IRemoteObjectUnion::make_errRet());
    }
    if (obj->IsProxyObject()) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(obj.GetRefPtr());
        auto jsProxy = RemoteProxyImpl::CreateRemoteProxyFromNative(addr);
        return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteProxy(jsProxy);
    } else {
        auto stub = reinterpret_cast<OHOS::IPCObjectStub *>(obj.GetRefPtr());
        if (stub->GetObjectType() == OHOS::IPCObjectStub::OBJECT_TYPE_JAVASCRIPT) {
            auto aniStub = reinterpret_cast<ANIRemoteObject *>(obj.GetRefPtr());
            return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteObject(aniStub->GetJsObject());
        } else {
            uintptr_t addr = reinterpret_cast<uintptr_t>(stub);
            auto jsStub = RemoteObjectImpl::CreateRemoteObjectFromNative(addr);
            return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteObject(jsStub);
        }
    }
}

void MessageSequenceImpl::WriteInterfaceToken(::taihe::string_view token)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (token.size() > MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "token is too large");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    std::u16string tokenStr(token.begin(), token.end());
    bool result = nativeParcel_->WriteInterfaceToken(tokenStr);
    if (!result) {
        ZLOGE(LOG_LABEL, "write interface token failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
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

::taihe::string MessageSequenceImpl::ReadInterfaceToken()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "");
    std::u16string result = nativeParcel_->ReadInterfaceToken();
    return OHOS::Str16ToStr8(result);
}

int32_t MessageSequenceImpl::GetCapacity()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = nativeParcel_->GetDataCapacity();
    return result;
}

void MessageSequenceImpl::SetCapacity(int32_t size)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->SetDataCapacity(size);
    if (!result) {
        ZLOGE(LOG_LABEL, "set data capacity failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteNoException()
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt32(0);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::ReadException()
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t code = nativeParcel_->ReadInt32();
    if (code == 0) {
        ZLOGE(LOG_LABEL, "ReadException failed, no exception");
        return;
    }
    std::u16string result = nativeParcel_->ReadString16();
    taihe::set_business_error(code, OHOS::Str16ToStr8(result));
}

void MessageSequenceImpl::WriteInt(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt32(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteLong(int64_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt64(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int64 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteBoolean(bool val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt8(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int8 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteChar(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteUint8(static_cast<uint8_t>(val));
    if (!result) {
        ZLOGE(LOG_LABEL, "write uint8 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteString(::taihe::string_view val)
{
    if (val.size() > MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "write string failed, string size:%{public}zu is too large", val.size());
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 * val.size(), nativeParcel_, (nativeParcel_->GetMaxCapacity()));
    std::u16string str(val.begin(), val.end());
    bool result = nativeParcel_->WriteString16(str);
    if (!result) {
        ZLOGE(LOG_LABEL, "write string16 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteParcelable(::ohos::rpc::rpc::weak::Parcelable val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteInt32(1);
    val->Marshalling(*jsObjRef_);
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call marshalling failed");
        nativeParcel_->RewindWrite(pos);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
    }
}

void MessageSequenceImpl::WriteByteArray(::taihe::array_view<int8_t> byteArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = byteArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + (BYTE_SIZE_8 * arrayLength), nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt8(byteArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int8 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteShortArray(::taihe::array_view<int32_t> shortArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = shortArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(int16_t) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt16(static_cast<int16_t>(shortArray[i]));
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int16 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteIntArray(::taihe::array_view<int32_t> intArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = intArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 * (arrayLength + 1), nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt32(intArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int32 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteLongArray(::taihe::array_view<int64_t> longArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = longArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(int64_t) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt64(longArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int64 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteFloatArray(::taihe::array_view<double> floatArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = floatArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(double) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteDouble(floatArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write float failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteDoubleArray(::taihe::array_view<double> doubleArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = doubleArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(double) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteDouble(doubleArray[i]);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write double failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteBooleanArray(::taihe::array_view<bool> booleanArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = booleanArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + (BYTE_SIZE_8 * arrayLength), nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteInt8(static_cast<int8_t>(booleanArray[i]));
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write int8 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteCharArray(::taihe::array_view<int32_t> charArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = charArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(uint8_t) * arrayLength, nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        result = nativeParcel_->WriteUint8(static_cast<uint8_t>(charArray[i]));
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write uint8 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteStringArray(::taihe::array_view<::taihe::string> stringArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = stringArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        if (stringArray[i].size() > MAX_BYTES_LENGTH) {
            ZLOGE(LOG_LABEL, "string length is too long, index:%{public}zu, size:%{public}zu",
                i, stringArray[i].size());
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
        }
        REWIND_IF_WRITE_CHECK_FAIL(BYTE_SIZE_32 + (BYTE_SIZE_16 * stringArray[i].size()), pos, nativeParcel_,
            (nativeParcel_->GetMaxCapacity()));
        std::u16string str(stringArray[i].begin(), stringArray[i].end());
        result = nativeParcel_->WriteString16(str);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write string16 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = parcelableArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    size_t pos = nativeParcel_->GetWritePosition();
    if (!(nativeParcel_->WriteUint32(arrayLength))) {
        ZLOGE(LOG_LABEL, "write array length failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    for (size_t i = 0; i < arrayLength; i++) {
        nativeParcel_->WriteInt32(1);
        parcelableArray[i]->Marshalling(*jsObjRef_);
        if (taihe::has_error()) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "call marshalling failed, element index:%{public}zu", i);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteRemoteObjectArray(::taihe::array_view<::ohos::rpc::rpc::IRemoteObjectUnion> objectArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = objectArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 + sizeof(::ohos::rpc::rpc::IRemoteObjectUnion) * arrayLength,
        nativeParcel_, nativeParcel_->GetMaxCapacity());
    size_t pos = nativeParcel_->GetWritePosition();
    if (!(nativeParcel_->WriteUint32(arrayLength))) {
        ZLOGE(LOG_LABEL, "write array length failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    for (size_t i = 0; i < arrayLength; i++) {
        if (objectArray[i].get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
            auto &remoteStub = objectArray[i].get_remoteObject_ref();
            OHOS::sptr<OHOS::IRemoteObject> nativeStub =
                reinterpret_cast<OHOS::IRemoteObject *>(remoteStub->GetNativePtr());
            if (nativeStub == nullptr) {
                ZLOGE(LOG_LABEL, "reinterpret_cast to IRemoteObject failed");
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
            bool result = nativeParcel_->WriteRemoteObject(nativeStub);
            if (!result) {
                ZLOGE(LOG_LABEL, "write RemoteObject failed");
                nativeParcel_->RewindWrite(pos);
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        } else if (objectArray[i].get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
            auto &remoteProxy = objectArray[i].get_remoteProxy_ref();
            auto nativeProxy = reinterpret_cast<OHOS::IPCObjectProxy *>(remoteProxy->GetNativePtr());
            bool result = nativeParcel_->WriteRemoteObject(nativeProxy);
            if (!result) {
                ZLOGE(LOG_LABEL, "write RemoteProxy failed");
                nativeParcel_->RewindWrite(pos);
                RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
            }
        } else {
            ZLOGE(LOG_LABEL, "unknown tag: %{public}d", objectArray[i].get_tag());
            TH_THROW(std::runtime_error, "unknown tag");
        }
    }
}

int32_t MessageSequenceImpl::ReadInt()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return nativeParcel_->ReadInt32();
}

int64_t MessageSequenceImpl::ReadLong()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return nativeParcel_->ReadInt64();
}

bool MessageSequenceImpl::ReadBoolean()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, false);
    return static_cast<bool>(nativeParcel_->ReadInt8());
}

::taihe::string MessageSequenceImpl::ReadString()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "");
    return OHOS::Str16ToStr8(nativeParcel_->ReadString16());
}

void MessageSequenceImpl::ReadParcelable(::ohos::rpc::rpc::weak::Parcelable dataIn)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t flags = nativeParcel_->ReadInt32();
    if (flags != 1) {
        ZLOGE(LOG_LABEL, "read parcelable failed, flags:%{public}d", flags);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    dataIn->Unmarshalling(*jsObjRef_);
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call marshalling failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
    }
}

::taihe::array<int32_t> MessageSequenceImpl::ReadIntArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<int32_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<int32_t>(nullptr, 0)));
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_32,
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
    ::taihe::array<int32_t> res(arrayLength);
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt32(res[i])) {
            ZLOGE(LOG_LABEL, "read int32 failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<int32_t>(nullptr, 0)));
        }
    }
    return res;
}

::taihe::array<double> MessageSequenceImpl::ReadDoubleArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<double>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<double>(nullptr, 0)));
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(double),
        nativeParcel_, (::taihe::array<double>(nullptr, 0)));
    ::taihe::array<double> res(arrayLength);
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadDouble(res[i])) {
            ZLOGE(LOG_LABEL, "read double failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<double>(nullptr, 0)));
        }
    }
    return res;
}

::taihe::array<bool> MessageSequenceImpl::ReadBooleanArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<bool>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<bool>(nullptr, 0)));
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_8,
        nativeParcel_, (::taihe::array<bool>(nullptr, 0)));
    ::taihe::array<bool> res(arrayLength);
    int8_t val;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt8(val)) {
            ZLOGE(LOG_LABEL, "read bool failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<bool>(nullptr, 0)));
        }
        res[i] = (val != 0) ? true : false;
    }
    return res;
}

::taihe::array<::taihe::string> MessageSequenceImpl::ReadStringArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<::taihe::string>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<::taihe::string>(nullptr, 0)));
    }
    std::vector<std::string> res;
    std::u16string val;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (nativeParcel_->GetReadableBytes() <= 0) {
            break;
        }
        if (!nativeParcel_->ReadString16(val)) {
            ZLOGE(LOG_LABEL, "read string16 failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<::taihe::string>(nullptr, 0)));
        }
        res.push_back(OHOS::Str16ToStr8(val));
    }
    return ::taihe::array<::taihe::string>(taihe::copy_data_t{}, res.data(), res.size());
}

::taihe::array<int32_t> MessageSequenceImpl::ReadCharArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<int32_t>(nullptr, 0));
    uint32_t arrayLength = nativeParcel_->ReadUint32();
    std::vector<int32_t> res;
    for (uint32_t i = 0; i < arrayLength; i++) {
        uint8_t val = nativeParcel_->ReadUint8();
        res.push_back(static_cast<int32_t>(val));
    }
    return ::taihe::array<int32_t>(res);
}

::taihe::array<double> MessageSequenceImpl::ReadFloatArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<double>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    std::vector<double> res;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        res.push_back(nativeParcel_->ReadDouble());
    }
    return ::taihe::array<double>(res);
}

::taihe::array<int64_t> MessageSequenceImpl::ReadLongArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<int64_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    std::vector<int64_t> res;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        res.push_back(nativeParcel_->ReadInt64());
    }
    return ::taihe::array<int64_t>(res);
}

::taihe::array<int32_t> MessageSequenceImpl::ReadShortArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<int32_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    std::vector<int32_t> res;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        int16_t val = nativeParcel_->ReadInt16();
        res.push_back(static_cast<int32_t>(val));
    }
    return ::taihe::array<int32_t>(res);
}

int32_t MessageSequenceImpl::ReadChar()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    uint8_t value = nativeParcel_->ReadUint8();
    return static_cast<int32_t>(value);
}

double MessageSequenceImpl::ReadFloat()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    double value = nativeParcel_->ReadDouble();
    return value;
}

double MessageSequenceImpl::ReadDouble()
{
    return ReadFloat();
}

int32_t MessageSequenceImpl::ReadShort()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int16_t value = nativeParcel_->ReadInt16();
    return static_cast<int32_t>(value);
}

int32_t MessageSequenceImpl::ReadByte()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int8_t value = nativeParcel_->ReadInt8();
    return static_cast<int32_t>(value);
}

void MessageSequenceImpl::ReadParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    int32_t flags;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        flags = nativeParcel_->ReadInt32();
        if (flags != 1) {
            ZLOGE(LOG_LABEL, "read parcelable failed, flags:%{public}d", flags);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        }
        parcelableArray[i]->Unmarshalling(*jsObjRef_);
        if (taihe::has_error()) {
            ZLOGE(LOG_LABEL, "call unmarshalling failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteFileDescriptor(int32_t fd)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteFileDescriptor(fd);
    if (!result) {
        ZLOGE(LOG_LABEL, "write file descriptor failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

int32_t MessageSequenceImpl::ReadFileDescriptor()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = nativeParcel_->ReadFileDescriptor();
    if (result < 0) {
        ZLOGE(LOG_LABEL, "read file descriptor failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    }
    return result;
}

void MessageSequenceImpl::WriteAshmem(::ohos::rpc::rpc::weak::Ashmem ashmem)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (!nativeParcel_->WriteAshmem(reinterpret_cast<OHOS::Ashmem *>(ashmem->GetNativePtr()))) {
        ZLOGE(LOG_LABEL, "write ashmem failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

::ohos::rpc::rpc::Ashmem MessageSequenceImpl::ReadAshmem()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        (taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>()));
    OHOS::sptr<OHOS::Ashmem> nativeAshmem = nativeParcel_->ReadAshmem();
    if (nativeAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "nativeAshmem is null");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            (taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>()));
    }
    return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(nativeAshmem);
}

void MessageSequenceImpl::WriteRawDataBuffer(::taihe::array_view<uint8_t> rawData, int32_t size)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (!nativeParcel_->WriteRawData(static_cast<const void*>(rawData.data()), size)) {
        ZLOGE(LOG_LABEL, "write raw data failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadRawDataBuffer(int32_t size)
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<uint8_t>(nullptr, 0));
    if (size <= 0) {
        ZLOGE(LOG_LABEL, "invalid param size:%{public}d", size);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<uint8_t>(nullptr, 0)));
    }
    const void *rawData = nativeParcel_->ReadRawData(size);
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

int64_t MessageSequenceImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(nativeParcel_);
}

void MessageSequenceImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::MessageSequence obj)
{
    jsObjRef_ = std::optional<::ohos::rpc::rpc::weak::MessageSequence>(std::in_place, obj);
}

::ohos::rpc::rpc::MessageSequence MessageSequenceImpl::CreateMessageSequence()
{
    ::ohos::rpc::rpc::MessageSequence obj =
        taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>();
    obj->AddJsObjWeakRef(obj);
    return obj;
}

int32_t MessageSequenceImpl::DupFileDescriptor(int32_t fd)
{
    if (fd < 0) {
        ZLOGE(LOG_LABEL, "invalid fd:%{public}d", fd);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR, -1);
    }
    return dup(fd);
}

void MessageSequenceImpl::CloseFileDescriptor(int32_t fd)
{
    if (fd < 0) {
        ZLOGE(LOG_LABEL, "invalid fd:%{public}d", fd);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    close(fd);
}

void MessageSequenceImpl::WriteArrayBuffer(::taihe::array_view<uint8_t> buf, ::ohos::rpc::rpc::TypeCode typeCode)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (typeCode.get_key() < ohos::rpc::rpc::TypeCode::key_t::INT8_ARRAY
        || typeCode.get_key() > ohos::rpc::rpc::TypeCode::key_t::BIGUINT64_ARRAY) {
        ZLOGE(LOG_LABEL, "typeCode is out of range. typeCode:%{public}d", typeCode.get_value());
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    int32_t byteLength = buf.size();
    void *data = nullptr;
    data = static_cast<void*>(buf.data());
    if (!WriteVectorByTypeCode(data, typeCode, byteLength)) {
        ZLOGE(LOG_LABEL, "write array buffer failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

template<typename T>
static std::vector<T> BufferToVector(void *data, size_t byteLength)
{
    const T* dataPtr = reinterpret_cast<const T*>(data);
    std::vector<T> vec;
    std::copy(dataPtr, dataPtr + byteLength / sizeof(T), std::back_inserter(vec));
    return vec;
}

bool MessageSequenceImpl::WriteVectorByTypeCode(void *data, ::ohos::rpc::rpc::TypeCode typeCode, int32_t byteLength)
{
    switch (typeCode.get_key()) {
        case ohos::rpc::rpc::TypeCode::key_t::INT8_ARRAY: {
            return nativeParcel_->WriteInt8Vector(BufferToVector<int8_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT8_ARRAY: {
            return nativeParcel_->WriteUInt8Vector(BufferToVector<uint8_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::INT16_ARRAY: {
            return nativeParcel_->WriteInt16Vector(BufferToVector<int16_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT16_ARRAY: {
            return nativeParcel_->WriteUInt16Vector(BufferToVector<uint16_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::INT32_ARRAY: {
            return nativeParcel_->WriteInt32Vector(BufferToVector<int32_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT32_ARRAY: {
            return nativeParcel_->WriteUInt32Vector(BufferToVector<uint32_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::FLOAT32_ARRAY: {
            return nativeParcel_->WriteFloatVector(BufferToVector<float>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::FLOAT64_ARRAY: {
            return nativeParcel_->WriteDoubleVector(BufferToVector<double>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::BIGINT64_ARRAY: {
            return nativeParcel_->WriteInt64Vector(BufferToVector<int64_t>(data, byteLength));
        }
        case ohos::rpc::rpc::TypeCode::key_t::BIGUINT64_ARRAY: {
            return nativeParcel_->WriteUInt64Vector(BufferToVector<uint64_t>(data, byteLength));
        }
        default:
            ZLOGE(LOG_LABEL, "unsupported typeCode:%{public}d", typeCode.get_value());
            return false;
    }
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadArrayBuffer(::ohos::rpc::rpc::TypeCode typeCode)
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<uint8_t>(nullptr, 0));
    if (typeCode.get_key() < ohos::rpc::rpc::TypeCode::key_t::INT8_ARRAY
        || typeCode.get_key() > ohos::rpc::rpc::TypeCode::key_t::BIGUINT64_ARRAY) {
        ZLOGE(LOG_LABEL, "typeCode is out of range. typeCode:%{public}d", typeCode.get_value());
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    switch (typeCode.get_key()) {
        case ohos::rpc::rpc::TypeCode::key_t::INT8_ARRAY: {
            return ReadInt8ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT8_ARRAY: {
            return ReadUInt8ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::INT16_ARRAY: {
            return ReadInt16ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT16_ARRAY: {
            return ReadUInt16ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::INT32_ARRAY: {
            return ReadInt32ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::UINT32_ARRAY: {
            return ReadUInt32ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::FLOAT32_ARRAY: {
            return ReadFloatArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::FLOAT64_ARRAY: {
            return ReadDoubleArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::BIGINT64_ARRAY: {
            return ReadInt64ArrayBuffer();
        }
        case ohos::rpc::rpc::TypeCode::key_t::BIGUINT64_ARRAY: {
            return ReadUInt64ArrayBuffer();
        }
        default:
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
                ::taihe::array<uint8_t>(nullptr, 0));
    }
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt8ArrayBuffer()
{
    std::vector<int8_t> int8Vector;
    if (!nativeParcel_->ReadInt8Vector(&int8Vector)) {
        ZLOGE(LOG_LABEL, "read Int8Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int8Vector.data());
    int32_t byteLength = int8Vector.size();

    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt8ArrayBuffer()
{
    std::vector<uint8_t> uint8Vector;
    if (!nativeParcel_->ReadUInt8Vector(&uint8Vector)) {
        ZLOGE(LOG_LABEL, "read int16Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    return ::taihe::array<uint8_t>(uint8Vector);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt16ArrayBuffer()
{
    std::vector<int16_t> int16Vector;
    if (!nativeParcel_->ReadInt16Vector(&int16Vector)) {
        ZLOGE(LOG_LABEL, "read int16Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int16Vector.data());
    int32_t byteLength = int16Vector.size() * BYTE_SIZE_16;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt16ArrayBuffer()
{
    std::vector<uint16_t> uint16Vector;
    if (!nativeParcel_->ReadUInt16Vector(&uint16Vector)) {
        ZLOGE(LOG_LABEL, "read uint16Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(uint16Vector.data());
    int32_t byteLength = uint16Vector.size() * BYTE_SIZE_16;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt32ArrayBuffer()
{
    std::vector<int32_t> int32Vector;
    if (!nativeParcel_->ReadInt32Vector(&int32Vector)) {
        ZLOGE(LOG_LABEL, "read int32Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int32Vector.data());
    int32_t byteLength = int32Vector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt32ArrayBuffer()
{
    std::vector<uint32_t> uint32Vector;
    if (!nativeParcel_->ReadUInt32Vector(&uint32Vector)) {
        ZLOGE(LOG_LABEL, "read uint32Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(uint32Vector.data());
    int32_t byteLength = uint32Vector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadFloatArrayBuffer()
{
    std::vector<float> floatVector;
    if (!nativeParcel_->ReadFloatVector(&floatVector)) {
        ZLOGE(LOG_LABEL, "read floatVector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(floatVector.data());
    int32_t byteLength = floatVector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadDoubleArrayBuffer()
{
    std::vector<double> doubleVector;
    if (!nativeParcel_->ReadDoubleVector(&doubleVector)) {
        ZLOGE(LOG_LABEL, "read doubleVector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(doubleVector.data());
    int32_t byteLength = doubleVector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadInt64ArrayBuffer()
{
    std::vector<int64_t> int64Vector;
    if (!nativeParcel_->ReadInt64Vector(&int64Vector)) {
        ZLOGE(LOG_LABEL, "read int64Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(int64Vector.data());
    int32_t byteLength = int64Vector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadUInt64ArrayBuffer()
{
    std::vector<uint64_t> uint64Vector;
    if (!nativeParcel_->ReadUInt64Vector(&uint64Vector)) {
        ZLOGE(LOG_LABEL, "read uint64Vector failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    void *vec = nullptr;
    vec = static_cast<void*>(uint64Vector.data());
    int32_t byteLength = uint64Vector.size() * BYTE_SIZE_64;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
}

int32_t MessageSequenceImpl::GetSize()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetDataSize());
    return result;
}

int32_t MessageSequenceImpl::GetWritableBytes()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetWritableBytes());
    return result;
}

int32_t MessageSequenceImpl::GetReadableBytes()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetReadableBytes());
    return result;
}

int32_t MessageSequenceImpl::GetReadPosition()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetReadPosition());
    return result;
}

int32_t MessageSequenceImpl::GetWritePosition()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = static_cast<int32_t>(nativeParcel_->GetWritePosition());
    return result;
}

bool MessageSequenceImpl::ContainFileDescriptors()
{
    bool result = nativeParcel_->GetWritePosition();
    return result;
}

int32_t MessageSequenceImpl::GetRawDataCapacity()
{
    int32_t result = static_cast<int32_t>(nativeParcel_->GetRawDataCapacity());
    return result;
}

void MessageSequenceImpl::WriteByte(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt8(static_cast<int8_t>(val));
    if (!result) {
        ZLOGE(LOG_LABEL, "write int8 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteShort(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt16(static_cast<int16_t>(val));
    if (!result) {
        ZLOGE(LOG_LABEL, "write int16 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteFloat(double val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteDouble(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write float failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteDouble(double val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteDouble(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write double failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
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
}

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

::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion> MessageSequenceImpl::ReadRemoteObjectArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
    }
    if (!(nativeParcel_->WriteUint32(arrayLength))) {
        ZLOGE(LOG_LABEL, "write array length failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
    }
    std::vector<::ohos::rpc::rpc::IRemoteObjectUnion> res;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        ::ohos::rpc::rpc::IRemoteObjectUnion temp = ReadRemoteObject();
        if (temp.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::errRet) {
            ZLOGE(LOG_LABEL, "read RemoteObject failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
        }
        res.push_back(temp);
    }
    return ::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(res);
}

void MessageSequenceImpl::RewindRead(int32_t pos)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    nativeParcel_->RewindRead(static_cast<size_t>(pos));
}

void MessageSequenceImpl::RewindWrite(int32_t pos)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    nativeParcel_->RewindWrite(static_cast<size_t>(pos));
}

void MessageSequenceImpl::SetSize(int32_t size)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    nativeParcel_->SetDataSize(static_cast<size_t>(size));
}

::ohos::rpc::rpc::IRemoteObjectUnion IPCSkeletonImpl::GetContextObject()
{
    auto object = OHOS::IPCSkeleton::GetContextObject();
    uintptr_t addr = reinterpret_cast<uintptr_t>(object.GetRefPtr());
    auto jsProxy = RemoteProxyImpl::CreateRemoteProxyFromNative(addr);
    return ::ohos::rpc::rpc::IRemoteObjectUnion::make_remoteProxy(jsProxy);
}

::taihe::array<int32_t> MessageSequenceImpl::ReadByteArrayGet()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<int32_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR,
            (::taihe::array<int32_t>(nullptr, 0)));
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(int8_t),
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
    ::taihe::array<int32_t> res(arrayLength);
    int8_t value = 0;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt8(value)) {
            ZLOGE(LOG_LABEL, "read int8 failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<int32_t>(nullptr, 0)));
        }
        res[i] = static_cast<int32_t>(value);
    }
    return res;
}

void MessageSequenceImpl::ReadByteArrayIn(::taihe::array_view<int32_t> dataIn)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    CHECK_READ_LENGTH(static_cast<size_t>(arrayLength), sizeof(int8_t), nativeParcel_);
    int8_t value = 0;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt8(value)) {
            ZLOGE(LOG_LABEL, "read int8 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        }
        dataIn[i] = static_cast<int32_t>(value);
    }
    return;
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
TH_EXPORT_CPP_API_CreateMessageSequence(OHOS::MessageSequenceImpl::CreateMessageSequence);
TH_EXPORT_CPP_API_CloseFileDescriptor(OHOS::MessageSequenceImpl::CloseFileDescriptor);
TH_EXPORT_CPP_API_RpcTransferStaicImpl(OHOS::MessageSequenceImpl::RpcTransferStaicImpl);
TH_EXPORT_CPP_API_RpcTransferDynamicImpl(OHOS::MessageSequenceImpl::RpcTransferDynamicImpl);
TH_EXPORT_CPP_API_CreateMessageOption_WithTwoParam(OHOS::MessageOptionImpl::CreateMessageOption_WithTwoParam);
TH_EXPORT_CPP_API_CreateMessageOption_WithOneParam(OHOS::MessageOptionImpl::CreateMessageOption_WithOneParam);
TH_EXPORT_CPP_API_DupFileDescriptor(OHOS::MessageSequenceImpl::DupFileDescriptor);
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
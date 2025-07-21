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

namespace OHOS {

static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_OTHER, "RpcTaiheImpl" };
constexpr size_t MAX_BYTES_LENGTH = 40960;
constexpr size_t MAX_CAPACITY_TO_WRITE = 200 * 1024;
constexpr size_t BYTE_SIZE_32 = 4;
constexpr size_t BYTE_SIZE_16 = 2;
constexpr size_t BYTE_SIZE_8 = 1;

#define CHECK_WRITE_POSITION(nativeParcel, maxCapacityToWrite)                                                        \
    do {                                                                                                              \
        if ((maxCapacityToWrite) < (nativeParcel)->GetWritePosition()) {                                              \
            ZLOGE(LOG_LABEL, "invalid write position, maxCapacityToWrite:%{public}zu, GetWritePosition:%{public}zu",  \
                (maxCapacityToWrite), (nativeParcel)->GetWritePosition());                                            \
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);                           \
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
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);                          \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_POSITION_RETVAL(nativeParcel, retVal)                                                              \
    do {                                                                                                              \
        if ((nativeParcel)->GetDataSize() < (nativeParcel)->GetReadPosition()) {                                      \
            ZLOGE(LOG_LABEL, "invalid read position, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",           \
                (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());                                    \
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, retVal);      \
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
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CALL_JS_METHOD_ERROR);
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
RemoteProxyImpl::RemoteProxyImpl(uintptr_t nativePtr)
{
    if (reinterpret_cast<void*>(nativePtr) == nullptr) {
        ZLOGE(LOG_LABEL, "nativePtr is null");
        TH_THROW(std::runtime_error, "RemoteProxyImpl nativePtr is nullptr");
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
    RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::ONLY_REMOTE_OBJECT_PERMITTED_ERROR, jsBroker);
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
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        ZLOGE(LOG_LABEL, "fail to dup fd:%{public}d", dupFd);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::OS_DUP_ERROR);
    }
    OHOS::sptr<OHOS::Ashmem> newAshmem(new (std::nothrow) OHOS::Ashmem(dupFd, size));
    if (newAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "fail to create new Ashmem");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::PARCEL_MEMORY_ALLOC_ERROR);
    }
    ashmem_ = newAshmem;
}

int64_t AshmemImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(ashmem_.GetRefPtr());
}

void AshmemImpl::MapReadWriteAshmem()
{
    CHECK_NATIVE_OBJECT(ashmem_, OHOS::RpcTaiheErrorCode::OS_MMAP_ERROR);
    ashmem_->MapReadAndWriteAshmem();
}

int32_t AshmemImpl::GetAshmemSize()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(ashmem_, OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR, 0);
    return ashmem_->GetAshmemSize();
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
    isOwner_ = true;
    nativeParcel_->SetDataCapacity(MAX_CAPACITY_TO_WRITE);
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
}

void MessageSequenceImpl::WriteRemoteObject(::ohos::rpc::rpc::IRemoteObjectUnion const& object)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteObject) {
        auto &remoteStub = object.get_remoteObject_ref();
        OHOS::sptr<OHOS::IRemoteObject> nativeStub =
            reinterpret_cast<OHOS::IRemoteObject *>(remoteStub->GetNativePtr());
        if (nativeStub == nullptr) {
            ZLOGE(LOG_LABEL, "reinterpret_cast to IRemoteObject failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        bool result = nativeParcel_->WriteRemoteObject(nativeStub);
        if (!result) {
            ZLOGE(LOG_LABEL, "write RemoteObject failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        return;
    } else if (object.get_tag() == ::ohos::rpc::rpc::IRemoteObjectUnion::tag_t::remoteProxy) {
        auto &remoteProxy = object.get_remoteProxy_ref();
        auto nativeProxy = reinterpret_cast<OHOS::IPCObjectProxy *>(remoteProxy->GetNativePtr());
        bool result = nativeParcel_->WriteRemoteObject(nativeProxy);
        if (!result) {
            ZLOGE(LOG_LABEL, "write RemoteProxy failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
        return;
    } else {
        ZLOGE(LOG_LABEL, "unknown tag: %{public}d", object.get_tag());
        TH_THROW(std::runtime_error, "unknown tag");
    }
}

::ohos::rpc::rpc::IRemoteObjectUnion MessageSequenceImpl::ReadRemoteObject()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::ohos::rpc::rpc::IRemoteObjectUnion::make_errRet());
    OHOS::sptr<OHOS::IRemoteObject> obj = nativeParcel_->ReadRemoteObject();
    if (obj == nullptr) {
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
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
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (token.size() > MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "token is too large");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
    }
    std::u16string tokenStr(token.begin(), token.end());
    bool result = nativeParcel_->WriteInterfaceToken(tokenStr);
    if (!result) {
        ZLOGE(LOG_LABEL, "write interface token failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

::taihe::string MessageSequenceImpl::ReadInterfaceToken()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "");
    std::u16string result = nativeParcel_->ReadInterfaceToken();
    return OHOS::Str16ToStr8(result);
}

int32_t MessageSequenceImpl::GetCapacity()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = nativeParcel_->GetDataCapacity();
    return result;
}

void MessageSequenceImpl::SetCapacity(int32_t size)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->SetDataCapacity(size);
    if (!result) {
        ZLOGE(LOG_LABEL, "set data capacity failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteNoException()
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt32(0);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::ReadException()
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t code = nativeParcel_->ReadInt32();
    if (code == 0) {
        ZLOGE(LOG_LABEL, "ReadException failed, no exception");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    std::u16string result = nativeParcel_->ReadString16();
    taihe::set_business_error(code, OHOS::Str16ToStr8(result));
}

void MessageSequenceImpl::WriteInt(int32_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt32(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int32 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteLong(int64_t val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt64(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int64 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteBoolean(bool val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteInt8(val);
    if (!result) {
        ZLOGE(LOG_LABEL, "write int8 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteString(::taihe::string_view val)
{
    if (val.size() > MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "write string failed, string size:%{public}zu is too large", val.size());
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
    }
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    CHECK_WRITE_CAPACITY(BYTE_SIZE_32 * val.size(), nativeParcel_, (nativeParcel_->GetMaxCapacity()));
    std::u16string str(val.begin(), val.end());
    bool result = nativeParcel_->WriteString16(str);
    if (!result) {
        ZLOGE(LOG_LABEL, "write string16 failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

void MessageSequenceImpl::WriteParcelable(::ohos::rpc::rpc::weak::Parcelable val)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteInt32(1);
    val->Marshalling(*jsObjRef_);
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call marshalling failed");
        nativeParcel_->RewindWrite(pos);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CALL_JS_METHOD_ERROR);
    }
}

void MessageSequenceImpl::WriteByteArray(::taihe::array_view<int8_t> byteArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = byteArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
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
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteIntArray(::taihe::array_view<int32_t> intArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = intArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
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
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteDoubleArray(::taihe::array_view<double> doubleArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = doubleArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
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
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteBooleanArray(::taihe::array_view<bool> booleanArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = booleanArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
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
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteStringArray(::taihe::array_view<::taihe::string> stringArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = stringArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
    }
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        if (stringArray[i].size() > MAX_BYTES_LENGTH) {
            ZLOGE(LOG_LABEL, "string length is too long, index:%{public}zu, size:%{public}zu",
                i, stringArray[i].size());
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
        }
        REWIND_IF_WRITE_CHECK_FAIL(BYTE_SIZE_32 + (BYTE_SIZE_16 * stringArray[i].size()), pos, nativeParcel_,
            (nativeParcel_->GetMaxCapacity()));
        std::u16string str(stringArray[i].begin(), stringArray[i].end());
        result = nativeParcel_->WriteString16(str);
        if (!result) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "write string16 failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = parcelableArray.size();
    if (arrayLength == 0) {
        ZLOGE(LOG_LABEL, "arrayLength is 0");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
    }
    size_t pos = nativeParcel_->GetWritePosition();
    if (!(nativeParcel_->WriteUint32(arrayLength))) {
        ZLOGE(LOG_LABEL, "write array length failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
    for (size_t i = 0; i < arrayLength; i++) {
        nativeParcel_->WriteInt32(1);
        parcelableArray[i]->Marshalling(*jsObjRef_);
        if (taihe::has_error()) {
            nativeParcel_->RewindWrite(pos);
            ZLOGE(LOG_LABEL, "call marshalling failed, element index:%{public}zu", i);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CALL_JS_METHOD_ERROR);
        }
    }
}

int32_t MessageSequenceImpl::ReadInt()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return nativeParcel_->ReadInt32();
}

int64_t MessageSequenceImpl::ReadLong()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    return nativeParcel_->ReadInt64();
}

bool MessageSequenceImpl::ReadBoolean()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, false);
    return static_cast<bool>(nativeParcel_->ReadInt8());
}

::taihe::string MessageSequenceImpl::ReadString()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, "");
    return OHOS::Str16ToStr8(nativeParcel_->ReadString16());
}

void MessageSequenceImpl::ReadParcelable(::ohos::rpc::rpc::weak::Parcelable dataIn)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t flags = nativeParcel_->ReadInt32();
    if (flags != 1) {
        ZLOGE(LOG_LABEL, "read parcelable failed, flags:%{public}d", flags);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    }
    dataIn->Unmarshalling(*jsObjRef_);
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call marshalling failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CALL_JS_METHOD_ERROR);
    }
}

::taihe::array<int32_t> MessageSequenceImpl::ReadIntArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<int32_t>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
            (::taihe::array<int32_t>(nullptr, 0)));
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_32,
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
    ::taihe::array<int32_t> res(arrayLength);
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt32(res[i])) {
            ZLOGE(LOG_LABEL, "read int32 failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<int32_t>(nullptr, 0)));
        }
    }
    return res;
}

::taihe::array<double> MessageSequenceImpl::ReadDoubleArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<double>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
            (::taihe::array<double>(nullptr, 0)));
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(double),
        nativeParcel_, (::taihe::array<double>(nullptr, 0)));
    ::taihe::array<double> res(arrayLength);
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadDouble(res[i])) {
            ZLOGE(LOG_LABEL, "read double failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<double>(nullptr, 0)));
        }
    }
    return res;
}

::taihe::array<bool> MessageSequenceImpl::ReadBooleanArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<bool>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
            (::taihe::array<bool>(nullptr, 0)));
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), BYTE_SIZE_8,
        nativeParcel_, (::taihe::array<bool>(nullptr, 0)));
    ::taihe::array<bool> res(arrayLength);
    int8_t val;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        if (!nativeParcel_->ReadInt8(val)) {
            ZLOGE(LOG_LABEL, "read bool failed");
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<bool>(nullptr, 0)));
        }
        res[i] = (val != 0) ? true : false;
    }
    return res;
}

::taihe::array<::taihe::string> MessageSequenceImpl::ReadStringArrayImpl()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        ::taihe::array<::taihe::string>(nullptr, 0));
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
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
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
                (::taihe::array<::taihe::string>(nullptr, 0)));
        }
        res.push_back(OHOS::Str16ToStr8(val));
    }
    return ::taihe::array<::taihe::string>(taihe::copy_data_t{}, res.data(), res.size());
}

void MessageSequenceImpl::ReadParcelableArray(::taihe::array_view<::ohos::rpc::rpc::Parcelable> parcelableArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
    }
    int32_t flags;
    for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
        flags = nativeParcel_->ReadInt32();
        if (flags != 1) {
            ZLOGE(LOG_LABEL, "read parcelable failed, flags:%{public}d", flags);
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);
        }
        parcelableArray[i]->Unmarshalling(*jsObjRef_);
        if (taihe::has_error()) {
            ZLOGE(LOG_LABEL, "call unmarshalling failed");
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CALL_JS_METHOD_ERROR);
        }
    }
}

void MessageSequenceImpl::WriteFileDescriptor(int32_t fd)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    bool result = nativeParcel_->WriteFileDescriptor(fd);
    if (!result) {
        ZLOGE(LOG_LABEL, "write file descriptor failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

int32_t MessageSequenceImpl::ReadFileDescriptor()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    int32_t result = nativeParcel_->ReadFileDescriptor();
    if (result < 0) {
        ZLOGE(LOG_LABEL, "read file descriptor failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, 0);
    }
    return result;
}

void MessageSequenceImpl::WriteAshmem(::ohos::rpc::rpc::weak::Ashmem ashmem)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (!nativeParcel_->WriteAshmem(reinterpret_cast<OHOS::Ashmem *>(ashmem->GetNativePtr()))) {
        ZLOGE(LOG_LABEL, "write ashmem failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

::ohos::rpc::rpc::Ashmem MessageSequenceImpl::ReadAshmem()
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
        (taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>()));
    OHOS::sptr<OHOS::Ashmem> nativeAshmem = nativeParcel_->ReadAshmem();
    if (nativeAshmem == nullptr) {
        ZLOGE(LOG_LABEL, "nativeAshmem is null");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
            (taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>()));
    }
    return taihe::make_holder<AshmemImpl, ::ohos::rpc::rpc::Ashmem>(nativeAshmem);
}

void MessageSequenceImpl::WriteRawDataBuffer(::taihe::array_view<uint8_t> rawData, int32_t size)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    if (!nativeParcel_->WriteRawData(static_cast<const void*>(rawData.data()), size)) {
        ZLOGE(LOG_LABEL, "write raw data failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    }
}

::taihe::array<uint8_t> MessageSequenceImpl::ReadRawDataBuffer(int32_t size)
{
    CHECK_NATIVE_OBJECT_WITH_RETVAL(nativeParcel_,
        OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, ::taihe::array<uint8_t>(nullptr, 0));
    if (size <= 0) {
        ZLOGE(LOG_LABEL, "invalid param size:%{public}d", size);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR,
            (::taihe::array<uint8_t>(nullptr, 0)));
    }
    const void *rawData = nativeParcel_->ReadRawData(size);
    if (rawData == nullptr) {
        ZLOGE(LOG_LABEL, "rawData is null");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR,
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

void MessageSequenceImpl::CloseFileDescriptor(int32_t fd)
{
    if (fd < 0) {
        ZLOGE(LOG_LABEL, "invalid fd:%{public}d", fd);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::CHECK_PARAM_ERROR);
    }
    close(fd);
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

void MessageOptionImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::MessageOption obj)
{
    jsObjRef_ = std::optional<::ohos::rpc::rpc::MessageOption>(std::in_place, obj);
}

::ohos::rpc::rpc::MessageOption MessageOptionImpl::CreateMessageOption_WithTwoParam(int32_t syncFlags, int32_t waitTime)
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
TH_EXPORT_CPP_API_CreateRemoteProxyFromNative(OHOS::RemoteProxyImpl::CreateRemoteProxyFromNative);
TH_EXPORT_CPP_API_CreateMessageSequence(OHOS::MessageSequenceImpl::CreateMessageSequence);
TH_EXPORT_CPP_API_CloseFileDescriptor(OHOS::MessageSequenceImpl::CloseFileDescriptor);
TH_EXPORT_CPP_API_CreateMessageOption_WithTwoParam(OHOS::MessageOptionImpl::CreateMessageOption_WithTwoParam);
TH_EXPORT_CPP_API_CreateMessageOption_WithOneParam(OHOS::MessageOptionImpl::CreateMessageOption_WithOneParam);
TH_EXPORT_CPP_API_CreateMessageOption(OHOS::MessageOptionImpl::CreateMessageOption);
TH_EXPORT_CPP_API_CreateAshmem_WithTwoParam(OHOS::AshmemImpl::CreateAshmem_WithTwoParam);
TH_EXPORT_CPP_API_CreateAshmem_WithOneParam(OHOS::AshmemImpl::CreateAshmem_WithOneParam);
TH_EXPORT_CPP_API_GetCallingPid(OHOS::IPCSkeletonImpl::GetCallingPid);
TH_EXPORT_CPP_API_GetCallingUid(OHOS::IPCSkeletonImpl::GetCallingUid);
TH_EXPORT_CPP_API_GetCallingTokenId(OHOS::IPCSkeletonImpl::GetCallingTokenId);
TH_EXPORT_CPP_API_GetContextObject(OHOS::IPCSkeletonImpl::GetContextObject);
// NOLINTEND
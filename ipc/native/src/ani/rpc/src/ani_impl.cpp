/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);                     \
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
            RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR);                    \
        }                                                                                                             \
    } while (0)

#define CHECK_READ_POSITION_RETVAL(nativeParcel, retVal)                                                              \
    do {                                                                                                              \
        if ((nativeParcel)->GetDataSize() < (nativeParcel)->GetReadPosition()) {                                      \
            ZLOGE(LOG_LABEL, "invalid read position, GetDataSize:%{public}zu, GetReadPosition:%{public}zu",           \
                (nativeParcel)->GetDataSize(), (nativeParcel)->GetReadPosition());                                    \
            RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_DATA_FROM_MESSAGE_SEQUENCE_ERROR, retVal);\
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
    jsObjRef_.onRemoteDied();
    if (taihe::has_error()) {
        ZLOGE(LOG_LABEL, "call onRemoteDied failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CALL_JS_METHOD_ERROR);
    }
}

// ANIRemoteObject
ANIRemoteObject::ANIRemoteObject(const std::u16string &descriptor, ::ohos::rpc::rpc::weak::RemoteObject jsObj,
    bool hasCallingInfo) : OHOS::IPCObjectStub(descriptor), jsObjRef_(jsObj), hasCallingInfoAni_(hasCallingInfo)
{
}

ANIRemoteObject::~ANIRemoteObject()
{
}

::ohos::rpc::rpc::CallingInfo ANIRemoteObject::GetCallingInfo()
{
    bool isLocalCalling = IPCSkeleton::IsLocalCalling();
    if (isLocalCalling) {
        return {
            IPCSkeleton::GetCallingPid(),
            IPCSkeleton::GetCallingUid(),
            IPCSkeleton::GetCallingTokenID(),
            "",
            "",
            IPCSkeleton::IsLocalCalling()
        };
    }
    return {
        IPCSkeleton::GetCallingPid(),
        IPCSkeleton::GetCallingUid(),
        IPCSkeleton::GetCallingTokenID(),
        IPCSkeleton::GetCallingDeviceID(),
        IPCSkeleton::GetLocalDeviceID(),
        IPCSkeleton::IsLocalCalling()
    };
}

::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion ANIRemoteObject::callOnRemoteMessageRequest(int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data, ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options)
{
    if (hasCallingInfoAni_) {
        ::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion retWithCallingInfo =
            jsObjRef_.value()->OnRemoteMessageRequestWithCallingInfo(code, data, reply, options, GetCallingInfo());
        return retWithCallingInfo;
    } else {
        ::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion ret =
            jsObjRef_.value()->OnRemoteMessageRequest(code, data, reply, options);
        return ret;
    }
}

int ANIRemoteObject::OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
    OHOS::MessageOption &option)
{
    auto [asyncCallback, future] =
        ::taihe::make_async_pair<::taihe::expected<::ohos::rpc::rpc::RequestResult, ::taihe::error>>();
    auto jsData = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(&data);
    jsData->AddJsObjWeakRef(jsData);
    auto jsReply = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(&reply);
    jsReply->AddJsObjWeakRef(jsReply);
    auto jsOption = taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(option.GetFlags(),
        option.GetWaitTime());
    ::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion res =
        callOnRemoteMessageRequest(code, jsData, jsReply, jsOption);
    if (res.holds_booleanValue()) {
        bool boolRes = res.get_booleanValue_ref();
        return boolRes ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
    } else {
        res.get_promiseValue_ref().on_complete(
            [cb = std::move(asyncCallback), code, jsData = ::ohos::rpc::rpc::MessageSequence(jsData), jsReply =
            ::ohos::rpc::rpc::MessageSequence(jsReply)](::taihe::expected<bool, ::taihe::error> expectedBool) {
            if (expectedBool.has_value()) {
                int32_t retVal = expectedBool.value() ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
                ::ohos::rpc::rpc::RequestResult resRequestResult = { retVal, code, jsData, jsReply };
                cb.complete(resRequestResult);
            } else {
                cb.complete(::taihe::unexpected<taihe::error>(expectedBool.error()));
            }
        });
        return OHOS::ERR_NONE;
    }
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

void RemoteProxyImpl::RegisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags)
{
    std::lock_guard<std::mutex> lock(deathMutex_);
    OHOS::sptr<DeathRecipientImpl> nativeDeathRecipient = new (std::nothrow) DeathRecipientImpl(recipient);
    if (!cachedObject_->AddDeathRecipient(nativeDeathRecipient)) {
        ZLOGE(LOG_LABEL, "AddDeathRecipient failed");
        return;
    }

    deathRecipientMap_.emplace(const_cast<::ohos::rpc::rpc::DeathRecipient *>(&recipient), nativeDeathRecipient);
}

void RemoteProxyImpl::UnregisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags)
{
    std::lock_guard<std::mutex> lock(deathMutex_);
    auto it = deathRecipientMap_.find(const_cast<::ohos::rpc::rpc::DeathRecipient *>(&recipient));
    if (it != deathRecipientMap_.end()) {
        if (!cachedObject_->RemoveDeathRecipient(it->second)) {
            ZLOGE(LOG_LABEL, "RemoveDeathRecipient failed");
        }
        deathRecipientMap_.erase(const_cast<::ohos::rpc::rpc::DeathRecipient *>(&recipient));
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

int32_t RemoteProxyImpl::GetPingTransaction()
{
    return static_cast<int32_t>(PING_TRANSACTION);
}

int32_t RemoteProxyImpl::GetDumpTransaction()
{
    return static_cast<int32_t>(DUMP_TRANSACTION);
}

int32_t RemoteProxyImpl::GetInterfaceTransaction()
{
    return static_cast<int32_t>(INTERFACE_TRANSACTION);
}

int32_t RemoteProxyImpl::GetMinTransactionId()
{
    return static_cast<int32_t>(MIN_TRANSACTION_ID);
}

int32_t RemoteProxyImpl::GetMaxTransactionId()
{
    return static_cast<int32_t>(MAX_TRANSACTION_ID);
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
        close(dupFd);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_PARCEL_MEMORY_ALLOC_ERROR);
    }
    ashmem_ = newAshmem;
}

int64_t AshmemImpl::GetNativePtr()
{
    return reinterpret_cast<int64_t>(ashmem_.GetRefPtr());
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
    int32_t ashmemSize = GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() ||
        offset < 0 || offset > std::numeric_limits<int32_t>::max() ||
        (size + offset) > ashmemSize || ashmemSize < 0) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}d offset:%{public}d", size, offset);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_FROM_ASHMEM_ERROR,
            ::taihe::array<uint8_t>(nullptr, 0));
    }
    const void *rawData = ashmem_->ReadFromAshmem(size, offset);
    if (rawData == nullptr) {
        ZLOGE(LOG_LABEL, "rawData is null");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_READ_FROM_ASHMEM_ERROR,
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
    int32_t ashmemSize = GetAshmemSize();
    if (size <= 0 || size > std::numeric_limits<int32_t>::max() ||
        offset < 0 || offset > std::numeric_limits<int32_t>::max() ||
        (size + offset) > ashmemSize || ashmemSize < 0) {
        ZLOGE(LOG_LABEL, "invalid parameter, size:%{public}d offset:%{public}d", size, offset);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_TO_ASHMEM_ERROR);
        return;
    }
    if (!ashmem_->WriteToAshmem(static_cast<const void*>(buf.data()), size, offset)) {
        ZLOGE(LOG_LABEL, "write data failed");
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_WRITE_TO_ASHMEM_ERROR);
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

int32_t AshmemImpl::GetProtExec()
{
    return static_cast<int32_t>(PROT_EXEC);
}

int32_t AshmemImpl::GetProtNone()
{
    return static_cast<int32_t>(PROT_NONE);
}

int32_t AshmemImpl::GetProtRead()
{
    return static_cast<int32_t>(PROT_READ);
}

int32_t AshmemImpl::GetProtWrite()
{
    return static_cast<int32_t>(PROT_WRITE);
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
    auto desc = OHOS::Str16ToStr8(stub->GetObjectDescriptor());
    SetDescriptor(desc);
    std::lock_guard<std::mutex> lockGuard(mutex_);
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
    if (std::string(descriptor).size() >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "string length exceeds %{public}zu bytes", MAX_BYTES_LENGTH);
        RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR);
    }
    jsLocalInterface_ = localInterface;
    SetDescriptor(descriptor);
}

::ohos::rpc::rpc::IRemoteBroker RemoteObjectImpl::GetLocalInterface(::taihe::string_view descriptor)
{
    auto jsBroker = taihe::make_holder<IRemoteBrokerImpl, ::ohos::rpc::rpc::IRemoteBroker>();
    if (std::string(descriptor).size() >= MAX_BYTES_LENGTH) {
        ZLOGE(LOG_LABEL, "string length exceeds %{public}zu bytes", MAX_BYTES_LENGTH);
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_CHECK_PARAM_ERROR, jsBroker);
    }
    auto desc = GetDescriptor();
    if (descriptor != desc) {
        ZLOGE(LOG_LABEL, "descriptor: %{public}s mispatch, expected: %{public}s", descriptor.data(), desc.data());
        return jsBroker;
    }
    if (!jsLocalInterface_.has_value()) {
        ZLOGE(LOG_LABEL, "jsLocalInterface_ is empty!");
        return jsBroker;
    }
    return jsLocalInterface_.value();
}

::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion RemoteObjectImpl::callOnRemoteMessageRequest(int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data, ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options)
{
    if (hasCallingInfo_) {
        auto *aniObj = reinterpret_cast<OHOS::ANIRemoteObject *>(GetNativePtr());
        ::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion retWithCallingInfo =
            jsObjRef_.value()->OnRemoteMessageRequestWithCallingInfo(code, data, reply, options,
            aniObj->GetCallingInfo());
        return retWithCallingInfo;
    } else {
        ::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion ret =
            jsObjRef_.value()->OnRemoteMessageRequest(code, data, reply, options);
        return ret;
    }
}

::taihe::future<::taihe::expected<::ohos::rpc::rpc::RequestResult, ::taihe::error>>
    RemoteObjectImpl::SendMessageRequestPromise(int32_t code, ::ohos::rpc::rpc::weak::MessageSequence data,
    ::ohos::rpc::rpc::weak::MessageSequence reply, ::ohos::rpc::rpc::weak::MessageOption options)
{
    auto [asyncCallback, future] =
        ::taihe::make_async_pair<::taihe::expected<::ohos::rpc::rpc::RequestResult, ::taihe::error>>();
    ::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion res = callOnRemoteMessageRequest(code, data, reply, options);
    if (res.holds_booleanValue()) {
        bool boolRes = res.get_booleanValue_ref();
        int32_t retVal = boolRes ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
        ::ohos::rpc::rpc::RequestResult resRequestResult = { retVal, code, data, reply };
        asyncCallback.complete(resRequestResult);
        return std::move(future);
    } else {
        res.get_promiseValue_ref().on_complete(
            [cb = std::move(asyncCallback), code, data = ::ohos::rpc::rpc::MessageSequence(data),
            reply = ::ohos::rpc::rpc::MessageSequence(reply)](::taihe::expected<bool, ::taihe::error> expectedBool) {
            if (expectedBool.has_value()) {
                int32_t retVal = expectedBool.value() ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
                ::ohos::rpc::rpc::RequestResult resRequestResult = { retVal, code, data, reply };
                cb.complete(resRequestResult);
            } else {
                cb.complete(::taihe::unexpected<taihe::error>(expectedBool.error()));
            }
        });
        return std::move(future);
    }
}

void RemoteObjectImpl::SendMessageRequestAsync(int32_t code, ::ohos::rpc::rpc::weak::MessageSequence data,
    ::ohos::rpc::rpc::weak::MessageSequence reply, ::ohos::rpc::rpc::weak::MessageOption options,
    ::taihe::completer<::taihe::expected<::ohos::rpc::rpc::RequestResult, ::taihe::error>> asyncCallback)
{
    ::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion res = callOnRemoteMessageRequest(code, data, reply, options);
    if (res.holds_booleanValue()) {
        bool boolRes = res.get_booleanValue_ref();
        int32_t retVal = boolRes ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
        ::ohos::rpc::rpc::RequestResult resRequestResult = { retVal, code, data, reply };
        asyncCallback.complete(resRequestResult);
    } else {
        res.get_promiseValue_ref().on_complete(
            [cb = std::move(asyncCallback), code, data = ::ohos::rpc::rpc::MessageSequence(data),
            reply = ::ohos::rpc::rpc::MessageSequence(reply)](::taihe::expected<bool, ::taihe::error> expectedBool) {
            if (expectedBool.has_value()) {
                int32_t retVal = expectedBool.value() ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
                ::ohos::rpc::rpc::RequestResult resRequestResult = { retVal, code, data, reply };
                cb.complete(resRequestResult);
            } else {
                cb.complete(::taihe::unexpected<taihe::error>(expectedBool.error()));
            }
        });
    }
}

::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion RemoteObjectImpl::OnRemoteMessageRequestWithCallingInfo(
    int32_t code, ::ohos::rpc::rpc::weak::MessageSequence data, ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options, ::ohos::rpc::rpc::CallingInfo const& callingInfo)
{
    TH_THROW(std::runtime_error, "OnRemoteMessageRequestWithCallingInfo should be implemented in ets");
}

::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion RemoteObjectImpl::OnRemoteMessageRequest(int32_t code,
    ::ohos::rpc::rpc::weak::MessageSequence data, ::ohos::rpc::rpc::weak::MessageSequence reply,
    ::ohos::rpc::rpc::weak::MessageOption options)
{
    TH_THROW(std::runtime_error, "OnRemoteMessageRequest should be implemented in ets");
}

void RemoteObjectImpl::RegisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags)
{
    ZLOGE(LOG_LABEL, "only RemoteProxy needed");
    RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_ONLY_PROXY_OBJECT_PERMITTED_ERROR);
}

void RemoteObjectImpl::UnregisterDeathRecipient(::ohos::rpc::rpc::DeathRecipient const& recipient, int32_t flags)
{
    ZLOGE(LOG_LABEL, "only RemoteProxy needed");
    RPC_TAIHE_ERROR(OHOS::RpcTaiheErrorCode::TAIHE_ONLY_PROXY_OBJECT_PERMITTED_ERROR);
}

::taihe::string RemoteObjectImpl::GetDescriptor()
{
    std::lock_guard<std::mutex> lockGuard(descMutex_);
    return desc_;
}

void RemoteObjectImpl::SetDescriptor(::taihe::string desc)
{
    std::lock_guard<std::mutex> lockGuard(descMutex_);
    desc_ = desc;
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
        auto desc = GetDescriptor();
        std::u16string descStr16(desc.begin(), desc.end());
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
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return reinterpret_cast<int64_t>(sptrCachedObject_ != nullptr ?
        sptrCachedObject_.GetRefPtr() : wptrCachedObject_.GetRefPtr());
}

void RemoteObjectImpl::AddJsObjWeakRef(::ohos::rpc::rpc::weak::RemoteObject obj, bool isNative, bool hasCallingInfo)
{
    hasCallingInfo_ = hasCallingInfo;
    jsObjRef_ = std::optional<::ohos::rpc::rpc::RemoteObject>(std::in_place, obj);
    if (!jsObjRef_.has_value()) {
        ZLOGE(LOG_LABEL, "jsObjRef_ is empty");
        return;
    }
    auto desc = GetDescriptor();
    std::u16string descStr16(desc.begin(), desc.end());
    ANIRemoteObject *newObject = new (std::nothrow) ANIRemoteObject(descStr16, jsObjRef_.value(), hasCallingInfo);
    if (newObject == nullptr) {
        ZLOGE(LOG_LABEL, "new ANIRemoteObject failed");
        return;
    }
    std::lock_guard<std::mutex> lockGuard(mutex_);
    if (!isNative) {
        wptrCachedObject_ = newObject;
    } else {
        sptrCachedObject_ = newObject;
    }
}

void MessageSequenceImpl::WriteFloatArray(::taihe::array_view<double> floatArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = floatArray.size();
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
    size_t pos = nativeParcel_->GetWritePosition();
    nativeParcel_->WriteUint32(arrayLength);
    bool result = false;
    for (size_t i = 0; i < arrayLength; i++) {
        if (stringArray[i].size() >= MAX_BYTES_LENGTH) {
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
        return ::taihe::array<int32_t>(nullptr, 0);
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
        return ::taihe::array<double>(nullptr, 0);
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
        return ::taihe::array<bool>(nullptr, 0);
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
        return ::taihe::array<::taihe::string>(nullptr, 0);
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
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<int32_t>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(uint8_t),
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
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
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<double>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(double),
        nativeParcel_, (::taihe::array<double>(nullptr, 0)));
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
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<int64_t>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(long),
        nativeParcel_, (::taihe::array<int64_t>(nullptr, 0)));
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
    if (arrayLength <= 0) {
        ZLOGE(LOG_LABEL, "arrayLength:%{public}d <= 0", arrayLength);
        return ::taihe::array<int32_t>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(int32_t),
        nativeParcel_, (::taihe::array<int32_t>(nullptr, 0)));
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
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateRemoteObject(OHOS::RemoteObjectImpl::CreateRemoteObject);
TH_EXPORT_CPP_API_CreateRemoteObjectFromNative(OHOS::RemoteObjectImpl::CreateRemoteObjectFromNative);
TH_EXPORT_CPP_API_CreateRemoteProxyFromNative(OHOS::RemoteProxyImpl::CreateRemoteProxyFromNative);
TH_EXPORT_CPP_API_GetPingTransaction(OHOS::RemoteProxyImpl::GetPingTransaction);
TH_EXPORT_CPP_API_GetDumpTransaction(OHOS::RemoteProxyImpl::GetDumpTransaction);
TH_EXPORT_CPP_API_GetInterfaceTransaction(OHOS::RemoteProxyImpl::GetInterfaceTransaction);
TH_EXPORT_CPP_API_GetMinTransactionId(OHOS::RemoteProxyImpl::GetMinTransactionId);
TH_EXPORT_CPP_API_GetMaxTransactionId(OHOS::RemoteProxyImpl::GetMaxTransactionId);
TH_EXPORT_CPP_API_CreateMessageSequence(OHOS::MessageSequenceImpl::CreateMessageSequence);
TH_EXPORT_CPP_API_CloseFileDescriptor(OHOS::MessageSequenceImpl::CloseFileDescriptor);
TH_EXPORT_CPP_API_RpcTransferStaicImpl(OHOS::MessageSequenceImpl::RpcTransferStaicImpl);
TH_EXPORT_CPP_API_RpcTransferDynamicImpl(OHOS::MessageSequenceImpl::RpcTransferDynamicImpl);
TH_EXPORT_CPP_API_CreateMessageOption_WithTwoParam(OHOS::MessageOptionImpl::CreateMessageOption_WithTwoParam);
TH_EXPORT_CPP_API_CreateMessageOption_WithOneParam(OHOS::MessageOptionImpl::CreateMessageOption_WithOneParam);
TH_EXPORT_CPP_API_CreateMessageOption_WithOneIntParam(OHOS::MessageOptionImpl::CreateMessageOption_WithOneIntParam);
TH_EXPORT_CPP_API_DupFileDescriptor(OHOS::MessageSequenceImpl::DupFileDescriptor);
TH_EXPORT_CPP_API_CreateMessageOption(OHOS::MessageOptionImpl::CreateMessageOption);
TH_EXPORT_CPP_API_GetTfSync(OHOS::MessageOptionImpl::GetTfSync);
TH_EXPORT_CPP_API_GetTfAsync(OHOS::MessageOptionImpl::GetTfAsync);
TH_EXPORT_CPP_API_GetTfAcceptFds(OHOS::MessageOptionImpl::GetTfAcceptFds);
TH_EXPORT_CPP_API_GetTfWaitTime(OHOS::MessageOptionImpl::GetTfWaitTime);
TH_EXPORT_CPP_API_CreateAshmem_WithTwoParam(OHOS::AshmemImpl::CreateAshmem_WithTwoParam);
TH_EXPORT_CPP_API_CreateAshmem_WithOneParam(OHOS::AshmemImpl::CreateAshmem_WithOneParam);
TH_EXPORT_CPP_API_GetProtExec(OHOS::AshmemImpl::GetProtExec);
TH_EXPORT_CPP_API_GetProtNone(OHOS::AshmemImpl::GetProtNone);
TH_EXPORT_CPP_API_GetProtRead(OHOS::AshmemImpl::GetProtRead);
TH_EXPORT_CPP_API_GetProtWrite(OHOS::AshmemImpl::GetProtWrite);
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

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

void MessageSequenceImpl::WriteShortArray(::taihe::array_view<int32_t> shortArray)
{
    CHECK_NATIVE_OBJECT(nativeParcel_, OHOS::RpcTaiheErrorCode::TAIHE_WRITE_DATA_TO_MESSAGE_SEQUENCE_ERROR);
    uint32_t arrayLength = shortArray.size();
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
    int32_t dupResult = dup(fd);
    if (dupResult < 0) {
        ZLOGE(LOG_LABEL, "os dup function failed");
        RPC_TAIHE_ERROR_WITH_RETVAL(OHOS::RpcTaiheErrorCode::TAIHE_OS_DUP_ERROR, -1);
    }
    return dupResult;
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
    size_t byteLength = buf.size();
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
    size_t byteLength = int8Vector.size();

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
    size_t byteLength = int16Vector.size() * BYTE_SIZE_16;
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
    size_t byteLength = uint16Vector.size() * BYTE_SIZE_16;
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
    size_t byteLength = int32Vector.size() * BYTE_SIZE_32;
    std::vector<uint8_t> ret;
    ret = BufferToVector<uint8_t>(vec, byteLength);
    return ::taihe::array<uint8_t>(ret);
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
        return ::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0);
    }
    CHECK_READ_LENGTH_RETVAL(static_cast<size_t>(arrayLength), sizeof(int32_t),
        nativeParcel_, (::taihe::array<::ohos::rpc::rpc::IRemoteObjectUnion>(nullptr, 0)));
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
}  // namespace
// NOLINTEND

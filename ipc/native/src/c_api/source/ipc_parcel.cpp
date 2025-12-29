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

 #include "ipc_cparcel.h"

 #include <securec.h>
 
 #include "ipc_debug.h"
 #include "ipc_error_code.h"
 #include "ipc_inner_object.h"
 #include "ipc_internal_utils.h"
 #include "log_tags.h"
 #include "message_parcel.h"
 
 static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, OHOS::LOG_ID_IPC_CAPI, "OHIPCParcel" };
 
 OHIPCParcel* OH_IPCParcel_Create(void)
 {
     OHOS::MessageParcel *msgParcel = new (std::nothrow) OHOS::MessageParcel();
     if (msgParcel == nullptr) {
         ZLOGE(LOG_LABEL, "message parcel is null!");
         return nullptr;
     }
     OHIPCParcel *parcel = new (std::nothrow) OHIPCParcel();
     if (parcel == nullptr) {
         ZLOGE(LOG_LABEL, "ipc parcel is null!");
         delete msgParcel;
         return nullptr;
     }
     parcel->msgParcel = msgParcel;
     return parcel;
 }
 
 void OH_IPCParcel_Destroy(OHIPCParcel *parcel)
 {
     if (parcel != nullptr) {
         if (parcel->msgParcel != nullptr) {
             delete parcel->msgParcel;
             parcel->msgParcel = nullptr;
         }
         delete parcel;
     }
 }
 
 template <typename T, typename U>
 static int SetParcelProperty(OHIPCParcel *parcel, T value, bool (OHOS::MessageParcel::*SetProperty)(U value))
 {
     if (!IsIPCParcelValid(parcel, __func__)) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
     return (parcel->msgParcel->*SetProperty)(static_cast<U>(value)) ? OH_IPC_SUCCESS : OH_IPC_INNER_ERROR;
 }
 
 template <typename T, typename U>
 static T GetParcelPropertyConst(const OHIPCParcel *parcel, U (OHOS::MessageParcel::*GetProperty)() const)
 {
     if (!IsIPCParcelValid(parcel, __func__)) {
         return -1;
     }
     return static_cast<T>((parcel->msgParcel->*GetProperty)());
 }
 
 template <typename T, typename U>
 static T GetParcelProperty(const OHIPCParcel *parcel, U (OHOS::MessageParcel::*GetProperty)())
 {
     if (!IsIPCParcelValid(parcel, __func__)) {
         return -1;
     }
     return static_cast<T>((parcel->msgParcel->*GetProperty)());
 }
 
 int OH_IPCParcel_GetDataSize(const OHIPCParcel *parcel)
 {
     return GetParcelPropertyConst<int, size_t>(parcel, &OHOS::MessageParcel::GetDataSize);
 }
 
 int OH_IPCParcel_GetWritableBytes(const OHIPCParcel *parcel)
 {
     return GetParcelPropertyConst<int, size_t>(parcel, &OHOS::MessageParcel::GetWritableBytes);
 }
 
 int OH_IPCParcel_GetReadableBytes(const OHIPCParcel *parcel)
 {
     return GetParcelPropertyConst<int, size_t>(parcel, &OHOS::MessageParcel::GetReadableBytes);
 }
 
 int OH_IPCParcel_GetReadPosition(const OHIPCParcel *parcel)
 {
     return GetParcelProperty<int, size_t>(parcel, &OHOS::MessageParcel::GetReadPosition);
 }
 
 int OH_IPCParcel_GetWritePosition(const OHIPCParcel *parcel)
 {
     return GetParcelProperty<int, size_t>(parcel, &OHOS::MessageParcel::GetWritePosition);
 }
 
 int OH_IPCParcel_RewindReadPosition(OHIPCParcel *parcel, uint32_t newReadPos)
 {
     return SetParcelProperty<uint32_t, size_t>(parcel, newReadPos, &OHOS::MessageParcel::RewindRead);
 }
 
 int OH_IPCParcel_RewindWritePosition(OHIPCParcel *parcel, uint32_t newWritePos)
 {
     return SetParcelProperty<uint32_t, size_t>(parcel, newWritePos, &OHOS::MessageParcel::RewindWrite);
 }
 
 template <typename T>
 static int WriteValue(OHIPCParcel *parcel, T value, bool (OHOS::MessageParcel::*Write)(T value))
 {
     if (!IsIPCParcelValid(parcel, __func__)) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
     return (parcel->msgParcel->*Write)(value) ? OH_IPC_SUCCESS : OH_IPC_PARCEL_WRITE_ERROR;
 }
 
 template <typename T>
 static int ReadValue(const OHIPCParcel *parcel, T *value, bool (OHOS::MessageParcel::*Read)(T &value))
 {
     if (!IsIPCParcelValid(parcel, __func__) || value == nullptr) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
 
     return (parcel->msgParcel->*Read)(*value) ? OH_IPC_SUCCESS : OH_IPC_PARCEL_READ_ERROR;
 }
 
 int OH_IPCParcel_WriteInt8(OHIPCParcel *parcel, int8_t value)
 {
     return WriteValue<int8_t>(parcel, value, &OHOS::MessageParcel::WriteInt8);
 }
 
 int OH_IPCParcel_ReadInt8(const OHIPCParcel *parcel, int8_t *value)
 {
     return ReadValue<int8_t>(parcel, value, &OHOS::MessageParcel::ReadInt8);
 }
 
 int OH_IPCParcel_WriteInt16(OHIPCParcel *parcel, int16_t value)
 {
     return WriteValue<int16_t>(parcel, value, &OHOS::MessageParcel::WriteInt16);
 }
 
 int OH_IPCParcel_ReadInt16(const OHIPCParcel *parcel, int16_t *value)
 {
     return ReadValue<int16_t>(parcel, value, &OHOS::MessageParcel::ReadInt16);
 }
 
 int OH_IPCParcel_WriteInt32(OHIPCParcel *parcel, int32_t value)
 {
     return WriteValue<int32_t>(parcel, value, &OHOS::MessageParcel::WriteInt32);
 }
 
 int OH_IPCParcel_ReadInt32(const OHIPCParcel *parcel, int32_t *value)
 {
     return ReadValue<int32_t>(parcel, value, &OHOS::MessageParcel::ReadInt32);
 }
 
 int OH_IPCParcel_WriteInt64(OHIPCParcel *parcel, int64_t value)
 {
     return WriteValue<int64_t>(parcel, value, &OHOS::MessageParcel::WriteInt64);
 }
 
 int OH_IPCParcel_ReadInt64(const OHIPCParcel *parcel, int64_t *value)
 {
     return ReadValue<int64_t>(parcel, value, &OHOS::MessageParcel::ReadInt64);
 }
 
 int OH_IPCParcel_WriteFloat(OHIPCParcel *parcel, float value)
 {
     return WriteValue<float>(parcel, value, &OHOS::MessageParcel::WriteFloat);
 }
 
 int OH_IPCParcel_ReadFloat(const OHIPCParcel *parcel, float *value)
 {
     return ReadValue<float>(parcel, value, &OHOS::MessageParcel::ReadFloat);
 }
 
 int OH_IPCParcel_WriteDouble(OHIPCParcel *parcel, double value)
 {
     return WriteValue<double>(parcel, value, &OHOS::MessageParcel::WriteDouble);
 }
 
 int OH_IPCParcel_ReadDouble(const OHIPCParcel *parcel, double *value)
 {
     return ReadValue<double>(parcel, value, &OHOS::MessageParcel::ReadDouble);
 }
 
 int OH_IPCParcel_WriteString(OHIPCParcel *parcel, const char *str)
 {
     if (!IsIPCParcelValid(parcel, __func__) || str == nullptr) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
 
     return parcel->msgParcel->WriteCString(str) ? OH_IPC_SUCCESS : OH_IPC_PARCEL_WRITE_ERROR;
 }
 
 const char* OH_IPCParcel_ReadString(const OHIPCParcel *parcel)
 {
     if (!IsIPCParcelValid(parcel, __func__)) {
         return nullptr;
     }
 
     return parcel->msgParcel->ReadCString();
 }
 
 int OH_IPCParcel_WriteBuffer(OHIPCParcel *parcel, const uint8_t *buffer, int32_t len)
 {
     if (!IsIPCParcelValid(parcel, __func__) || buffer == nullptr || len <= 0) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
 
     size_t writePosition = parcel->msgParcel->GetWritePosition();
     if (!parcel->msgParcel->WriteBuffer(buffer, len)) {
         ZLOGE(LOG_LABEL, "write buffer failed! buffer len:%{public}d", len);
         parcel->msgParcel->RewindWrite(writePosition);
         return OH_IPC_PARCEL_WRITE_ERROR;
     }
     return OH_IPC_SUCCESS;
 }
 
 const uint8_t* OH_IPCParcel_ReadBuffer(const OHIPCParcel *parcel, int32_t len)
 {
     if (!IsIPCParcelValid(parcel, __func__)) {
         return nullptr;
     }
     int readableBytes = static_cast<int>(parcel->msgParcel->GetReadableBytes());
     if (len <= 0 || len > readableBytes) {
         ZLOGE(LOG_LABEL, "read buf len:%{public}d invalid! ReadableBytes:%{public}d", len, readableBytes);
         return nullptr;
     }
 
     return parcel->msgParcel->ReadBuffer(len);
 }
 
 template <typename T>
 static int WriteIPCRemoteObject(OHIPCParcel *parcel, const T *object)
 {
     if (!IsIPCParcelValid(parcel, __func__) || object == nullptr) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
     if (!parcel->msgParcel->WriteRemoteObject(object->remote)) {
         ZLOGE(LOG_LABEL, "write remote object failed!");
         return OH_IPC_PARCEL_WRITE_ERROR;
     }
     return OH_IPC_SUCCESS;
 }
 
 template <typename T>
 static T* ReadIPCRemoteObject(const OHIPCParcel *parcel)
 {
     if (!IsIPCParcelValid(parcel, __func__)) {
         return nullptr;
     }
     OHOS::sptr<OHOS::IRemoteObject> object = parcel->msgParcel->ReadRemoteObject();
     if (object == nullptr) {
         ZLOGE(LOG_LABEL, "read remote object failed!");
         return nullptr;
     }
     T *remoteObject = new (std::nothrow) T();
     if (remoteObject == nullptr) {
         ZLOGE(LOG_LABEL, "new remote object failed");
         return nullptr;
     }
     remoteObject->remote = object;
     return remoteObject;
 }
 
 int OH_IPCParcel_WriteRemoteStub(OHIPCParcel *parcel, const OHIPCRemoteStub *stub)
 {
     return WriteIPCRemoteObject(parcel, stub);
 }
 
 OHIPCRemoteStub* OH_IPCParcel_ReadRemoteStub(const OHIPCParcel *parcel)
 {
     return ReadIPCRemoteObject<OHIPCRemoteStub>(parcel);
 }
 
 int OH_IPCParcel_WriteRemoteProxy(OHIPCParcel *parcel, const OHIPCRemoteProxy *proxy)
 {
     return WriteIPCRemoteObject(parcel, proxy);
 }
 
 OHIPCRemoteProxy* OH_IPCParcel_ReadRemoteProxy(const OHIPCParcel *parcel)
 {
     return ReadIPCRemoteObject<OHIPCRemoteProxy>(parcel);
 }
 
 int OH_IPCParcel_WriteFileDescriptor(OHIPCParcel *parcel, int32_t fd)
 {
     return WriteValue<int32_t>(parcel, fd, &OHOS::MessageParcel::WriteFileDescriptor);
 }
 
 int OH_IPCParcel_ReadFileDescriptor(const OHIPCParcel *parcel, int32_t *fd)
 {
     if (!IsIPCParcelValid(parcel, __func__) || fd == nullptr) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
 
     int tmpFd = parcel->msgParcel->ReadFileDescriptor();
     if (tmpFd == -1) {
         ZLOGE(LOG_LABEL, "read file descriptor failed!");
         return OH_IPC_PARCEL_READ_ERROR;
     }
     *fd = tmpFd;
     return OH_IPC_SUCCESS;
 }
 
 int OH_IPCParcel_Append(OHIPCParcel *parcel, const OHIPCParcel *data)
 {
     if (!IsIPCParcelValid(parcel, __func__) || !IsIPCParcelValid(data, __func__)) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
     return parcel->msgParcel->Append(*(data->msgParcel)) ? OH_IPC_SUCCESS : OH_IPC_PARCEL_WRITE_ERROR;
 }
 
 int OH_IPCParcel_WriteInterfaceToken(OHIPCParcel *parcel, const char *token)
 {
     if (!IsIPCParcelValid(parcel, __func__) || token == nullptr) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
 
     int tokenLen = strlen(token);
     if (tokenLen == 0 || tokenLen > MAX_PARCEL_LEN) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
     std::u16string u16Token = OHOS::Str8ToStr16(std::string(token, tokenLen));
     if (u16Token.length() == 0 && tokenLen != 0) {
         ZLOGE(LOG_LABEL, "convert token to u16string failed: %{public}d", tokenLen);
         return OH_IPC_PARCEL_WRITE_ERROR;
     }
     size_t writePosition = parcel->msgParcel->GetWritePosition();
     if (!parcel->msgParcel->WriteInterfaceToken(u16Token)) {
         ZLOGE(LOG_LABEL, "WriteInterfaceToken failed! token len:%{public}d", tokenLen);
         parcel->msgParcel->RewindWrite(writePosition);
         return OH_IPC_PARCEL_WRITE_ERROR;
     }
     return OH_IPC_SUCCESS;
 }
 
 int OH_IPCParcel_ReadInterfaceToken(const OHIPCParcel *parcel, char **token, int32_t *len,
     OH_IPC_MemAllocator allocator)
 {
     if (!IsIPCParcelValid(parcel, __func__) || !IsMemoryParamsValid(token, len, allocator, __func__)) {
         return OH_IPC_CHECK_PARAM_ERROR;
     }
     size_t readPosition = parcel->msgParcel->GetReadPosition();
     std::u16string u16Token = parcel->msgParcel->ReadInterfaceToken();
     std::string strToken = OHOS::Str16ToStr8(u16Token);
     if (u16Token.length() != 0 && strToken.length() == 0) {
         parcel->msgParcel->RewindRead(readPosition);
         ZLOGE(LOG_LABEL, "Str16ToStr8 failed! u16Token len: %{public}u, string len: %{public}u",
             static_cast<uint32_t>(u16Token.length()), static_cast<uint32_t>(strToken.length()));
         return OH_IPC_PARCEL_READ_ERROR;
     }
 
     int memLength = static_cast<int>(strToken.length()) + 1;
     *token = static_cast<char *>(allocator(memLength));
     if (*token == nullptr) {
         parcel->msgParcel->RewindRead(readPosition);
         ZLOGE(LOG_LABEL, "memory allocator failed!");
         return OH_IPC_MEM_ALLOCATOR_ERROR;
     }
     if (memcpy_s(*token, memLength, strToken.c_str(), memLength) != EOK) {
         parcel->msgParcel->RewindRead(readPosition);
         ZLOGE(LOG_LABEL, "memcpy string failed, string len: %{public}d", memLength);
         return OH_IPC_PARCEL_READ_ERROR;
     }
     *len = memLength;
     return OH_IPC_SUCCESS;
 }

IPCObjectProxy::IPCObjectProxy(int handle, std::u16string descriptor, int proto)
    : IRemoteObject(std::move(descriptor)), handle_(handle), proto_(proto), isFinishInit_(false), isRemoteDead_(false)
{
    ZLOGD(LABEL, "handle:%{public}u desc:%{public}s %{public}u", handle_,
        Str16ToStr8(descriptor_).c_str(), ProcessSkeleton::ConvertAddr(this));
    ExtendObjectLifetime();
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LABEL, "ProcessSkeleton is null");
        return;
    }
    current->AttachValidObject(this, descriptor_);
}

// LCOV_EXCL_START
IPCObjectProxy::~IPCObjectProxy()
{
#ifdef ENABLE_IPC_TRACE
    if (isTraceEnabled_) {
        IPCTrace::FinishAsync(GenLifeCycleTraceInfo(), static_cast<int32_t>(ProcessSkeleton::ConvertAddr(this)));
    }
#endif
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        ZLOGD(LABEL, "handle:%{public}u desc:%{public}s %{public}u", handle_,
            remoteDescriptor_.c_str(), ProcessSkeleton::ConvertAddr(this));
        desc = remoteDescriptor_;
    }
    auto pos = desc.find("IVpnStateCallback");
    if (pos != std::string::npos) {
        ZLOGI(LABEL, "handle:%{public}u desc:%{public}s %{public}u", handle_,
            desc.c_str(), ProcessSkeleton::ConvertAddr(this));
    }
    ProcessSkeleton *current = ProcessSkeleton::GetInstance();
    if (current == nullptr) {
        ZLOGE(LABEL, "ProcessSkeleton is null");
        return;
    }
    current->DetachValidObject(this);
    // for map clean
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (!recipients_.empty()) {
            recipients_.clear();
        }
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t IPCObjectProxy::GetObjectRefCount()
{
    MessageParcel data, reply;
    MessageOption option;
    int err = SendRequestInner(false, SYNCHRONIZE_REFERENCE, data, reply, option);
    if (err == ERR_NONE) {
        return reply.ReadInt32();
    }
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, remoteDescriptor_, ProcessSkeleton::ConvertAddr(this));
    }
    return 0;
}
// LCOV_EXCL_STOP

int IPCObjectProxy::Dump(int fd, const std::vector<std::u16string> &args)
{
    MessageParcel data, reply;
    MessageOption option{ MessageOption::TF_SYNC };
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    return SendRequestInner(false, DUMP_TRANSACTION, data, reply, option);
}

std::string IPCObjectProxy::GetDescriptor(MessageParcel &data)
{
    std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
    if (remoteDescriptor_.empty()) {
#ifdef ENABLE_IPC_TRACE
        fullRemoteDescriptor_ = Str16ToStr8(data.GetInterfaceToken());
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(fullRemoteDescriptor_);
        StartLifeCycleTrace();
#else
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(data.GetInterfaceToken()));
#endif
    }
    return remoteDescriptor_;
}

void IPCObjectProxy::PrintErrorDetailedInfo(int err, const std::string &desc)
{
#ifndef __linux__
    uint32_t errorCode;
    std::string errorDesc;
    if (err == BR_FAILED_REPLY) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is null");
            return;
        }
        bool isInvokerSuccess = invoker->GetDetailedErrorInfo(errorCode, errorDesc);
        if (isInvokerSuccess) {
            std::string newDesc = "(subErr:" + std::to_string(errCode) + " SubErrDesc:" + errorDesc + ") " + desc;
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, newDesc, ProcessSkeleton::ConvertAddr(this));
        } else {
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        }
    }
#else
    PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
#endif
}

int IPCObjectProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != DUMP_TRANSACTION && code > MAX_TRANSACTION_ID) {
        return IPC_PROXY_INVALID_CODE_ERR;
    }
    std::string desc = GetDescriptor(data);
#ifdef ENABLE_IPC_TRACE
    bool isTraceEnable = IPCTrace::IsEnabled();
    if (isTraceEnable) {
        IPCTrace::Start(GenSendRequestTraceInfo(code));
    }
#endif
    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
#ifdef ENABLE_IPC_TRACE
    if (isTraceEnable) {
        IPCTrace::Finish();
    }
#endif
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGW(LABEL, "DFX_BlockMonitor cost %{public}lld ms, code:%{public}u, desc:%{public}s", timeInterval,
            code, desc.c_str());
    }
    return err;
}

int IPCObjectProxy::SendLocalRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return SendRequestInner(true, code, data, reply, option);
}

int IPCObjectProxy::SendRequestInner(bool isLocal, uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (IsObjectDead()) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        ZLOGD(LABEL, "proxy is already dead, handle:%{public}d desc:%{public}s", handle_, remoteDescriptor_.c_str());
        return ERR_DEAD_OBJECT;
    }

    IRemoteInvoker *invoker = nullptr;
    if (isLocal) {
        invoker = IPCThreadSkeleton::GetDefaultInvoker();
    } else {
        invoker = IPCThreadSkeleton::GetRemoteInvoker(proto_);
    }
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null, handle:%{public}u proto:%{public}d", handle_, proto_);
        return ERR_NULL_OBJECT;
    }

    IPCThreadSkeleton::UpdateSendRequestCount(1);
    int status = invoker->SendRequest(handle_, code, data, reply, option);
    if (status == ERR_DEAD_OBJECT || status == BR_DEAD_REPLY) {
        SetObjectDied(true);
    }
    IPCThreadSkeleton::UpdateSendRequestCount(-1);

    std::string desc = GetDescriptor(data);
    if (status != ERR_NONE && ProcessSkeleton::IsPrint(status, lastErr_, lastErrCnt_)) {
        PrintErrorDetailedInfo(status, desc);
#ifdef ENABLE_IPC_PROXY_DFX_BACKTRACE
        if (status == BR_FAILED_REPLY) {
            std::string backtrace;
            if (!GetBacktrace(backtrace, false)) {
                ZLOGE(LABEL, "GetBacktrace fail");
            } else {
                ZLOGW(LABEL, "backtrace info:\n%{public}s", backtrace.c_str());
            }
        }
#endif
    }
    return status;
}

// LCOV_EXCL_START
std::u16string IPCObjectProxy::GetInterfaceDescriptor()
{
    if (!interfaceDesc_.empty()) {
        return interfaceDesc_;
    }
    if (handle_ == 0) {
        ZLOGD(LABEL, "handle == 0, do nothing");
        return std::u16string();
    }

    MessageParcel data, reply;
    MessageOption option;
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = remoteDescriptor_;
    }

    int err = SendRequestInner(false, INTERFACE_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        return std::u16string();
    }
    interfaceDesc_ = reply.ReadString16();

    return interfaceDesc_;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
std::string IPCObjectProxy::GetSessionName()
{
    MessageParcel data, reply;
    MessageOption option;

    int err = SendRequestInner(false, GET_SESSION_NAME, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, remoteDescriptor_, ProcessSkeleton::ConvertAddr(this));
        return std::string("");
    }
    return reply.ReadString();
}
// LCOV_EXCL_STOP

std::string IPCObjectProxy::GetGrantedSessionName()
{
    MessageParcel data, reply;
    MessageOption option;

    int err = SendRequestInner(false, GET_GRANTED_SESSION_NAME, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, remoteDescriptor_, ProcessSkeleton::ConvertAddr(this));
        return std::string("");
    }

    if (reply.ReadUint32() != IRemoteObject::IF_PROT_DATABUS) {
        ZLOGE(LABEL, "GetDataBusName normal binder");
        return std::string("");
    }

    return reply.ReadString();
}

std::string IPCObjectProxy::GetSessionNameForPidUid(uint32_t uid, uint32_t pid)
{
    if (pid == static_cast<uint32_t>(getpid())) {
        ZLOGE(LABEL, "TransDataBusName can't write local pid. my/remotePid:%{public}u/%{public}u", getpid(), pid);
        return std::string("");
    }

    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteUint32(pid) || !data.WriteUint32(uid)) {
        ZLOGE(LABEL, "TransDataBusName write pid/uid:%{public}u/%{public}u failed", pid, uid);
        return std::string("");
    }
    int err = SendRequestInner(false, GET_SESSION_NAME_PID_UID, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, remoteDescriptor_, ProcessSkeleton::ConvertAddr(this));
        return std::string("");
    }

    if (reply.ReadUint32() != IRemoteObject::IF_PROT_DATABUS) {
        ZLOGE(LABEL, "TransDataBusName normal binder");
        return std::string("");
    }

    return reply.ReadString();
}

int IPCObjectProxy::RemoveSessionName(const std::string &sessionName)
{
    MessageParcel data, reply;
    MessageOption option{ MessageOption::TF_ASYNC };
    if (!data.WriteString(sessionName)) {
        ZLOGE(LABEL, "write parcel fail, sessionName:%{public}s", sessionName.c_str());
        return IPC_PROXY_WRITE_PARCEL_ERR;
    }
    int err = SendRequestInner(false, REMOVE_SESSION_NAME, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, remoteDescriptor_, ProcessSkeleton::ConvertAddr(this));
    }
    return err;
}

void IPCObjectProxy::OnFirstStrongRef(const void *objectId)
{
    // IPC proxy: AcquireHandle->AttachObject
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        invoker->AcquireHandle(handle_);
    }
}

void IPCObjectProxy::WaitForInit(const void *dbinderData)
{
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = remoteDescriptor_;
    }
    // RPC proxy: AcquireHandle->AttachObject->Open Session->IncRef to Remote Stub
    {
        std::lock_guard<std::mutex> lockGuard(initMutex_);
        // When remote stub is gone, handle is reclaimed. But mapping from this handle to
        // proxy may still exist before OnLastStrongRef called. If so, in FindOrNewObject
        // we may find the same proxy that has been marked as dead. Thus, we need to check again.
        if (IsObjectDead()) {
            ZLOGW(LABEL, "proxy is dead, init again, handle:%{public}d desc:%{public}s", handle_, desc.c_str());
            SetObjectDied(false);
            isFinishInit_ = false;
        }

        if (!isFinishInit_) {
#ifndef CONFIG_IPC_SINGLE
            if (!UpdateProto(dbinderData)) {
                return;
            }
#endif
            isFinishInit_ = true;
        } else {
#ifndef CONFIG_IPC_SINGLE
            // Anoymous rpc proxy need to update proto anyway because ownership of session
            // corresponding to this handle has been marked as null in TranslateRemoteHandleType
            if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
                if (!CheckHaveSession()) {
                    SetProto(IRemoteObject::IF_PROT_ERROR);
                    SetObjectDied(true);
                }
            }
#endif
        }
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS) {
        if (IncRefToRemote() != ERR_NONE) {
            SetProto(IRemoteObject::IF_PROT_ERROR);
            SetObjectDied(true);
        }
    }
#endif
}

void IPCObjectProxy::OnLastStrongRef(const void *objectId)
{
    // IPC proxy: DetachObject->ReleaseHandle
    // RPC proxy: DecRef to Remote Stub->Close Session->DetachObject->ReleaseHandle
    ZLOGD(LABEL, "handle:%{public}u proto:%{public}d", handle_, proto_);
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "skeleton is null");
        return;
    }
#ifndef CONFIG_IPC_SINGLE
    ReleaseProto();
#endif
    ClearDeathRecipients();
    // This proxy is going to be destroyed, so we need to decrease refcount of binder_ref.
    // It may has been replace with a new proxy, thus we have no need to check result.
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        if (handle_ == IPCProcessSkeleton::INVALID_HANDLE_VALUE) {
            ZLOGW(LABEL, "handle has been released, desc:%{public}s %{public}u",
                remoteDescriptor_.c_str(), ProcessSkeleton::ConvertAddr(this));
        } else {
            invoker->ReleaseHandle(handle_);
            handle_ = IPCProcessSkeleton::INVALID_HANDLE_VALUE;
        }
    }
    current->DetachObject(this);
}

void IPCObjectProxy::SetObjectDied(bool isDied)
{
    isRemoteDead_.store(isDied);
}

bool IPCObjectProxy::IsObjectDead() const
{
    return isRemoteDead_.load();
}

bool IPCObjectProxy::AddDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    if (recipient == nullptr) {
        ZLOGE(LABEL, "recipient is null");
        return false;
    }
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = remoteDescriptor_;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (IsObjectDead()) {
        ZLOGE(LABEL, "proxy is already dead, handle:%{public}d desc:%{public}s", handle_, desc.c_str());
        return false;
    }
    sptr<DeathRecipientAddrInfo> info = new DeathRecipientAddrInfo(recipient);
    if (info == nullptr || info->soPath_.empty()) {
        ZLOGE(LABEL, "invalid object, info is nullptr:%{public}d", info == nullptr);
        return false;
    }
    recipients_.push_back(info);
    if (recipients_.size() > 1 || handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        ZLOGD(LABEL, "death recipient is already registered, handle:%{public}d desc:%{public}s",
            handle_, desc.c_str());
        return true;
    }
    if (!RegisterBinderDeathRecipient()) {
        ZLOGE(LABEL, "register failed, handle:%{public}d desc:%{public}s addr:%{public}u", handle_,
            desc.c_str(), ProcessSkeleton::ConvertAddr(this));
        recipients_.pop_back();
    }
    ZLOGD(LABEL, "success, handle:%{public}d desc:%{public}s %{public}u", handle_,
        desc.c_str(), ProcessSkeleton::ConvertAddr(this));
    return true;
}

bool IPCObjectProxy::RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
{
    if (recipient == nullptr) {
        ZLOGW(LABEL, "recipient is null");
        return false;
    }
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = remoteDescriptor_;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (IsObjectDead()) {
        ZLOGD(LABEL, "proxy is already dead, handle:%{public}d desc:%{public}s", handle_, desc.c_str());
        return false;
    }
    bool recipientErased = false;
    for (auto iter = recipients_.begin(); iter != recipients_.end(); iter++) {
        if ((*iter)->recipient_ == recipient) {
            recipients_.erase(iter);
            recipientErased = true;
            break;
        }
    }
    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE && recipientErased == true) {
        ZLOGI(LABEL, "death recipient is already unregistered, handle:%{public}d desc:%{public}s",
            handle_, desc.c_str());
        return true;
    }

    if (recipientErased && recipients_.empty() && !UnRegisterBinderDeathRecipient()) {
        ZLOGE(LABEL, "unregister failed, handle:%{public}d desc:%{public}s addr:%{public}u",
            handle_, desc.c_str(), ProcessSkeleton::ConvertAddr(this));
    }

    ZLOGD(LABEL, "handle:%{public}d desc:%{public}s addr:%{public}u, result:%{public}d", handle_,
        desc.c_str(), ProcessSkeleton::ConvertAddr(this), recipientErased);
    return recipientErased;
}

// LCOV_EXCL_START
void IPCObjectProxy::SendObituary()
{
    std::vector<sptr<DeathRecipientAddrInfo>> toBeReport;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        toBeReport.swap(recipients_);
    }
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        // hd is handle, ct is count
        ZLOGI_SENDOBITUARY(LABEL, "hd:%{public}d ct:%{public}zu", handle_, toBeReport.size());
    }
#ifndef CONFIG_IPC_SINGLE
    if (handle_ < IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        if (proto_ == IRemoteObject::IF_PROT_DATABUS || proto_ == IRemoteObject::IF_PROT_ERROR) {
            RemoveDbinderDeathRecipient();
        }
    }
#endif
    SetObjectDied(true);
    if (toBeReport.size() > 0 && handle_ < IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker != nullptr) {
            invoker->RemoveDeathRecipient(handle_, this);
        } else {
            ZLOGE(LABEL, "invoker is null");
        }
    }
    for (auto iter = toBeReport.begin(); iter != toBeReport.end(); iter++) {
        if ((*iter)->IsDlclosed()) {
            ZLOGE(LABEL, "so has been dlclosed, sopath:%{public}s", (*iter)->soPath_.c_str());
            continue;
        }
        sptr<DeathRecipient> recipient = (*iter)->recipient_;
        if (recipient != nullptr) {
            ZLOGD(LABEL, "handle:%{public}u call OnRemoteDied begin", handle_);
            recipient->OnRemoteDied(this);
            ZLOGD(LABEL, "handle:%{public}u call OnRemoteDied end", handle_);
        }
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void IPCObjectProxy::ClearDeathRecipients()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (recipients_.empty()) {
        return;
    }
    recipients_.clear();
    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        return;
    }
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker != nullptr) {
        invoker->RemoveDeathRecipient(handle_, this);
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS || proto_ == IRemoteObject::IF_PROT_ERROR) {
        RemoveDbinderDeathRecipient();
    }
#endif
}
// LCOV_EXCL_STOP

int IPCObjectProxy::GetProto() const
{
    return proto_;
}

// LCOV_EXCL_START
int32_t IPCObjectProxy::NoticeServiceDie()
{
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = remoteDescriptor_;
    }
    ZLOGW(LABEL, "handle:%{public}d desc:%{public}s", handle_, desc.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::NOTICE_DEATH_RECIPIENT);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE || reply.ReadInt32() != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        return IPC_PROXY_TRANSACTION_ERR;
    }

    return ERR_NONE;
}
// LCOV_EXCL_STOP

int IPCObjectProxy::InvokeListenThread(MessageParcel &data, MessageParcel &reply)
{
    MessageOption option;
    return SendRequestInner(false, INVOKE_LISTEN_THREAD, data, reply, option);
}

// LCOV_EXCL_START
uint32_t IPCObjectProxy::GetStrongRefCountForStub()
{
    BinderInvoker *invoker = reinterpret_cast<BinderInvoker *>(IPCThreadSkeleton::GetDefaultInvoker());
    if (invoker == nullptr) {
        ZLOGE(LABEL, "get default invoker failed");
        return 0; // 0 means get failed
    }
    return invoker->GetStrongRefCountForStub(handle_);
}
// LCOV_EXCL_STOP

#ifdef OHOS_PLATFORM
// LCOV_EXCL_START
bool IPCObjectProxy::CanPromote()
{
    return (GetSptrRefCount() > 0);
}
// LCOV_EXCL_STOP
#endif

#ifndef CONFIG_IPC_SINGLE
// LCOV_EXCL_START
int IPCObjectProxy::UpdateProto()
{
    int proto = GetProtoInfo();
    SetProto(proto);
    return proto;
}
// LCOV_EXCL_STOP

bool IPCObjectProxy::UpdateProto(const void *dbinderData)
{
    auto data = reinterpret_cast<const dbinder_negotiation_data *>(dbinderData);
    if (data != nullptr && data->proto == IRemoteObject::IF_PROT_DATABUS) {
        dbinderData_ = std::make_unique<uint8_t[]>(sizeof(dbinder_negotiation_data));
        if (dbinderData_ == nullptr) {
            SetObjectDied(true);
            SetProto(IRemoteObject::IF_PROT_ERROR);
            ZLOGE(LABEL, "malloc dbinderData fail, handle:%{public}d", handle_);
            return false;
        }
        auto tmp = reinterpret_cast<dbinder_negotiation_data *>(dbinderData_.get());
        *tmp = *data;
        if (!UpdateDatabusClientSession()) {
            ZLOGE(LABEL, "UpdateDatabusClientSession fail, handle:%{public}d", handle_);
            SetObjectDied(true);
            SetProto(IRemoteObject::IF_PROT_ERROR);
            dbinderData_ = nullptr;
            return false;
        }
        SetProto(IRemoteObject::IF_PROT_DATABUS);
        {
            std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
            remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(data->desc));
        }
    } else if (CheckHaveSession()) {
        SetProto(IRemoteObject::IF_PROT_DATABUS);
    }
    return true;
}

// LCOV_EXCL_START
int32_t IPCObjectProxy::IncRefToRemote()
{
    MessageParcel data, reply;
    MessageOption option;

    int32_t err = SendRequestInner(false, DBINDER_INCREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, remoteDescriptor_, ProcessSkeleton::ConvertAddr(this));
        // do nothing
    }
    return err;
}
// LCOV_EXCL_STOP

void IPCObjectProxy::ReleaseProto()
{
    switch (GetProto()) {
        case IRemoteObject::IF_PROT_BINDER: {
            ReleaseBinderProto();
            break;
        }
        case IRemoteObject::IF_PROT_DATABUS:
        case IRemoteObject::IF_PROT_ERROR: {
            ReleaseDatabusProto();
            break;
        }
        default: {
            ZLOGE(LABEL, "release invalid proto:%{public}d", proto_);
            break;
        }
    }
}

void IPCObjectProxy::SetProto(int proto)
{
    proto_ = proto;
}

// LCOV_EXCL_START
int IPCObjectProxy::GetProtoInfo()
{
    if (CheckHaveSession()) {
        return IRemoteObject::IF_PROT_DATABUS;
    }
    if (handle_ >= IPCProcessSkeleton::DBINDER_HANDLE_BASE) {
        ZLOGE(LABEL, "cannot find session for handle:%{public}u", handle_);
        return IRemoteObject::IF_PROT_ERROR;
    }

    MessageParcel data, reply;
    MessageOption option;
    int err = SendRequestInner(true, GET_PROTO_INFO, data, reply, option);
    if (err != ERR_NONE && err != -EBADMSG) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGW(LABEL, "GET_PROTO_INFO transact return error:%{public}d handle:%{public}u time:%{public}" PRIu64, err,
            handle_, curTime);
        return IRemoteObject::IF_PROT_ERROR;
    }

    switch (reply.ReadUint32()) {
        case IRemoteObject::IF_PROT_BINDER: {
            std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
            remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(reply.ReadString16()));
            ZLOGD(LABEL, "binder, handle:%{public}u desc:%{public}s", handle_, remoteDescriptor_.c_str());
            break;
        }
        case IRemoteObject::IF_PROT_DATABUS: {
            if (UpdateDatabusClientSession(handle_, reply)) {
                std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
                remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(reply.ReadString16()));
                ZLOGD(LABEL, "dbinder, handle:%{public}u desc:%{public}s", handle_, remoteDescriptor_.c_str());
                return IRemoteObject::IF_PROT_DATABUS;
            } else {
                ZLOGE(LABEL, "UpdateDatabusClientSession failed");
                return IRemoteObject::IF_PROT_ERROR;
            }
        }
        default: {
            ZLOGE(LABEL, "get Invalid proto");
            return IRemoteObject::IF_PROT_ERROR;
        }
    }

    return IRemoteObject::IF_PROT_BINDER;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool IPCObjectProxy::AddDbinderDeathRecipient()
{
    std::string desc;
    std::u16string remoteDescriptorTmp;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        remoteDescriptorTmp = Str8ToStr16(remoteDescriptor_);
        desc = remoteDescriptor_;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGW(LABEL, "get current fail, handle:%{public}d desc:%{public}s", handle_, desc.c_str());
        return false;
    }

    if (current->QueryCallbackStub(this) != nullptr) {
        ZLOGW(LABEL, "already attach callback stub, handle:%{public}d desc:%{public}s", handle_, desc.c_str());
        return true;
    }

    //note that cannot use this proxy's descriptor
    sptr<IPCObjectStub> callbackStub = new (std::nothrow) IPCObjectStub(u"DBinderDeathRecipient" + remoteDescriptorTmp);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "create IPCObjectStub object failed, handle:%{public}d desc:%{public}s", handle_, desc.c_str());
        return false;
    }
    if (!current->AttachCallbackStub(this, callbackStub)) {
        ZLOGW(LABEL, "already attach new callback stub, handle:%{public}d desc:%{public}s", handle_, desc.c_str());
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::ADD_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc,
            ProcessSkeleton::ConvertAddr(this));
        current->DetachCallbackStub(this);
        return false;
    }

    return true;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool IPCObjectProxy::RemoveDbinderDeathRecipient()
{
    std::string desc;
    {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        desc = remoteDescriptor_;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "get current fail");
        return false;
    }
    ZLOGW(LABEL, "handle:%{public}d desc:%{public}s", handle_, desc.c_str());
    sptr<IPCObjectStub> callbackStub = current->DetachCallbackStub(this);
    if (callbackStub == nullptr) {
        ZLOGE(LABEL, "get callbackStub fail, handle:%{public}d desc:%{public}s", handle_, desc.c_str());
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    data.WriteInt32(IRemoteObject::DeathRecipient::REMOVE_DEATH_RECIPIENT);
    data.WriteRemoteObject(callbackStub);

    int err = SendLocalRequest(DBINDER_OBITUARY_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        // do nothing, even send request failed
    }
    return err == ERR_NONE;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool IPCObjectProxy::CheckHaveSession()
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "IPCProcessSkeleton is null");
        return false;
    }

    return current->ProxyMoveDBinderSession(handle_, this);
}
// LCOV_EXCL_STOP

bool IPCObjectProxy::MakeDBinderTransSession(const DBinderNegotiationData &data)
{
    DBinderDatabusInvoker *invoker =
        reinterpret_cast<DBinderDatabusInvoker *>(IPCThreadSkeleton::GetRemoteInvoker(IRemoteObject::IF_PROT_DATABUS));
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null");
        return false;
    }
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "skeleton is nullptr");
        return false;
    }
    if (data.peerServiceName.empty()) {
        ZLOGE(LABEL, "serviceName is empty");
        return false;
    }

    auto dbinderSession = std::make_shared<DBinderSessionObject>(data.peerServiceName, data.peerDeviceId,
        data.stubIndex, this, data.peerTokenId);
    if (dbinderSession == nullptr) {
        ZLOGE(LABEL, "make DBinderSessionObject fail!");
        return false;
    }
    dbinderSession->SetPeerPid(data.peerPid);
    dbinderSession->SetPeerUid(data.peerUid);

    if (!current->CreateSoftbusServer(data.localServiceName)) {
        ZLOGE(LABEL, "CreateSoftbusServer fail, name:%{public}s localID:%{public}s", data.localServiceName.c_str(),
            IPCProcessSkeleton::ConvertToSecureString(data.localDeviceId).c_str());
        return false;
    }
    if (!invoker->UpdateClientSession(dbinderSession)) {
        // no need to remove softbus server
        ZLOGE(LABEL, "UpdateClientSession fail!");
        return false;
    }
    if (!current->ProxyAttachDBinderSession(handle_, dbinderSession)) {
        // should not get here
        ZLOGW(LABEL, "ProxyAttachDBinderSession fail for handle:%{public}d, maybe a concurrent scenarios", handle_);
        if (current->QuerySessionByInfo(data.peerServiceName, data.peerDeviceId) == nullptr) {
            ZLOGE(LABEL, "session is not exist, service:%{public}s devId:%{public}s", data.peerServiceName.c_str(),
                IPCProcessSkeleton::ConvertToSecureString(data.peerDeviceId).c_str());
            dbinderSession->CloseDatabusSession();
            return false;
        }
    }
    ZLOGI(LABEL, "succ");
    return true;
}

int IPCObjectProxy::GetDBinderNegotiationData(int handle, MessageParcel &reply, DBinderNegotiationData &dbinderData)
{
    dbinderData.stubIndex = reply.ReadUint64();
    dbinderData.peerServiceName = reply.ReadString();
    dbinderData.peerDeviceId = reply.ReadString();
    dbinderData.localDeviceId = reply.ReadString();
    dbinderData.localServiceName = reply.ReadString();
    dbinderData.peerTokenId = reply.ReadUint32();
    if (dbinderData.peerServiceName.empty() || dbinderData.peerDeviceId.empty() || dbinderData.localDeviceId.empty() ||
        dbinderData.localServiceName.empty()) {
        ZLOGE(LABEL, "invalid param");
        return ERR_INVALID_DATA;
    }

    int32_t peerPid = -1;
    int32_t peerUid = -1;
    if (!DatabusSocketListener::GetPidAndUidFromServiceName(dbinderData.peerServiceName, peerPid, peerUid)) {
        ZLOGE(LOG_LABEL, "failed to get peerpid and peeruid from serviceName");
        return ERR_INVALID_DATA;
    }

    dbinderData.peerUid = peerUid;
    dbinderData.peerPid = peerPid;
    return ERR_NONE;
}

bool IPCObjectProxy::UpdateDatabusClientSession(int handle, MessageParcel &reply)
{
    DBinderNegotiationData dbinderData;
    if (GetDBinderNegotiationData(handle, reply, dbinderData) != ERR_NONE) {
        return false;
    }
    return MakeDBinderTransSession(dbinderData);
}

int IPCObjectProxy::GetDBinderNegotiationData(DBinderNegotiationData &dbinderData)
{
    if (dbinderData_ == nullptr) {
        ZLOGE(LABEL, "dbinderData_ is null");
        return ERR_INVALID_DATA;
    }
    auto data = reinterpret_cast<const dbinder_negotiation_data *>(dbinderData_.get());
    dbinderData.stubIndex = data->stub_index;
    dbinderData.peerServiceName = data->target_name;
    dbinderData.peerDeviceId = data->target_device;
    dbinderData.localDeviceId = data->local_device;
    dbinderData.localServiceName = data->local_name;
    dbinderData.peerTokenId = data->tokenid;

    int32_t peerPid = -1;
    int32_t peerUid = -1;
    if (!DatabusSocketListener::GetPidAndUidFromServiceName(dbinderData.peerServiceName, peerPid, peerUid)) {
        ZLOGE(LOG_LABEL, "failed to get peerpid and peeruid from serviceName");
        return ERR_INVALID_DATA;
    }

    dbinderData.peerUid = peerUid;
    dbinderData.peerPid = peerPid;
    return ERR_NONE;
}

// LCOV_EXCL_START
bool IPCObjectProxy::UpdateDatabusClientSession()
{
    DBinderNegotiationData dbinderData;
    if (GetDBinderNegotiationData(dbinderData) != ERR_NONE) {
        return false;
    }
    return MakeDBinderTransSession(dbinderData);
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void IPCObjectProxy::ReleaseDatabusProto()
{
    if (handle_ == 0) {
        ZLOGW(LABEL, "handle == 0, do nothing");
        return;
    }

    MessageParcel data, reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int err = SendRequestInner(false, DBINDER_DECREFS_TRANSACTION, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, remoteDescriptor_, ProcessSkeleton::ConvertAddr(this));
        // do nothing, if this cmd failed, stub's refcount will be decreased when OnSessionClosed called
    }

    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LABEL, "release databus proto skeleton is null");
        return;
    }
    std::shared_ptr<DBinderSessionObject> toBeDelete = current->ProxyDetachDBinderSession(handle_, this);
    if (toBeDelete != nullptr) {
        // make sure session corresponding to this sessionName and deviceId is no longer used by other proxy
        std::shared_ptr<DBinderSessionObject> sessionObj
            = current->QuerySessionByInfo(toBeDelete->GetServiceName(), toBeDelete->GetDeviceId());
        if (sessionObj == nullptr) {
            // close session in lock
            toBeDelete->CloseDatabusSession();
        } else {
            ZLOGI(LOG_LABEL, "the session is using by others, can't close it, handle:%{public}u socketId:%{public}d "
                "sessionName:%{public}s deviceId:%{public}s", handle_, toBeDelete->GetSocketId(),
                toBeDelete->GetServiceName().c_str(),
                IPCProcessSkeleton::ConvertToSecureString(toBeDelete->GetDeviceId()).c_str());
        }
    }
    ClearDBinderServiceState();
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void IPCObjectProxy::ReleaseBinderProto()
{
    // do nothing
}

int IPCObjectProxy::ClearDBinderServiceState()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int err = SendRequestInner(true, CLEAR_DBINDER_SERVICE_STATE, data, reply, option);
    if (err != ERR_NONE) {
        std::shared_lock<std::shared_mutex> lockGuard(descMutex_);
        PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, remoteDescriptor_, ProcessSkeleton::ConvertAddr(this));
    }
    ZLOGI(LABEL, "result:%{public}d", err);
    return err;
}
// LCOV_EXCL_STOP
#endif

// LCOV_EXCL_START
bool IPCObjectProxy::RegisterBinderDeathRecipient()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null");
        return false;
    }
    if (!invoker->AddDeathRecipient(handle_, this)) {
        ZLOGE(LABEL, "add failed, handle:%{public}d", handle_);
        return false;
    }
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS && !AddDbinderDeathRecipient()) {
        ZLOGE(LABEL, "add failed, handle:%{public}d", handle_);
        return false;
    }
#endif
    ZLOGD(LABEL, "success, handle:%{public}d", handle_);
    return true;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool IPCObjectProxy::UnRegisterBinderDeathRecipient()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
    if (invoker == nullptr) {
        ZLOGE(LABEL, "invoker is null");
        return false;
    }

    bool dbinderStatus = true;
    bool status = invoker->RemoveDeathRecipient(handle_, this);
#ifndef CONFIG_IPC_SINGLE
    if (proto_ == IRemoteObject::IF_PROT_DATABUS || proto_ == IRemoteObject::IF_PROT_ERROR) {
        dbinderStatus = RemoveDbinderDeathRecipient();
    }
#endif
    ZLOGD(LABEL, "unregister result:%{public}d, handle:%{public}d", status && dbinderStatus, handle_);
    return status && dbinderStatus;
}
// LCOV_EXCL_STOP

IPCObjectProxy::DeathRecipientAddrInfo::DeathRecipientAddrInfo(const sptr<DeathRecipient> &recipient)
    : recipient_(recipient), soFuncAddr_(nullptr), soPath_()
{
    if (recipient_ == nullptr) {
        ZLOGD(LABEL, "recipient is null");
        return;
    }
    soFuncAddr_ = reinterpret_cast<void *>(GET_FIRST_VIRTUAL_FUNC_ADDR(recipient_.GetRefPtr()));
    soPath_ = GetNewSoPath();
}

// LCOV_EXCL_START
std::string IPCObjectProxy::DeathRecipientAddrInfo::GetNewSoPath()
{
    if (soFuncAddr_ == nullptr) {
        ZLOGE(LABEL, "empty function addr");
        return "";
    }

    Dl_info info;
    int32_t ret = dladdr(soFuncAddr_, &info);
    if ((ret == 0) || (info.dli_fname == nullptr)) {
        ZLOGE(LABEL, "dladdr failed ret:%{public}d", ret);
        return "";
    }
    return info.dli_fname;
}
// LCOV_EXCL_STOP

bool IPCObjectProxy::DeathRecipientAddrInfo::IsDlclosed()
{
    std::string newSoPath = GetNewSoPath();
    if (newSoPath.empty() || (newSoPath != soPath_)) {
        return true;
    }
    return false;
}

#ifdef ENABLE_IPC_TRACE
// LCOV_EXCL_START
void IPCObjectProxy::StartLifeCycleTrace()
{
    isTraceEnabled_ = IPCTrace::IsEnabled();
    if (isTraceEnabled_) {
        IPCTrace::StartAsync(GenLifeCycleTraceInfo(), static_cast<int32_t>(ProcessSkeleton::ConvertAddr(this)));
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
std::string IPCObjectProxy::GenLifeCycleTraceInfo() const
{
    return "Proxy:" +
        fullRemoteDescriptor_ + "_" +
        std::to_string(handle_) + "_" +
        std::to_string(ProcessSkeleton::ConvertAddr(this));
}
// LCOV_EXCL_STOP

std::string IPCObjectProxy::GenSendRequestTraceInfo(uint32_t code) const
{
    return "SendRequest:" +
        fullRemoteDescriptor_ + "_" +
        std::to_string(handle_) + "_" +
        std::to_string(ProcessSkeleton::ConvertAddr(this)) + "_" +
        std::to_string(code);
}
#endif

int IPCObjectProxy::Dump(int fd, const std::vector<std::u16string> &args)
{
    MessageParcel data, reply;
    MessageOption option{ MessageOption::TF_SYNC };
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    return SendRequestInner(false, DUMP_TRANSACTION, data, reply, option);
}

std::string IPCObjectProxy::GetDescriptor(MessageParcel &data)
{
    std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
    if (remoteDescriptor_.empty()) {
#ifdef ENABLE_IPC_TRACE
        fullRemoteDescriptor_ = Str16ToStr8(data.GetInterfaceToken());
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(fullRemoteDescriptor_);
        StartLifeCycleTrace();
#else
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(data.GetInterfaceToken()));
#endif
    }
    return remoteDescriptor_;
}

void IPCObjectProxy::PrintErrorDetailedInfo(int err, const std::string &desc)
{
#ifndef __linux__
    uint32_t errorCode;
    std::string errorDesc;
    if (err == BR_FAILED_REPLY) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is null");
            return;
        }
        bool isInvokerSuccess = invoker->GetDetailedErrorInfo(errorCode, errorDesc);
        if (isInvokerSuccess) {
            std::string newDesc = "(subErr:" + std::to_string(errCode) + " SubErrDesc:" + errorDesc + ") " + desc;
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, newDesc, ProcessSkeleton::ConvertAddr(this));
        } else {
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        }
    }
#else
    PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
#endif
}

int IPCObjectProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != DUMP_TRANSACTION && code > MAX_TRANSACTION_ID) {
        return IPC_PROXY_INVALID_CODE_ERR;
    }
    std::string desc = GetDescriptor(data);
#ifdef ENABLE_IPC_TRACE
    bool isTraceEnable = IPCTrace::IsEnabled();
    if (isTraceEnable) {
        IPCTrace::Start(GenSendRequestTraceInfo(code));
    }
#endif
    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
#ifdef ENABLE_IPC_TRACE
    if (isTraceEnable) {
        IPCTrace::Finish();
    }
#endif
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGW(LABEL, "DFX_BlockMonitor cost %{public}lld ms, code:%{public}u, desc:%{public}s", timeInterval,
            code, desc.c_str());
    }
    return err;
}

int IPCObjectProxy::Dump(int fd, const std::vector<std::u16string> &args)
{
    MessageParcel data, reply;
    MessageOption option{ MessageOption::TF_SYNC };
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    return SendRequestInner(false, DUMP_TRANSACTION, data, reply, option);
}

std::string IPCObjectProxy::GetDescriptor(MessageParcel &data)
{
    std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
    if (remoteDescriptor_.empty()) {
#ifdef ENABLE_IPC_TRACE
        fullRemoteDescriptor_ = Str16ToStr8(data.GetInterfaceToken());
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(fullRemoteDescriptor_);
        StartLifeCycleTrace();
#else
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(data.GetInterfaceToken()));
#endif
    }
    return remoteDescriptor_;
}

void IPCObjectProxy::PrintErrorDetailedInfo(int err, const std::string &desc)
{
#ifndef __linux__
    uint32_t errorCode;
    std::string errorDesc;
    if (err == BR_FAILED_REPLY) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is null");
            return;
        }
        bool isInvokerSuccess = invoker->GetDetailedErrorInfo(errorCode, errorDesc);
        if (isInvokerSuccess) {
            std::string newDesc = "(subErr:" + std::to_string(errCode) + " SubErrDesc:" + errorDesc + ") " + desc;
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, newDesc, ProcessSkeleton::ConvertAddr(this));
        } else {
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        }
    }
#else
    PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
#endif
}

int IPCObjectProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != DUMP_TRANSACTION && code > MAX_TRANSACTION_ID) {
        return IPC_PROXY_INVALID_CODE_ERR;
    }
    std::string desc = GetDescriptor(data);
#ifdef ENABLE_IPC_TRACE
    bool isTraceEnable = IPCTrace::IsEnabled();
    if (isTraceEnable) {
        IPCTrace::Start(GenSendRequestTraceInfo(code));
    }
#endif
    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
#ifdef ENABLE_IPC_TRACE
    if (isTraceEnable) {
        IPCTrace::Finish();
    }
#endif
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGW(LABEL, "DFX_BlockMonitor cost %{public}lld ms, code:%{public}u, desc:%{public}s", timeInterval,
            code, desc.c_str());
    }
    return err;
}

int IPCObjectProxy::Dump(int fd, const std::vector<std::u16string> &args)
{
    MessageParcel data, reply;
    MessageOption option{ MessageOption::TF_SYNC };
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    return SendRequestInner(false, DUMP_TRANSACTION, data, reply, option);
}

std::string IPCObjectProxy::GetDescriptor(MessageParcel &data)
{
    std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
    if (remoteDescriptor_.empty()) {
#ifdef ENABLE_IPC_TRACE
        fullRemoteDescriptor_ = Str16ToStr8(data.GetInterfaceToken());
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(fullRemoteDescriptor_);
        StartLifeCycleTrace();
#else
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(data.GetInterfaceToken()));
#endif
    }
    return remoteDescriptor_;
}

void IPCObjectProxy::PrintErrorDetailedInfo(int err, const std::string &desc)
{
#ifndef __linux__
    uint32_t errorCode;
    std::string errorDesc;
    if (err == BR_FAILED_REPLY) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is null");
            return;
        }
        bool isInvokerSuccess = invoker->GetDetailedErrorInfo(errorCode, errorDesc);
        if (isInvokerSuccess) {
            std::string newDesc = "(subErr:" + std::to_string(errCode) + " SubErrDesc:" + errorDesc + ") " + desc;
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, newDesc, ProcessSkeleton::ConvertAddr(this));
        } else {
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        }
    }
#else
    PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
#endif
}

int IPCObjectProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != DUMP_TRANSACTION && code > MAX_TRANSACTION_ID) {
        return IPC_PROXY_INVALID_CODE_ERR;
    }
    std::string desc = GetDescriptor(data);
#ifdef ENABLE_IPC_TRACE
    bool isTraceEnable = IPCTrace::IsEnabled();
    if (isTraceEnable) {
        IPCTrace::Start(GenSendRequestTraceInfo(code));
    }
#endif
    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
#ifdef ENABLE_IPC_TRACE
    if (isTraceEnable) {
        IPCTrace::Finish();
    }
#endif
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGW(LABEL, "DFX_BlockMonitor cost %{public}lld ms, code:%{public}u, desc:%{public}s", timeInterval,
            code, desc.c_str());
    }
    return err;
}

int IPCObjectProxy::Dump(int fd, const std::vector<std::u16string> &args)
{
    MessageParcel data, reply;
    MessageOption option{ MessageOption::TF_SYNC };
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    return SendRequestInner(false, DUMP_TRANSACTION, data, reply, option);
}

std::string IPCObjectProxy::GetDescriptor(MessageParcel &data)
{
    std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
    if (remoteDescriptor_.empty()) {
#ifdef ENABLE_IPC_TRACE
        fullRemoteDescriptor_ = Str16ToStr8(data.GetInterfaceToken());
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(fullRemoteDescriptor_);
        StartLifeCycleTrace();
#else
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(data.GetInterfaceToken()));
#endif
    }
    return remoteDescriptor_;
}

void IPCObjectProxy::PrintErrorDetailedInfo(int err, const std::string &desc)
{
#ifndef __linux__
    uint32_t errorCode;
    std::string errorDesc;
    if (err == BR_FAILED_REPLY) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is null");
            return;
        }
        bool isInvokerSuccess = invoker->GetDetailedErrorInfo(errorCode, errorDesc);
        if (isInvokerSuccess) {
            std::string newDesc = "(subErr:" + std::to_string(errCode) + " SubErrDesc:" + errorDesc + ") " + desc;
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, newDesc, ProcessSkeleton::ConvertAddr(this));
        } else {
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        }
    }
#else
    PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
#endif
}

int IPCObjectProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != DUMP_TRANSACTION && code > MAX_TRANSACTION_ID) {
        return IPC_PROXY_INVALID_CODE_ERR;
    }
    std::string desc = GetDescriptor(data);
#ifdef ENABLE_IPC_TRACE
    bool isTraceEnable = IPCTrace::IsEnabled();
    if (isTraceEnable) {
        IPCTrace::Start(GenSendRequestTraceInfo(code));
    }
#endif
    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
#ifdef ENABLE_IPC_TRACE
    if (isTraceEnable) {
        IPCTrace::Finish();
    }
#endif
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGW(LABEL, "DFX_BlockMonitor cost %{public}lld ms, code:%{public}u, desc:%{public}s", timeInterval,
            code, desc.c_str());
    }
    return err;
}

int IPCObjectProxy::Dump(int fd, const std::vector<std::u16string> &args)
{
    MessageParcel data, reply;
    MessageOption option{ MessageOption::TF_SYNC };
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    return SendRequestInner(false, DUMP_TRANSACTION, data, reply, option);
}

std::string IPCObjectProxy::GetDescriptor(MessageParcel &data)
{
    std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
    if (remoteDescriptor_.empty()) {
#ifdef ENABLE_IPC_TRACE
        fullRemoteDescriptor_ = Str16ToStr8(data.GetInterfaceToken());
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(fullRemoteDescriptor_);
        StartLifeCycleTrace();
#else
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(data.GetInterfaceToken()));
#endif
    }
    return remoteDescriptor_;
}

void IPCObjectProxy::PrintErrorDetailedInfo(int err, const std::string &desc)
{
#ifndef __linux__
    uint32_t errorCode;
    std::string errorDesc;
    if (err == BR_FAILED_REPLY) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is null");
            return;
        }
        bool isInvokerSuccess = invoker->GetDetailedErrorInfo(errorCode, errorDesc);
        if (isInvokerSuccess) {
            std::string newDesc = "(subErr:" + std::to_string(errCode) + " SubErrDesc:" + errorDesc + ") " + desc;
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, newDesc, ProcessSkeleton::ConvertAddr(this));
        } else {
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        }
    }
#else
    PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
#endif
}

int IPCObjectProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != DUMP_TRANSACTION && code > MAX_TRANSACTION_ID) {
        return IPC_PROXY_INVALID_CODE_ERR;
    }
    std::string desc = GetDescriptor(data);
#ifdef ENABLE_IPC_TRACE
    bool isTraceEnable = IPCTrace::IsEnabled();
    if (isTraceEnable) {
        IPCTrace::Start(GenSendRequestTraceInfo(code));
    }
#endif
    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
#ifdef ENABLE_IPC_TRACE
    if (isTraceEnable) {
        IPCTrace::Finish();
    }
#endif
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGW(LABEL, "DFX_BlockMonitor cost %{public}lld ms, code:%{public}u, desc:%{public}s", timeInterval,
            code, desc.c_str());
    }
    return err;
}

int IPCObjectProxy::Dump(int fd, const std::vector<std::u16string> &args)
{
    MessageParcel data, reply;
    MessageOption option{ MessageOption::TF_SYNC };
    data.WriteFileDescriptor(fd);
    data.WriteString16Vector(args);
    return SendRequestInner(false, DUMP_TRANSACTION, data, reply, option);
}

std::string IPCObjectProxy::GetDescriptor(MessageParcel &data)
{
    std::unique_lock<std::shared_mutex> lockGuard(descMutex_);
    if (remoteDescriptor_.empty()) {
#ifdef ENABLE_IPC_TRACE
        fullRemoteDescriptor_ = Str16ToStr8(data.GetInterfaceToken());
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(fullRemoteDescriptor_);
        StartLifeCycleTrace();
#else
        remoteDescriptor_ = ProcessSkeleton::ConvertToSecureDesc(Str16ToStr8(data.GetInterfaceToken()));
#endif
    }
    return remoteDescriptor_;
}

void IPCObjectProxy::PrintErrorDetailedInfo(int err, const std::string &desc)
{
#ifndef __linux__
    uint32_t errorCode;
    std::string errorDesc;
    if (err == BR_FAILED_REPLY) {
        IRemoteInvoker *invoker = IPCThreadSkeleton::GetDefaultInvoker();
        if (invoker == nullptr) {
            ZLOGE(LABEL, "invoker is null");
            return;
        }
        bool isInvokerSuccess = invoker->GetDetailedErrorInfo(errorCode, errorDesc);
        if (isInvokerSuccess) {
            std::string newDesc = "(subErr:" + std::to_string(errCode) + " SubErrDesc:" + errorDesc + ") " + desc;
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, newDesc, ProcessSkeleton::ConvertAddr(this));
        } else {
            PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
        }
    }
#else
    PRINT_SEND_REQUEST_FAIL_INFO(handle_, err, desc, ProcessSkeleton::ConvertAddr(this));
#endif
}

int IPCObjectProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != DUMP_TRANSACTION && code > MAX_TRANSACTION_ID) {
        return IPC_PROXY_INVALID_CODE_ERR;
    }
    std::string desc = GetDescriptor(data);
#ifdef ENABLE_IPC_TRACE
    bool isTraceEnable = IPCTrace::IsEnabled();
    if (isTraceEnable) {
        IPCTrace::Start(GenSendRequestTraceInfo(code));
    }
#endif
    auto beginTime = std::chrono::steady_clock::now();
    int err = SendRequestInner(false, code, data, reply, option);
    auto endTime = std::chrono::steady_clock::now();
#ifdef ENABLE_IPC_TRACE
    if (isTraceEnable) {
        IPCTrace::Finish();
    }
#endif
    auto timeInterval = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime).count();
    if (timeInterval > SEND_REQUEST_TIMEOUT) {
        ZLOGW(LABEL, "DFX_BlockMonitor cost %{public}lld ms, code:%{public}u, desc:%{public}s", timeInterval,
            code, desc.c_str());
    }
    return err;
}

 
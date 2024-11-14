/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "message_parcel.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#include "ashmem.h"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "ipc_debug.h"
#include "ipc_file_descriptor.h"
#include "ipc_process_skeleton.h"
#include "iremote_invoker.h"
#include "iremote_object.h"
#include "log_tags.h"
#include "memory"
#include "new"
#include "parcel.h"
#include "process_skeleton.h"
#include "refbase.h"
#include "securec.h"
#include "sys_binder.h"

#ifndef CONFIG_IPC_SINGLE
#include "dbinder_callback_stub.h"
#include "dbinder_session_object.h"
#endif

namespace OHOS {
#ifdef CONFIG_IPC_SINGLE
using namespace IPC_SINGLE;
#endif
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_PARCEL, "MessageParcel" };

void AcquireObject(flat_binder_object *flat, const void *cookie)
{
    switch (flat->hdr.type) {
        case BINDER_TYPE_BINDER:
            if (flat->binder) {
                reinterpret_cast<IRemoteObject *>(flat->cookie)->IncStrongRef(cookie);
            }
            break;
        case BINDER_TYPE_HANDLE: {
            IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
            IRemoteObject *remoteObject = nullptr;
            if (current != nullptr) {
                remoteObject = current->QueryObject(current->MakeHandleDescriptor(flat->handle));
            }
            if (remoteObject != nullptr) {
                remoteObject->IncStrongRef(cookie);
            }
            break;
        }
        case BINDER_TYPE_FD:
            flat->handle = static_cast<uint32_t>(dup(flat->handle));
            flat->cookie = 1;
            break;
        default:
            ZLOGE(LOG_LABEL, "binder object type is invalid.");
            break;
    }
}

MessageParcel::MessageParcel()
    : Parcel(),
      writeRawDataFd_(-1),
      readRawDataFd_(-1),
      kernelMappedWrite_(nullptr),
      kernelMappedRead_(nullptr),
      rawData_(nullptr),
      rawDataSize_(0)
{}

MessageParcel::MessageParcel(Allocator *allocator)
    : Parcel(allocator),
      writeRawDataFd_(-1),
      readRawDataFd_(-1),
      kernelMappedWrite_(nullptr),
      kernelMappedRead_(nullptr),
      rawData_(nullptr),
      rawDataSize_(0)
{}

MessageParcel::~MessageParcel()
{
    if (kernelMappedWrite_ != nullptr) {
        ::munmap(kernelMappedWrite_, rawDataSize_);
        kernelMappedWrite_ = nullptr;
    }
    if (kernelMappedRead_ != nullptr) {
        ::munmap(kernelMappedRead_, rawDataSize_);
        kernelMappedRead_ = nullptr;
    }

    if (readRawDataFd_ > 0) {
        ::close(readRawDataFd_);
        readRawDataFd_ = -1;
    }
    if (writeRawDataFd_ > 0) {
        ::close(writeRawDataFd_);
        writeRawDataFd_ = -1;
    }

    ClearFileDescriptor();
    rawData_ = nullptr;
    rawDataSize_ = 0;
}


#ifndef CONFIG_IPC_SINGLE
bool MessageParcel::WriteDBinderProxy(const sptr<IRemoteObject> &object, uint32_t handle, uint64_t stubIndex)
{
    IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
    if (current == nullptr) {
        ZLOGE(LOG_LABEL, "current is nullptr");
        return false;
    }
    std::shared_ptr<DBinderSessionObject> sessionOfPeer = current->ProxyQueryDBinderSession(handle);
    if (sessionOfPeer == nullptr) {
        ZLOGE(LOG_LABEL, "sessionOfPeer is null, handle:%{public}u stubIndex:%{public}" PRIu64, handle, stubIndex);
        return false;
    }
    std::string peerName = sessionOfPeer->GetServiceName();
    std::string peerId = sessionOfPeer->GetDeviceId();
    std::string localId = current->GetLocalDeviceID();
    uint32_t tokenId = sessionOfPeer->GetTokenId();

    sptr<DBinderCallbackStub> fakeStub = current->QueryDBinderCallbackStub(object);
    if (fakeStub == nullptr) {
        // note that cannot use this proxy's descriptor, this stub is now stored and strong refered
        // and need to be erased in an approprite time
        fakeStub = new (std::nothrow) DBinderCallbackStub(peerName, peerId, localId, sessionOfPeer->GetStubIndex(),
            handle, tokenId);
        if (fakeStub == nullptr) {
            ZLOGE(LOG_LABEL, "create DBinderCallbackStub object failed");
            return false;
        }
        if (!current->AttachDBinderCallbackStub(object, fakeStub)) {
            ZLOGE(LOG_LABEL, "save callback of fake stub failed");
            return false;
        }
    }
    return WriteRemoteObject(fakeStub);
}

bool MessageParcel::UpdateDBinderDataOffset(size_t offset)
{
    size_t curOffset = GetWritePosition();
    const binder_buffer_object *obj = reinterpret_cast<const binder_buffer_object *>(GetData() + offset);
    if (obj->hdr.type == BINDER_TYPE_PTR) {
        if (obj->length == sizeof(dbinder_negotiation_data)) {
            // update dbinder object offset
            size_t objOffset = offset + sizeof(binder_buffer_object);
            if (!WriteObjectOffset(objOffset)) {
                RewindWrite(curOffset);
                ZLOGE(LOG_LABEL, "update obj offset:%{public}zu fail, ptr offset:%{public}zu", objOffset, offset);
                return false;
            }
            ZLOGI(LOG_LABEL, "update obj offset:%{public}zu, ptr offset:%{public}zu", objOffset, offset);
        }
    }
    return true;
}
#endif

bool MessageParcel::WriteRemoteObject(const sptr<IRemoteObject> &object)
{
    if (object == nullptr) {
        return false;
    }
    // Increase object's refcount temporarily in case of premature deallocation,
    // object's refcount will be decreased when this MessageParcel destroyed.
    if (object->AttemptIncStrongRef(this) != true) {
        return false;
    }
    holders_.push_back(object);
    object->DecStrongRef(this);
#ifndef CONFIG_IPC_SINGLE
    if (object->IsProxyObject()) {
        const IPCObjectProxy *proxy = reinterpret_cast<const IPCObjectProxy *>(object.GetRefPtr());
        const uint32_t handle = proxy ? proxy->GetHandle() : 0;
        if (IPCProcessSkeleton::IsHandleMadeByUser(handle)) {
            /* this is a fake proxy which handle get by MakeRemoteHandle(), Not binder driver of kernel */
            ZLOGI(LOG_LABEL, "send a dbinder proxy to another process in this device");
            return WriteDBinderProxy(object, handle, 0);
        }
    }
#endif

#ifndef CONFIG_IPC_SINGLE
    auto offset = GetWritePosition();
#endif
    if (!WriteObject<IRemoteObject>(object)) {
        return false;
    }
#ifndef CONFIG_IPC_SINGLE
    if (!UpdateDBinderDataOffset(offset)) {
        RewindWrite(offset);
        return false;
    }
#endif
    return true;
}

sptr<IRemoteObject> MessageParcel::ReadRemoteObject()
{
    sptr<IRemoteObject> temp = ReadObject<IRemoteObject>();
#ifndef CONFIG_IPC_SINGLE
    if (temp != nullptr && !temp->IsProxyObject()) {
        // if this stub is a DBinderCallbackStub, return corresponding proxy
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();
        if (current != nullptr) {
            sptr<IRemoteObject> proxy = current->QueryDBinderCallbackProxy(temp);
            if (proxy != nullptr) {
                temp = proxy;
            }
        }
    }
#endif
    return temp;
}

bool MessageParcel::WriteFileDescriptor(int fd)
{
    if (fd < 0) {
        ZLOGE(LOG_LABEL, "invalid fd:%{public}d", fd);
        return false;
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        ZLOGE(LOG_LABEL, "dup failed, fd:%{public}d, errno:%{public}d", fd, errno);
        return false;
    }
    sptr<IPCFileDescriptor> descriptor = new (std::nothrow) IPCFileDescriptor(dupFd);
    if (descriptor == nullptr) {
        ZLOGE(LOG_LABEL, "create IPCFileDescriptor object failed");
        return false;
    }
    return WriteObject<IPCFileDescriptor>(descriptor);
}

int MessageParcel::ReadFileDescriptor()
{
    sptr<IPCFileDescriptor> descriptor = ReadObject<IPCFileDescriptor>();
    if (descriptor == nullptr) {
        ZLOGE(LOG_LABEL, "ReadObject failed");
        return INVALID_FD;
    }
    int fd = descriptor->GetFd();
    if (fd < 0) {
        ZLOGE(LOG_LABEL, "get fd failed, invalid fd:%{public}d", fd);
        return INVALID_FD;
    }

    int dupFd = dup(fd);
    if (dupFd < 0) {
        ZLOGE(LOG_LABEL, "dup failed, fd:%{public}d, errno:%{public}d", fd, errno);
    }
    return dupFd;
}

void MessageParcel::ClearFileDescriptor()
{
    size_t dataOffset = 0;
    binder_size_t *object = nullptr;
    const flat_binder_object *flat = nullptr;
    for (size_t i = 0; i < GetOffsetsSize(); i++) {
        object = reinterpret_cast<binder_size_t *>(GetObjectOffsets());
        if (object == nullptr) {
            ZLOGE(LOG_LABEL, "object get by GetObjectOffsets() is nullptr");
            break;
        }
        // offset + size
        dataOffset = object[i] + sizeof(flat_binder_object);
        if (dataOffset > GetDataSize()) {
            ZLOGE(LOG_LABEL, "object offset is overflow, dataOffset:%{public}zu dataSize:%{public}zu",
                dataOffset, GetDataSize());
            break;
        }
        uintptr_t data = GetData();
        if (data == 0) {
            ZLOGE(LOG_LABEL, "data get by GetData() is invalid");
            break;
        }
        flat = reinterpret_cast<flat_binder_object *>(data + object[i]);
        if (flat->hdr.type == BINDER_TYPE_FD && flat->handle > 0) {
            ::close(flat->handle);
        }
    }
}

bool MessageParcel::ContainFileDescriptors() const
{
    size_t dataOffset = 0;
    binder_size_t *object = nullptr;
    const flat_binder_object *flat = nullptr;
    for (size_t i = 0; i < GetOffsetsSize(); i++) {
        object = reinterpret_cast<binder_size_t *>(GetObjectOffsets());
        if (object == nullptr) {
            ZLOGE(LOG_LABEL, "object get by GetObjectOffsets() is nullptr");
            break;
        }
        // offset + size
        dataOffset = object[i] + sizeof(flat_binder_object);
        if (dataOffset > GetDataSize()) {
            ZLOGE(LOG_LABEL, "object offset is overflow, dataOffset:%{public}zu dataSize:%{public}zu",
                dataOffset, GetDataSize());
            break;
        }
        uintptr_t data = GetData();
        if (data == 0) {
            ZLOGE(LOG_LABEL, "data get by GetData() is invalid");
            break;
        }
        flat = reinterpret_cast<flat_binder_object *>(data + object[i]);
        if (flat->hdr.type == BINDER_TYPE_FD) {
            return true;
        }
    }

    return false;
}

bool MessageParcel::WriteInterfaceToken(std::u16string name)
{
    constexpr int strictModePolicy = 0x100;
    constexpr int workSource = 0;
    size_t rewindPos = GetWritePosition();
    if (!WriteInt32(strictModePolicy)) {
        return false;
    }

    if (!WriteInt32(workSource)) {
        if (!RewindWrite(rewindPos)) {
            FlushBuffer();
        }
        return false;
    }

    interfaceToken_ = name;
    return WriteString16(name);
}

std::u16string MessageParcel::ReadInterfaceToken()
{
    [[maybe_unused]] int32_t strictModePolicy = ReadInt32();
    [[maybe_unused]] int32_t workSource = ReadInt32();
    interfaceToken_ = ReadString16();
    return interfaceToken_;
}

std::u16string MessageParcel::GetInterfaceToken() const
{
    return interfaceToken_;
}

bool MessageParcel::WriteRawData(const void *data, size_t size)
{
    if (data == nullptr || size > MAX_RAWDATA_SIZE || size == 0) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LOG_LABEL, "data is null or size:%{public}zu not ok, time:%{public}" PRIu64, size, curTime);
        return false;
    }
    if (kernelMappedWrite_ != nullptr) {
        return false;
    }
    if (!WriteInt32(size)) {
        return false;
    }
    if (size <= MIN_RAWDATA_SIZE) {
        rawDataSize_ = size;
        return WriteUnpadBuffer(data, size);
    }
    int fd = AshmemCreate("Parcel RawData", size);
    if (fd < 0) {
        return false;
    }
    writeRawDataFd_ = fd;

    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        // Do not close fd here, which will be closed in MessageParcel's destructor.
        return false;
    }
    void *ptr = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        // Do not close fd here, which will be closed in MessageParcel's destructor.
        return false;
    }
    if (!WriteFileDescriptor(fd)) {
        // Do not close fd here, which will be closed in MessageParcel's destructor.
        ::munmap(ptr, size);
        return false;
    }
    if (memcpy_s(ptr, size, data, size) != EOK) {
        // Do not close fd here, which will be closed in MessageParcel's destructor.
        ::munmap(ptr, size);
        return false;
    }
    kernelMappedWrite_ = ptr;
    rawDataSize_ = size;
    return true;
}

bool MessageParcel::RestoreRawData(std::shared_ptr<char> rawData, size_t size)
{
    if (rawData_ != nullptr || rawData == nullptr) {
        return false;
    }
    ZLOGD(LOG_LABEL, "enter");
    rawData_ = rawData;
    rawDataSize_ = size;
    writeRawDataFd_ = 0;
    return true;
}

const void *MessageParcel::ReadRawData(size_t size)
{
    if (size == 0) {
        uint64_t curTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        ZLOGE(LOG_LABEL, "the parameter size is 0, time:%{public}" PRIu64, curTime);
        return nullptr;
    }
    size_t bufferSize =  static_cast<size_t>(ReadInt32());
    if (bufferSize != size) {
        ZLOGE(LOG_LABEL, "ReadRawData: the buffersize:%{public}zu not equal the parameter size:%{public}zu",
            bufferSize, size);
        return nullptr;
    }
    if (bufferSize <= MIN_RAWDATA_SIZE) {
        rawDataSize_ = size;
        return ReadUnpadBuffer(size);
    }

    /* if rawDataFd_ == 0 means rawData is received from remote */
    if (rawData_ != nullptr && writeRawDataFd_ == 0) {
        /* should read fd for move readCursor of parcel */
        if (ReadFileDescriptor()) {
            // do nothing
        }
        if (rawDataSize_ != size) {
            ZLOGE(LOG_LABEL, "rawData is received from remote, the rawDataSize:%{public}zu"
                " not equal size:%{public}zu", rawDataSize_, size);
            return nullptr;
        }
        return rawData_.get();
    }
    int fd = ReadFileDescriptor();
    if (fd < 0) {
        return nullptr;
    }
    readRawDataFd_ = fd;

    int ashmemSize = AshmemGetSize(fd);
    if (ashmemSize < 0 || size_t(ashmemSize) < size) {
        // Do not close fd here, which will be closed in MessageParcel's destructor.
        ZLOGE(LOG_LABEL, "ashmemSize:%{public}d less than size:%{public}zu",
            ashmemSize, size);
        return nullptr;
    }
    void *ptr = ::mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        // Do not close fd here, which will be closed in MessageParcel's destructor.
        return nullptr;
    }
    kernelMappedRead_ = ptr;
    rawDataSize_ = size;
    return ptr;
}

const void *MessageParcel::GetRawData() const
{
    if (rawData_ != nullptr) {
        return rawData_.get();
    }
    if (kernelMappedWrite_ != nullptr) {
        return kernelMappedWrite_;
    }
    if (kernelMappedRead_ != nullptr) {
        return kernelMappedRead_;
    }
    return nullptr;
}

size_t MessageParcel::GetRawDataSize() const
{
    return rawDataSize_;
}

size_t MessageParcel::GetRawDataCapacity() const
{
    return MAX_RAWDATA_SIZE;
}

void MessageParcel::WriteNoException()
{
    WriteInt32(0);
}

int32_t MessageParcel::ReadException()
{
    int32_t errorCode = ReadInt32();
    if (errorCode != 0) {
        ReadString16();
    }
    return errorCode;
}

bool MessageParcel::WriteAshmem(sptr<Ashmem> ashmem)
{
    int fd = ashmem->GetAshmemFd();
    int32_t size = ashmem->GetAshmemSize();
    if (fd < 0 || size <= 0) {
        return false;
    }
    if (!WriteFileDescriptor(fd) || !WriteInt32(size)) {
        return false;
    }
    return true;
}

sptr<Ashmem> MessageParcel::ReadAshmem()
{
    int fd = ReadFileDescriptor();
    if (fd < 0) {
        return nullptr;
    }

    int32_t size = ReadInt32();
    if (size <= 0) {
        ::close(fd);
        return nullptr;
    }
    return new (std::nothrow) Ashmem(fd, size);
}

bool MessageParcel::Append(MessageParcel &data)
{
    size_t dataSize = data.GetDataSize();
    if (dataSize == 0) {
        ZLOGI(LOG_LABEL, "no data to append");
        return true;
    }
    uintptr_t dataPtr = data.GetData();
    size_t writeCursorOld = this->GetWritePosition();
    if (!WriteBuffer(reinterpret_cast<void *>(dataPtr), dataSize)) {
        ZLOGE(LOG_LABEL, "failed to append data with writebuffer.");
        return false;
    }
    size_t objectSize = data.GetOffsetsSize();
    if (objectSize == 0) {
        return true;
    }
    binder_size_t objectOffsets = data.GetObjectOffsets();
    auto *newObjectOffsets = reinterpret_cast<binder_size_t *>(objectOffsets);
    for (size_t index = 0; index < objectSize; index++) {
        if (EnsureObjectsCapacity()) {
            size_t offset = writeCursorOld + newObjectOffsets[index];
            if (!WriteObjectOffset(offset)) {
                ZLOGE(LOG_LABEL, "failed to write object offset");
                return false;
            }
            flat_binder_object *flat = reinterpret_cast<flat_binder_object *>(this->GetData() + offset);
            if (flat == nullptr) {
                ZLOGE(LOG_LABEL, "flat binder object is nullptr");
                return false;
            }
            AcquireObject(flat, this);
        } else {
            ZLOGE(LOG_LABEL, "Failed to ensure parcel capacity");
            return false;
        }
    }
    return true;
}

void MessageParcel::PrintBuffer(const char *funcName, const size_t lineNum)
{
    if (funcName == nullptr) {
        ZLOGE(LOG_LABEL, "invalid param, funcName is null");
        return;
    }
    ZLOGI(LOG_LABEL, "[%{public}s %{public}zu %{public}u]: DataSize:%{public}zu, WP:%{public}zu, RP:%{public}zu",
        funcName, lineNum, ProcessSkeleton::ConvertAddr(this), GetDataSize(), GetWritePosition(), GetReadPosition());
    std::string format;
    size_t idx = 0;
    size_t size = GetOffsetsSize();
    auto objOffsets = reinterpret_cast<binder_size_t *>(GetObjectOffsets());
    while (idx < size) {
        format += std::to_string(objOffsets[idx]) + ',';
        ++idx;
    }
    ZLOGI(LOG_LABEL, "[%{public}s %{public}zu %{public}u]: ObjSize:%{public}zu, ObjOffsets:%{public}s",
        funcName, lineNum, ProcessSkeleton::ConvertAddr(this), size, format.c_str());

    format.clear();
    idx = 0;
    size = GetDataSize();
    auto data = reinterpret_cast<const uint8_t *>(GetData());
    while (idx < size) {
        format += std::to_string(data[idx]) + ',';
        ++idx;
    }
    ZLOGI(LOG_LABEL, "[%{public}s %{public}zu %{public}u]: data:%{public}s", funcName, lineNum,
        ProcessSkeleton::ConvertAddr(this), format.c_str());
}
} // namespace OHOS

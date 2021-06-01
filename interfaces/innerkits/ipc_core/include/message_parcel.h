/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_MESSAGE_PARCEL_H
#define OHOS_IPC_MESSAGE_PARCEL_H

#include <string>
#include "parcel.h"
#include "refbase.h"
#include <ashmem.h>

namespace OHOS {
class IRemoteObject;
class MessageParcel : public Parcel {
public:
    MessageParcel();
    ~MessageParcel();
    explicit MessageParcel(Allocator *allocator);
    bool WriteRemoteObject(const sptr<IRemoteObject> &object);
    sptr<IRemoteObject> ReadRemoteObject();
    bool WriteFileDescriptor(int fd);
    int ReadFileDescriptor();
    bool ContainFileDescriptors() const;
    bool WriteInterfaceToken(std::u16string name);
    std::u16string ReadInterfaceToken();
    bool WriteRawData(const void *data, size_t size);
    const void *ReadRawData(size_t size);
    bool RestoreRawData(std::shared_ptr<char> rawData, size_t size);
    const void *GetRawData() const;
    size_t GetRawDataSize() const;
    size_t GetRawDataCapacity() const;
    void WriteNoException();
    int32_t ReadException();
    bool WriteAshmem(sptr<Ashmem> ashmem);
    sptr<Ashmem> ReadAshmem();
    void ClearFileDescriptor();
    void SetClearFdFlag()
    {
        needCloseFd_ = true;
    };

private:
    static constexpr size_t MAX_RAWDATA_SIZE = 128 * 1024 * 1024; // 128M
    static constexpr size_t MIN_RAWDATA_SIZE = 32 * 1024;         // 32k
    bool needCloseFd_ = false;
    std::vector<sptr<Parcelable>> holders_;
    int writeRawDataFd_;
    int readRawDataFd_;
    void *kernelMappedWrite_;
    void *kernelMappedRead_;
    std::shared_ptr<char> rawData_;
    size_t rawDataSize_;
};
} // namespace OHOS
#endif // OHOS_IPC_MESSAGE_PARCEL_H

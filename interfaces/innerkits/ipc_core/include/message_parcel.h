/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include <ashmem.h>
#include "parcel.h"
#include "refbase.h"
#include <string>

namespace OHOS {
class IRemoteObject;
class MessageParcel : public Parcel {
public:
    MessageParcel();
    ~MessageParcel();
    explicit MessageParcel(Allocator *allocator);

    /**
     * @brief Serializes the remote object and writes it.
     * @param object Indicates the remote object to serialize.
     * @return Returns <b>true</b> if it is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    bool WriteRemoteObject(const sptr<IRemoteObject> &object);

    /**
     * @brief Reads a remote object.
     * @return Returns the IRemoteObject pointer object.
     * @since 9
     */
    sptr<IRemoteObject> ReadRemoteObject();

    /**
     * @brief Writes an file descriptor into the object.
     * @param fd Indicates file descriptor to write.
     * @return Returns <b>true</b> if the write succeeds; return <b>false</b> otherwise.
     * @since 9
     */
    bool WriteFileDescriptor(int fd);

    /**
     * @brief Reads an file descriptor from the object.
     * @return Returns the corresponding descriptor If the read is successful; returns {@code -1} otherwise.
     * @since 9
     */
    int ReadFileDescriptor();

    /**
     * @brief Check whether the file descriptor is included.
     * @return Returns <b>true</b> if checking for inclusion; returns <b>false</b> Otherwise.
     * @since 9
     */
    bool ContainFileDescriptors() const;

    /**
     * @brief Writes an interface token into the object.
     * @param name Indicates the string type name.
     * @return Returns <b>true</b> if the write succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool WriteInterfaceToken(std::u16string name);

    /**
     * @brief Reads an interface token from the object.
     * @return Returns a string value.
     * @since 9
     */
    std::u16string ReadInterfaceToken();

    /**
     * @brief Writes raw data to the object.
     * @param data Indicates the original data written.
     * @param size Indicates the size of the raw data sent.
     * @return Returns <b>true</b> if the write succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool WriteRawData(const void *data, size_t size);

    /**
     * @brief Reads raw data from the object.
     * @param size Indicates the size of the raw data to read.
     * @return void
     * @since 9
     */
    const void *ReadRawData(size_t size);

    /**
     * @brief Restore raw data.
     * @param rawData Indicates the original data to be recovered.
     * @param size Indicates the size of the raw data to read.
     * @return Returns <b>true</b> if recovery is successful; returns <b>false</b> Otherwise.
     * @since 9
     */
    bool RestoreRawData(std::shared_ptr<char> rawData, size_t size);

    /**
     * @brief Obtains raw data from the object.
     * @return void
     * @since 9
     */
    const void *GetRawData() const;

    /**
     * @brief Gets the raw data size.
     * @return Returns the resulting raw data size.
     * @since 9
     */
    size_t GetRawDataSize() const;

    /**
     * @brief Get raw data capacity.
     * @return Returns the maximum value of the raw data capacity.
     * @since 9
     */
    size_t GetRawDataCapacity() const;

    /**
     * @brief writes information to the object indicating that no exception occurred.
     * @return void
     * @since 9
     */
    void WriteNoException();

    /**
     * @brief Reads the exception information from the object.
     * @return Returns the read error code.
     * @since 9
     */
    int32_t ReadException();

    /**
     * @brief Writes an anonymous shared memory object to the object.
     * @param ashmem Indicates anonymous shared memory object to wrote.
     * @return Returns <b>true</b> if the write succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool WriteAshmem(sptr<Ashmem> ashmem);

    /**
     * @brief Reads the anonymous shared memory object from the object.
     * @return Returns anonymous share object obtained.
     * @since 9
     */
    sptr<Ashmem> ReadAshmem();

    /**
     * @brief Clear the file descriptor.
     * @return void
     * @since 9
     */
    void ClearFileDescriptor();

    /**
     * @brief Sets the Clear specified file descriptor flag.
     * @return void
     * @since 9
     */
    void SetClearFdFlag()
    {
        needCloseFd_ = true;
    };

    /**
     * @brief Append a MessageParcel object to the end of the current MessageParcel.
     * @param data Indicates the data to append.
     * @return Returns <b>true</b> if append succeeds; returns <b>false</b> Otherwise.
     * @since 9
     */
    bool Append(MessageParcel &data);

    /**
     * @brief Print the content in MessageParcel buffer.
     * @param funcName Indicates the invoke function name.
     * @param lineNum Indicates the invoke function line number.
     * @return void
     * @since 12
     */
    void PrintBuffer(const char *funcName, const size_t lineNum);

    /**
     * @brief Get the interface token string.
     * @return Returns a valid interface token string, if WriteInterfaceToken or ReadInterfaceToken is called;
     *         returns an empty string otherwise.
     * @since 12
     */
    std::u16string GetInterfaceToken() const;

private:
#ifndef CONFIG_IPC_SINGLE
    /**
     * @brief Write to the DBinder proxy object.
     * @param object Indicates an IRemoteObject type object.
     * @param handle Indicates the handle to write.
     * @param stubIndex Indicates the stub index to write to.
     * @return Returns <b>true</b> if the write succeeds; returns <b>false</b> otherwise.
     * @since 9
     */
    bool WriteDBinderProxy(const sptr<IRemoteObject> &object, uint32_t handle, uint64_t stubIndex);

    /**
     * @brief Update the DBinder object's offset.
     * @param offset Indicates the object offset.
     * @return Returns <b>true</b> if the update succeeds; returns <b>false</b> otherwise.
     * @since 12
     */
    bool UpdateDBinderDataOffset(size_t offset);
#endif

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
    std::u16string interfaceToken_;
};
} // namespace OHOS
#endif // OHOS_IPC_MESSAGE_PARCEL_H

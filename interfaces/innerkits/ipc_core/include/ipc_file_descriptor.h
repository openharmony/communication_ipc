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

#ifndef OHOS_IPC_IPC_FILE_DESCRIPTOR_H
#define OHOS_IPC_IPC_FILE_DESCRIPTOR_H

#include "parcel.h"

namespace OHOS {
class IPCFileDescriptor : public virtual Parcelable {
public:
    IPCFileDescriptor();
    explicit IPCFileDescriptor(int fd);
    ~IPCFileDescriptor();

    /**
     * @brief Marshal the object.
     * @param parcel Indicates the Parcel object to which the sequenceable object will be marshaled.
     * @return Returns <b>true</b> if the marshalling is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Marshal the object.
     * @param Parcel Indicates the Parcel object to which the sequenceable object will be marshaled.
     * @param object Indicates the IPCFileDescriptor pointer object.
     * @return Returns <b>true</b> if the marshalling is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    static bool Marshalling(Parcel &parcel, const sptr<IPCFileDescriptor> &object);

    /**
     * @brief Unmarshal the object.
     * @param Parcel Indicates the Parcel object to which the sequenceable object will be marshaled.
     * @return Returns <b>true</b> if the marshalling is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    static IPCFileDescriptor *Unmarshalling(Parcel &parcel);

    /**
     * @brief Gets the file descriptor.
     * @return Returns the file descriptor.
     * @since 9
     */
    int GetFd() const;

    /**
     * @brief Sets the file descriptor.
     * @param fd Indicates the file descriptor.
     * @return void
     * @since 9
     */
    void SetFd(int fd);

private:
    int fd_ = -1;
};
} // namespace OHOS
#endif // OHOS_IPC_IPC_FILE_DESCRIPTOR_H

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

#ifndef OHOS_IPC_IPC_FILE_DESCRIPTOR_H
#define OHOS_IPC_IPC_FILE_DESCRIPTOR_H

#include "parcel.h"

namespace OHOS {
class IPCFileDescriptor : public virtual Parcelable {
public:
    IPCFileDescriptor();
    explicit IPCFileDescriptor(int fd);
    ~IPCFileDescriptor();

    bool Marshalling(Parcel &parcel) const override;
    static bool Marshalling(Parcel &parcel, const sptr<IPCFileDescriptor> &object);
    static IPCFileDescriptor *Unmarshalling(Parcel &parcel);
    int GetFd() const;
    void SetFd(int fd);

private:
    int fd_ = -1;
};
} // namespace OHOS
#endif // OHOS_IPC_IPC_FILE_DESCRIPTOR_H

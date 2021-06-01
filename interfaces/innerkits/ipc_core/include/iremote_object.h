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

#ifndef OHOS_IPC_IREMOTE_OBJECT_H
#define OHOS_IPC_IREMOTE_OBJECT_H

#include <codecvt>
#include <locale>
#include <vector>
#include <string>
#include "ipc_types.h"
#include "message_parcel.h"
#include "message_option.h"

namespace OHOS {
class IRemoteBroker;
inline std::u16string to_utf16(const std::string &str)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.from_bytes(str);
}

class IRemoteObject : public virtual Parcelable, public virtual RefBase {
public:
    enum {
        IF_PROT_DEFAULT, /* Invoker family. */
        IF_PROT_BINDER = IF_PROT_DEFAULT,
        IF_PROT_DATABUS,
    };
    enum {
        DATABUS_TYPE,
    };
    class DeathRecipient : public RefBase {
    public:
        enum {
            ADD_DEATH_RECIPIENT,
            REMOVE_DEATH_RECIPIENT,
            NOTICE_DEATH_RECIPIENT,
            TEST_SERVICE_DEATH_RECIPIENT,
            TEST_DEVICE_DEATH_RECIPIENT,
        };
        virtual void OnRemoteDied(const wptr<IRemoteObject> &object) = 0;
    };

    virtual int32_t GetObjectRefCount() = 0;

    virtual int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) = 0;

    virtual bool IsProxyObject() const;

    virtual bool CheckObjectLegality() const;

    virtual bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) = 0;

    virtual bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) = 0;

    virtual bool Marshalling(Parcel &parcel) const override;

    static IRemoteObject *Unmarshalling(Parcel &parcel);

    static bool Marshalling(Parcel &parcel, const sptr<IRemoteObject> &object);

    virtual sptr<IRemoteBroker> AsInterface();

    virtual int Dump(int fd, const std::vector<std::u16string> &args) = 0;

    const std::u16string descriptor_;

    std::u16string GetObjectDescriptor() const;

protected:
    explicit IRemoteObject(std::u16string descriptor = nullptr);
};
} // namespace OHOS
#endif // OHOS_IPC_IREMOTE_OBJECT_H

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

#ifndef OHOS_IPC_IREMOTE_OBJECT_H
#define OHOS_IPC_IREMOTE_OBJECT_H

#include <codecvt>
#include <locale>
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
    /**
     * @brief Enumerates communication protocols.
     * @since 9
     */
    enum {
        IF_PROT_DEFAULT, /* Invoker family. */
        IF_PROT_BINDER = IF_PROT_DEFAULT,
        IF_PROT_DATABUS,
        IF_PROT_ERROR,
    };
    enum {
        DATABUS_TYPE,
    };
    class DeathRecipient : public virtual RefBase {
    public:
       /**
        * @brief Methods that enumerate death notifications.
        * @since 9
        */
        enum {
            ADD_DEATH_RECIPIENT,
            REMOVE_DEATH_RECIPIENT,
            NOTICE_DEATH_RECIPIENT,
            TEST_SERVICE_DEATH_RECIPIENT,
            TEST_DEVICE_DEATH_RECIPIENT,
        };

        /**
         * @brief Called to perform subsequent operations when a death notification of the remote object is received.
         * @param object Indicates the IRemoteObject pointer object.
         * @return void
         * @since 9
         */
        virtual void OnRemoteDied(const wptr<IRemoteObject> &object) = 0;
    };

    /**
     * @brief Obtains the object reference count.
     * @return Returns the resulting object reference count.
     * @since 9
     */
    virtual int32_t GetObjectRefCount() = 0;

    /**
     * @brief Sends message to the peer process in synchronous or asynchronous mode.
     * @param code Indicates the message code of the request.
     * @param data Indicates the object storing the data to be sent.
     * @param reply Indicates the object receiving the response data.
     * @param option Indicates a synchronous (default) or asynchronous request.
     * @return Returns the result of the send request.
     * @since 9
     */
    virtual int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) = 0;

    /**
     * @brief Determine whether it is a proxy object.
     * @return Returns <b>true</b> if as a proxy object; returns <b>false</b> otherwise.
     * @since 9
     */
    virtual bool IsProxyObject() const;

    /**
     * @brief Check the object is dead.
     * @return Returns <b>true</b> if the object has dead; returns <b>false</b> otherwise.
     * @since 9
     */
    virtual bool IsObjectDead() const;

    /**
     * @brief Obtains the interface descriptor.
     * @return Returns the resulting interface descriptor.
     * @since 9
     */
    virtual std::u16string GetInterfaceDescriptor();

    /**
     * @brief Check the legitimacy of the object.
     * @return Returns <b>true</b> if the identity is legal; returns <b>false</b> otherwise.
     * @since 9
     */
    virtual bool CheckObjectLegality() const;

    /**
     * @brief Add a callback used to receive notifications of the death of a remote object.
     * @return Returns <b>true</b> if the identity is legal; returns <b>false</b> otherwise.
     * @since 9
     */
    virtual bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) = 0;

    /**
     * @brief Remove a callback used to receive notifications of the death of a remote object.
     * @return Returns <b>true</b> if the identity is legal; returns <b>false</b> otherwise.
     * @since 9
     */
    virtual bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) = 0;

    /**
     * @brief Marshal this object.
     * @param parcel Indicates a marshaling parcel type object.
     * @return Returns <b>true</b> if the marshalling is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal this object.
     * @return Returns the IRemoteObject pointer object.
     * @since 9
     */
    static sptr<IRemoteObject> Unmarshalling(Parcel &parcel);

    /**
     * @brief Marshal this object.
     * @param parcel Indicates a marshaling parcel type object.
     * @param object Indicates an IRemoteObject pointer type object.
     * @return Returns <b>true</b> if the marshalling is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    static bool Marshalling(Parcel &parcel, const sptr<IRemoteObject> &object);

    /**
     * @brief Obtains the interface.
     * @return Returns an IRemoteBroker pointer object.
     * @since 9
     */
    virtual sptr<IRemoteBroker> AsInterface();

    /**
     * @brief Dump the contents.
     * @param fd Indicates the file descriptor.
     * @param args Indicates a vector containing u16string.
     * @return Returns {@link ERR_NONE} if the dump is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 9
     */
    virtual int Dump(int fd, const std::vector<std::u16string> &args) = 0;

    const std::u16string descriptor_;

    /**
     * @brief Obtains the object descriptor.
     * @return Returns the object descriptor.
     * @since 9
     */
    std::u16string GetObjectDescriptor() const;

protected:
    explicit IRemoteObject(std::u16string descriptor = nullptr);
    virtual ~IRemoteObject() = default;
};
} // namespace OHOS
#endif // OHOS_IPC_IREMOTE_OBJECT_H

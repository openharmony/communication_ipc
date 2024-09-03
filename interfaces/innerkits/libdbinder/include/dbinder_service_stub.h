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

#ifndef OHOS_IPC_SERVICES_DBINDER_DBINDER_STUB_H
#define OHOS_IPC_SERVICES_DBINDER_DBINDER_STUB_H

#include <string>
#include <parcel.h>
#include "ipc_object_stub.h"

namespace OHOS {
#ifdef BINDER_IPC_32BIT
typedef unsigned int binder_uintptr_t;
#else
typedef unsigned long long binder_uintptr_t;
#endif

class DBinderServiceStub : public IPCObjectStub {
public:
    explicit DBinderServiceStub(const std::string &serviceName, const std::string &deviceID,
        binder_uintptr_t binderObject);
    ~DBinderServiceStub();

    /**
     * @brief Serialize a specified DBinderServiceStub object.
     * @param parcel Indicates the object storing the data.
     * @param object Indicates the serialized object.
     * @return Returns <b>true</b> if serialized successfully; returns <b>false</b> otherwise.
     * @since 12
     */
    static bool Marshalling(Parcel &parcel, const sptr<IRemoteObject> &object);

    /**
     * @brief Serialize self.
     * @param parcel Indicates the object storing the data.
     * @return Returns <b>true</b> if serialized successfully; returns <b>false</b> otherwise.
     * @since 12
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Gets the process protocol.
     * @param code Indicates the message code of the request.
     * @param data Indicates the object storing the data to be sent.
     * @param reply Indicates the object receiving the response data.
     * @param option Indicates a synchronous (default) or asynchronous request.
     * @return Returns {@code 0} if valid notifications; returns an error code if the operation fails.
     * @since 9
     */
    int32_t ProcessProto(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    /**
     * @brief Response processing of the request.
     * @param code Indicates the service request code sent from the peer end.
     * @param data Indicates the  object sent from the peer end.
     * @param reply Indicates the response message object sent from the remote service.
     * @param options Indicates whether the operation is synchronous or asynchronous.
     * @return Returns {@code 0} if the operation succeeds; returns an error code if the operation fails.
     * @since 9
     */
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    /**
     * @brief Get and save the dbinder object data.
     * @param pid Indicates the sender pid.
     * @param uid Indicates the sender uid.
     * @return Returns {@link ERR_NONE} if the operation is successful; returns an error code
     * defined in {@link ipc_types.h} otherwise.
     * @since 12
     */
    int GetAndSaveDBinderData(pid_t pid, uid_t uid) override;

    /**
     * @brief Obtains the service name.
     * @return Returns the service name.
     * @since 9
     */
    const std::string &GetServiceName();

    /**
     * @brief Obtain the device ID.
     * @return Returns the device ID.
     * @since 9
     */
    const std::string &GetDeviceID();

    /**
     * @brief Obtain the binder object.
     * @return Returns the binder object.
     * @since 9
     */
    binder_uintptr_t GetBinderObject() const;

private:
    int32_t ProcessDeathRecipient(MessageParcel &data);
    int32_t AddDbinderDeathRecipient(MessageParcel &data);
    int32_t RemoveDbinderDeathRecipient(MessageParcel &data);
    bool CheckSessionObjectValidity();
    int SaveDBinderData(const std::string &localBusName);

    const std::string serviceName_;
    const std::string deviceID_;
    binder_uintptr_t binderObject_;
    std::unique_ptr<uint8_t[]> dbinderData_ {nullptr};
};
} // namespace OHOS
#endif // OHOS_IPC_SERVICES_DBINDER_DBINDER_STUB_H

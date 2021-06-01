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

#ifndef OHOS_IPC_IPC_OBJECT_PROXY_H
#define OHOS_IPC_IPC_OBJECT_PROXY_H

#include <mutex>
#include <vector>

#include "iremote_object.h"

namespace OHOS {
class IPCObjectProxy : public IRemoteObject {
public:
    explicit IPCObjectProxy(int handle, std::u16string descriptor = std::u16string(),
        int proto = IRemoteObject::IF_PROT_DEFAULT);
    ~IPCObjectProxy();

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &optionoption) override;

    bool IsProxyObject() const override
    {
        return true;
    };

    bool IsObjectDead() const;

    int32_t GetObjectRefCount() override;

    int Dump(int fd, const std::vector<std::u16string> &args) override;

    void OnFirstStrongRef(const void *objectId) override;

    void OnLastStrongRef(const void *objectId) override;

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override;

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override;

    void SendObituary();

    bool IsSubscribeDeathNotice() const
    {
        if (recipients_.empty()) {
            return false;
        }
        return true;
    };

    uint32_t GetHandle() const
    {
        return handle_;
    };

    int InvokeListenThread(MessageParcel &data, MessageParcel &reply);
    int32_t NoticeServiceDie();
    std::string GetPidAndUidInfo();

    std::string GetDataBusName();
    int GetProto() const;
    void WaitForInit();
    std::u16string GetInterfaceDescriptor();

private:
    void MarkObjectDied();
    int SendLocalRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &optionoption);
    int SendRequestInner(bool isLocal, uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

#ifndef CONFIG_IPC_SINGLE
    void SetProto(int proto);

    int UpdateProto();

    void ReleaseProto();

    void IncRefToRemote();

    int GetSessionFromDBinderService();

    bool AddDbinderDeathRecipient();

    bool RemoveDbinderDeathRecipient();

    void ReleaseDatabusProto();

    void ReleaseBinderProto();

    bool UpdateDatabusClientSession(int handle, MessageParcel &reply);

    bool CheckHaveSession(uint32_t &type);
#endif

private:
    std::mutex initMutex_;
    std::recursive_mutex mutex_;

    std::vector<sptr<DeathRecipient>> recipients_;
    const uint32_t handle_;
    int proto_;
    bool isFinishInit_;
    bool isRemoteDead_;
    std::u16string remoteDescriptor_;
};
} // namespace OHOS
#endif // OHOS_IPC_IPC_OBJECT_PROXY_H

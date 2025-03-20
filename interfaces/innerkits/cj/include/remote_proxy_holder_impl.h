/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef REMOTE_PROXY_HOLDER_IMPL_H
#define REMOTE_PROXY_HOLDER_IMPL_H

#include <set>

#include "ffi_remote_data.h"
#include "message_sequence_impl.h"
#include "iremote_object_impl.h"

namespace OHOS {
class CJDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CJDeathRecipient(int64_t funcId);

    void OnRemoteDied(const wptr<IRemoteObject>& object) override;

    bool Matches(int64_t funcId);

protected:
    virtual ~CJDeathRecipient() = default;

private:
    int64_t funcId_;
};

class CJDeathRecipientList : public RefBase {
public:
    CJDeathRecipientList();

    ~CJDeathRecipientList();

    bool Add(const sptr<CJDeathRecipient>& recipient);

    bool Remove(const sptr<CJDeathRecipient>& recipient);

    sptr<CJDeathRecipient> Find(int64_t funcId);

private:
    std::mutex mutex_;
    std::set<sptr<CJDeathRecipient>> set_;
};

class RemoteProxyHolderImpl : public CjIRemoteObjectImpl {
    DECL_TYPE(RemoteProxyHolderImpl, OHOS::FFI::FFIData)
public:
    RemoteProxyHolderImpl();
    ~RemoteProxyHolderImpl();
    sptr<CJDeathRecipientList> list_;
    sptr<IRemoteObject> object_;

    int32_t SendMessageRequest(uint32_t code, int64_t dataId, int64_t replyId, MessageOption option, int64_t funcId);
    char* GetDescriptor(int32_t* errCode);
    bool IsObjectDead();
    int32_t RegisterDeathRecipient(int64_t funcId, int32_t flag);
    int32_t UnregisterDeathRecipient(int64_t funcId, int32_t flag);
    bool IsProxyObject() override;
    sptr<IRemoteObject> GetRemoteObject() override;
};
} // namespace OHOS
#endif // REMOTE_PROXY_HOLDER_IMPL_H
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

#ifndef OHOS_IPC_IREMOTE_BROKER_H
#define OHOS_IPC_IREMOTE_BROKER_H

#include <unordered_map>
#include <functional>
#include "iremote_object.h"
#include "refbase.h"

namespace OHOS {
template <typename T> class BrokerCreator {
public:
    BrokerCreator() = default;
    ~BrokerCreator() = default;
    sptr<IRemoteBroker> operator () (const sptr<IRemoteObject> &object)
    {
        return static_cast<IRemoteBroker *>(new T(object));
    };
};

class IRemoteBroker : public virtual RefBase {
public:
    IRemoteBroker() = default;
    virtual ~IRemoteBroker() override = default;
    virtual sptr<IRemoteObject> AsObject() = 0;
    static inline sptr<IRemoteBroker> AsImplement(const sptr<IRemoteObject> &object)
    {
        return nullptr;
    }
};

#define DECLARE_INTERFACE_DESCRIPTOR(DESCRIPTOR)                         \
    static inline const std::u16string metaDescriptor_ = { DESCRIPTOR }; \
    static inline const std::u16string &GetDescriptor()                  \
    {                                                                    \
        return metaDescriptor_;                                          \
    }

class BrokerRegistration {
    using Constructor = std::function<sptr<IRemoteBroker>(const sptr<IRemoteObject> &object)>;

public:
    static BrokerRegistration &Get();
    bool Register(const std::u16string &descriptor, const Constructor &creator);
    void Unregister(const std::u16string &descriptor);
    sptr<IRemoteBroker> NewInstance(const std::u16string &descriptor, const sptr<IRemoteObject> &object);

protected:
    BrokerRegistration() = default;
    ~BrokerRegistration();

private:
    BrokerRegistration(const BrokerRegistration &) = delete;
    BrokerRegistration(BrokerRegistration &&) = delete;
    BrokerRegistration &operator = (const BrokerRegistration &) = delete;
    BrokerRegistration &operator = (BrokerRegistration &&) = delete;
    std::mutex creatorMutex_;
    std::unordered_map<std::u16string, Constructor> creators_;
};

template <typename T> class BrokerDelegator {
public:
    BrokerDelegator();
    ~BrokerDelegator();

private:
    BrokerDelegator(const BrokerDelegator &) = delete;
    BrokerDelegator(BrokerDelegator &&) = delete;
    BrokerDelegator &operator = (const BrokerDelegator &) = delete;
    BrokerDelegator &operator = (BrokerDelegator &&) = delete;
};

template <typename T> BrokerDelegator<T>::BrokerDelegator()
{
    const std::u16string descriptor = T::GetDescriptor();
    BrokerRegistration &registration = BrokerRegistration::Get();
    registration.Register(descriptor, BrokerCreator<T>());
}

template <typename T> BrokerDelegator<T>::~BrokerDelegator()
{
    const std::u16string descriptor = T::GetDescriptor();
    BrokerRegistration &registration = BrokerRegistration::Get();
    registration.Unregister(descriptor);
}

template <typename INTERFACE> inline sptr<INTERFACE> iface_cast(const sptr<IRemoteObject> &object)
{
    const std::u16string descriptor = INTERFACE::GetDescriptor();
    BrokerRegistration &registration = BrokerRegistration::Get();
    sptr<IRemoteBroker> broker = registration.NewInstance(descriptor, object);
    return static_cast<INTERFACE *>(broker.GetRefPtr());
}
} // namespace OHOS
#endif // OHOS_IPC_IREMOTE_BROKER_H

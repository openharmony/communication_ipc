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

#ifndef OHOS_IPC_IREMOTE_BROKER_H
#define OHOS_IPC_IREMOTE_BROKER_H

#include <unordered_map>
#include <functional>
#include <vector>
#include "iremote_object.h"
#include "refbase.h"

namespace OHOS {
template <typename T> class BrokerCreator {
public:
    BrokerCreator() = default;
    ~BrokerCreator() = default;
    sptr<IRemoteBroker> operator () (const sptr<IRemoteObject> &object)
    {
        T *proxy = new (std::nothrow) T(object);
        if (proxy != nullptr) {
            return static_cast<IRemoteBroker *>(proxy);
        }
        return nullptr;
    };
};

class IRemoteBroker : public virtual RefBase {
public:
    IRemoteBroker() = default;
    virtual ~IRemoteBroker() override = default;

    /**
     * @brief Obtains a proxy or remote object.
     * @return Returns the RemoteObject if the caller is a RemoteObject;
     * returns the IRemoteObject if the caller is a RemoteProxy object.
     * @since 9
     */
    virtual sptr<IRemoteObject> AsObject() = 0;
};

class BrokerDelegatorBase {
public:
    BrokerDelegatorBase() = default;
    virtual ~BrokerDelegatorBase() = default;

public:
    bool isSoUnloaded = false;
    std::u16string descriptor_;
};

#define DECLARE_INTERFACE_DESCRIPTOR(DESCRIPTOR)                         \
    static constexpr const char16_t *metaDescriptor_ = DESCRIPTOR;       \
    static inline const std::u16string GetDescriptor()                  \
    {                                                                    \
        return metaDescriptor_;                                          \
    }

class BrokerRegistration {
    using Constructor = std::function<sptr<IRemoteBroker>(const sptr<IRemoteObject> &object)>;

public:
    /**
     * @brief Get broker registered.
     * @return Returns the BrokerRegistration instance.
     * @since 9
     */
    static BrokerRegistration &Get();

    /**
     * @brief Register the broker.
     * @param descriptor Indicates a descriptor the type of string.
     * @param creator Indicates the constructor.
     * @param object Indicates an object of type BrokerDelegatorBase.
     * @return Returns <b>true</b> if registration is successful; returns <b>false</b> otherwise.
     * @since 9
     */
    bool Register(const std::u16string &descriptor, const Constructor &creator, const BrokerDelegatorBase *object);

    /**
     * @brief Deregister the broker.
     * @param descriptor Indicates a descriptor the type of string.
     * @return void
     * @since 9
     */
    void Unregister(const std::u16string &descriptor);

    /**
     * @brief Obtains the new instance object.
     * @param descriptor Indicates a descriptor the type of string.
     * @param object Indicates an IRemoteObject pointer object.
     * @return Returns an IRemoteBroker pointer object.
     * @since 9
     */
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
    std::vector<uintptr_t> objects_;
    std::atomic<bool> isUnloading = false;
};

template <typename T> class BrokerDelegator : public BrokerDelegatorBase {
public:
    BrokerDelegator();
    ~BrokerDelegator() override;

private:
    BrokerDelegator(const BrokerDelegator &) = delete;
    BrokerDelegator(BrokerDelegator &&) = delete;
    BrokerDelegator &operator = (const BrokerDelegator &) = delete;
    BrokerDelegator &operator = (BrokerDelegator &&) = delete;
    std::mutex regMutex_;
};

template <typename T> BrokerDelegator<T>::BrokerDelegator()
{
    std::lock_guard<std::mutex> lockGuard(regMutex_);
    const std::u16string descriptor = T::GetDescriptor();
    BrokerRegistration &registration = BrokerRegistration::Get();
    if (registration.Register(descriptor, BrokerCreator<T>(), this)) {
        descriptor_ = T::GetDescriptor();
    }
}

template <typename T> BrokerDelegator<T>::~BrokerDelegator()
{
    std::lock_guard<std::mutex> lockGuard(regMutex_);
    if (!isSoUnloaded && !descriptor_.empty()) {
        BrokerRegistration &registration = BrokerRegistration::Get();
        registration.Unregister(descriptor_);
    }
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

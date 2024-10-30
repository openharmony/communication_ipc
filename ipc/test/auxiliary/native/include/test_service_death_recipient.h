/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_TEST_SERVICE_DEATH_RECIPIENT_H
#define OHOS_TEST_SERVICE_DEATH_RECIPIENT_H

#include "test_service_base.h"

namespace OHOS {
class TestDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
    TestDeathRecipient();
    virtual ~TestDeathRecipient();
    static bool GotDeathRecipient();
    static bool gotDeathRecipient_;
private:
    static constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_ID_TEST, "TestDeathRecipient" };
};

} // namespace OHOS
#endif // OHOS_TEST_SERVICE_DEATH_RECIPIENT_H

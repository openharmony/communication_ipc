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

#include "stub_refcount_object.h"

namespace OHOS {
StubRefCountObject::StubRefCountObject(IRemoteObject *stub, int remotePid, const std::string &deviceId)
    : stub_(stub), remotePid_(remotePid), deviceId_(deviceId)
{
}

StubRefCountObject::~StubRefCountObject()
{
    stub_ = nullptr;
}

IRemoteObject *StubRefCountObject::GetStubObject() const
{
    return stub_;
}

int StubRefCountObject::GetRemotePid() const
{
    return remotePid_;
}

std::string StubRefCountObject::GetDeviceId() const
{
    return deviceId_;
}
} // namespace OHOS

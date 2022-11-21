/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_SESSION_IMPL_H
#define OHOS_MOCK_SESSION_IMPL_H

#include <string>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "Session.h"

using Communication::SoftBus::Session;

namespace OHOS {
class MockSessionImpl : public std::enable_shared_from_this<MockSessionImpl>, public Session {
public:
    MockSessionImpl() = default;
    ~MockSessionImpl() = default;
    MOCK_CONST_METHOD0(GetMySessionName, const std::string &());
    MOCK_CONST_METHOD0(GetPeerSessionName, const std::string &());
    MOCK_CONST_METHOD0(GetDeviceId, const std::string &());
    MOCK_CONST_METHOD0(GetPeerDeviceId, const std::string &());
    MOCK_CONST_METHOD0(GetChannelId, int64_t());
    MOCK_CONST_METHOD0(GetPeerUid, uid_t());
    MOCK_CONST_METHOD0(GetPeerPid, pid_t());
    MOCK_CONST_METHOD0(IsServerSide, bool());
    MOCK_CONST_METHOD2(SendBytes, int(const void *buf, ssize_t len));
    MOCK_CONST_METHOD0(GetSessionId, int());
    MOCK_METHOD1(SetSessionId, void(int sessionId));
    MOCK_METHOD1(SetMySessionName, void(const std::string &name));
    MOCK_METHOD1(SetPeerSessionName, void(const std::string &name));
    MOCK_METHOD1(SetPeerDeviceId, void(const std::string &name));
    MOCK_METHOD1(SetDeviceId, void(const std::string &name));
    MOCK_METHOD1(SetIsServer, void(bool isServer));
    MOCK_METHOD1(SetPeerUid, void(uid_t peerUid));
    MOCK_METHOD1(SetPeerPid, void(pid_t peerPid));
}; // namespace OHOS
}
#endif // OHOS_MOCK_SESSION_IMPL_H

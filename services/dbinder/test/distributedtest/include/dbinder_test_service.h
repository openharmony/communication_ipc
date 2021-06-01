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

#ifndef OHOS_DBINDER_TEST_SERVICE_H
#define OHOS_DBINDER_TEST_SERVICE_H

#include "dbinder_test_service_skeleton.h"
#include "hilog/log.h"

namespace OHOS {
class DBinderTestService : public DBinderTestServiceStub {
public:
    DBinderTestService() = default;
    virtual ~DBinderTestService();
    static int Instantiate();
    int ReverseInt(int data, int &rep) override;
    int ReverseIntDelay(int data, int &rep) override;
    int Delay(int data, int &rep) override;
    int PingService(std::u16string &serviceName) override;
    int TransProxyObject(int data, sptr<IRemoteObject> &transObject, int operation, int &rep,
        int &withdrawRes) override;
    int TransStubObject(int data, sptr<IRemoteObject> &transObject, int &rep, int &stubRep) override;
    int TransOversizedPkt(const std::string &dataStr, std::string &repStr) override;
    int ProxyTransRawData(int length) override;
    int StubTransRawData(int length) override;
#ifndef CONFIG_STANDARD_SYSTEM
    int GetChildId(uint64_t &rep) override;
#endif
    sptr<IRemoteObject> GetRemoteObject(int type) override;
    int FlushAsyncCommands(int count, int length) override;
    int GetRemoteDecTimes() override;
    void ClearRemoteDecTimes() override;

public:
    static std::mutex destructTimesMutex_;
    static int destructTimes_;
    sptr<IRemoteObject> object_;
};
} // namespace OHOS

#endif // OHOS_DBINDER_TEST_SERVICE_H

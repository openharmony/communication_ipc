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

#include "dbinderdatabusinvoker_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "dbinder_databus_invoker.h"
#include "sys_binder.h"

namespace OHOS {
    bool AcquireHandleTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        int32_t testHandle = *(reinterpret_cast<const int32_t*>(data));
        int ret = invoker.AcquireHandle(testHandle);
        if (ret == 0) {
            return false;
        }
        return true;
    }

    bool ReleaseHandleTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        int32_t testHandle = *(reinterpret_cast<const int32_t*>(data));
        int ret = invoker.ReleaseHandle(testHandle);
        if (ret == 0) {
            return false;
        }
        return true;
    }

    bool QueryClientSessionObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        int32_t testHandle = *(reinterpret_cast<const int32_t*>(data));
        std::shared_ptr<DBinderSessionObject> testPeer = nullptr;
        testPeer = invoker.QueryClientSessionObject(testHandle);
        if (testPeer == nullptr) {
            return false;
        }
        return true;
    }

    bool QueryServerSessionObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        int32_t testHandle = *(reinterpret_cast<const int32_t*>(data));
        std::shared_ptr<DBinderSessionObject> testPeer = nullptr;
        testPeer = invoker.QueryServerSessionObject(testHandle);
        if (testPeer == nullptr) {
            return false;
        }
        return true;
    }

    bool OnMessageAvailableTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(ssize_t)) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        std::shared_ptr<Session> session = nullptr;
        char *testData = nullptr;
        ssize_t testLen = *(reinterpret_cast<const ssize_t*>(data));
        invoker.OnMessageAvailable(session, testData, testLen);
        return true;
    }

    bool JoinThreadTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(bool)) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        bool initiative  = *(reinterpret_cast<const bool*>(data));
        invoker.JoinThread(initiative);
        return true;
    }

    bool StopWorkThreadTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        invoker.StopWorkThread();
        return true;
    }

    bool OnDatabusSessionClosedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        std::shared_ptr<Session> session = nullptr;
        if (invoker.OnDatabusSessionClosed(session) == false) {
            return false;
        }
        return true;
    }

    bool GetCallerPidTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        invoker.GetCallerPid();
        return true;
    }

    bool GetStatusTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        invoker.GetStatus();
        return true;
    }

    bool GetCallerUidTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        invoker.GetCallerUid();
        return true;
    }

    bool GetCallerTokenIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        invoker.GetCallerTokenID();
        return true;
    }

    bool GetFirstTokenIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        invoker.GetFirstTokenID();
        return true;
    }

    bool IsLocalCallingTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        if (invoker.IsLocalCalling() != false) {
            return false;
        }
        return true;
    }

    bool FlushCommandsTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        IRemoteObject *object = nullptr;
        if (invoker.FlushCommands(object) == 0) {
            return false;
        }
        return true;
    }

    bool ResetCallingIdentityTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        std::string identity = invoker.ResetCallingIdentity();
        if (identity.empty()) {
            return false;
        }
        return true;
    }

    bool TranslateProxyTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return false;
        }

        DBinderDatabusInvoker invoker;
        int32_t testHandle = *(reinterpret_cast<const int32_t*>(data));
        uint32_t flag = 0;
        if (invoker.TranslateProxy(testHandle, flag) == 0) {
            return false;
        }
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AcquireHandleTest(data, size);
    OHOS::ReleaseHandleTest(data, size);
    OHOS::QueryClientSessionObjectTest(data, size);
    OHOS::QueryServerSessionObjectTest(data, size);
    OHOS::OnMessageAvailableTest(data, size);
    OHOS::JoinThreadTest(data, size);
    OHOS::StopWorkThreadTest(data, size);
    OHOS::OnDatabusSessionClosedTest(data, size);
    OHOS::GetCallerPidTest(data, size);
    OHOS::GetStatusTest(data, size);
    OHOS::GetCallerUidTest(data, size);
    OHOS::GetCallerTokenIDTest(data, size);
    OHOS::GetFirstTokenIDTest(data, size);
    OHOS::IsLocalCallingTest(data, size);
    OHOS::FlushCommandsTest(data, size);
    OHOS::ResetCallingIdentityTest(data, size);
    OHOS::TranslateProxyTest(data, size);
    return 0;
}

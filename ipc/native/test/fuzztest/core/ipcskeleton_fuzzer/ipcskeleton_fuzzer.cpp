/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ipcskeleton_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "iremote_object.h"
#include "ipc_skeleton.h"

namespace OHOS {
    void SetMaxWorkThreadNumTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        int maxThreadNum = *(reinterpret_cast<const int32_t*>(data));
        IPCSkeleton::SetMaxWorkThreadNum(maxThreadNum);
    }

    void StopWorkThreadTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::StopWorkThread();
    }

    void GetCallingSidTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetCallingSid();
    }

    void GetCallingPidTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetCallingPid();
    }

    void GetCallingRealPidTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetCallingRealPid();
    }

    void GetCallingUidTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetCallingUid();
    }

    void GetCallingTokenIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton skeleton = IPCSkeleton::GetInstance();
        skeleton.GetCallingTokenID();
    }

    void GetFirstTokenIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton skeleton = IPCSkeleton::GetInstance();
        skeleton.GetFirstTokenID();
    }

    void GetFirstFullTokenIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetFirstFullTokenID();
    }

    void GetSelfTokenIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetSelfTokenID();
    }

    void GetLocalDeviceIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetLocalDeviceID();
    }

    void GetCallingDeviceIDTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetCallingDeviceID();
    }

    void IsLocalCallingTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::IsLocalCalling();
    }

    void GetInstanceTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetInstance();
    }

    void GetContextObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::GetContextObject();
    }

    void SetContextObjectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        sptr<IRemoteObject> object;
        IPCSkeleton::SetContextObject(object);
    }

    void FlushCommandsTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::FlushCommands(nullptr);
    }

    void ResetCallingIdentityTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        IPCSkeleton::ResetCallingIdentity();
    }

    void SetCallingIdentityTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }

        std::string identity = "identity";
        IPCSkeleton::SetCallingIdentity(identity);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetMaxWorkThreadNumTest(data, size);
    OHOS::StopWorkThreadTest(data, size);
    OHOS::GetCallingSidTest(data, size);
    OHOS::GetCallingPidTest(data, size);
    OHOS::GetCallingRealPidTest(data, size);
    OHOS::GetCallingUidTest(data, size);
    OHOS::GetCallingTokenIDTest(data, size);
    OHOS::GetFirstTokenIDTest(data, size);
    OHOS::GetFirstFullTokenIDTest(data, size);
    OHOS::GetSelfTokenIDTest(data, size);
    OHOS::GetLocalDeviceIDTest(data, size);
    OHOS::GetCallingDeviceIDTest(data, size);
    OHOS::IsLocalCallingTest(data, size);
    OHOS::GetInstanceTest(data, size);
    OHOS::GetContextObjectTest(data, size);
    OHOS::SetContextObjectTest(data, size);
    OHOS::FlushCommandsTest(data, size);
    OHOS::ResetCallingIdentityTest(data, size);
    OHOS::SetCallingIdentityTest(data, size);

    return 0;
}
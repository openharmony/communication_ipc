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

#include "ipcskeleton_fuzzer.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "message_parcel.h"

namespace OHOS {
void SetMaxWorkThreadNumTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }

    int maxThreadNum = *(reinterpret_cast<const int32_t*>(data));
    IPCSkeleton::SetMaxWorkThreadNum(maxThreadNum);
}

void SetCallingIdentityTest(const uint8_t *data, size_t size)
{
    std::string identity(reinterpret_cast<const char *>(data), size);
    IPCSkeleton::SetCallingIdentity(identity);
}

void SetContextObjectFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> iRemoteObject = parcel.ReadRemoteObject();

    IPCSkeleton::SetContextObject(iRemoteObject);
}

void FlushCommandsFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    sptr<IRemoteObject> iRemoteObject = parcel.ReadRemoteObject();

    IPCSkeleton::FlushCommands(iRemoteObject);
}

void EnableIPCThreadreClaimFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    bool enable = parcel.ReadBool();

    IPCSkeleton::EnableIPCThreadReclaim(enable);
}

void StopWorkThreadTest()
{
    IPCSkeleton::StopWorkThread();
}

void GetCallingSidTest()
{
    IPCSkeleton::GetCallingSid();
}

void GetCallingPidTest()
{
    IPCSkeleton::GetCallingPid();
}

void GetCallingRealPidTest()
{
    IPCSkeleton::GetCallingRealPid();
}

void GetCallingUidTest()
{
    IPCSkeleton::GetCallingUid();
}

void GetCallingTokenIDTest()
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    skeleton.GetCallingTokenID();
}

void GetFirstTokenIDTest()
{
    IPCSkeleton skeleton = IPCSkeleton::GetInstance();
    skeleton.GetFirstTokenID();
}

void GetFirstFullTokenIDTest()
{
    IPCSkeleton::GetFirstFullTokenID();
}

void GetSelfTokenIDTest()
{
    IPCSkeleton::GetSelfTokenID();
}

void GetLocalDeviceIDTest()
{
    IPCSkeleton::GetLocalDeviceID();
}

void GetCallingDeviceIDTest()
{
    IPCSkeleton::GetCallingDeviceID();
}

void IsLocalCallingTest()
{
    IPCSkeleton::IsLocalCalling();
}

void GetInstanceTest()
{
    IPCSkeleton::GetInstance();
}

void GetContextObjectTest()
{
    IPCSkeleton::GetContextObject();
}

void SetContextObjectTest()
{
    sptr<IRemoteObject> object;
    IPCSkeleton::SetContextObject(object);
}

void FlushCommandsTest()
{
    IPCSkeleton::FlushCommands(nullptr);
}

void ResetCallingIdentityTest()
{
    IPCSkeleton::ResetCallingIdentity();
}

void FuzzerTestInner1(const uint8_t* data, size_t size)
{
    OHOS::EnableIPCThreadreClaimFuzzTest(data, size);
    OHOS::StopWorkThreadTest();
    OHOS::GetCallingSidTest();
    OHOS::GetCallingPidTest();
    OHOS::GetCallingRealPidTest();
    OHOS::GetCallingUidTest();
    OHOS::GetCallingTokenIDTest();
    OHOS::GetFirstTokenIDTest();
    OHOS::GetFirstFullTokenIDTest();
    OHOS::GetSelfTokenIDTest();
    OHOS::GetLocalDeviceIDTest();
    OHOS::GetCallingDeviceIDTest();
    OHOS::IsLocalCallingTest();
    OHOS::GetInstanceTest();
    OHOS::GetContextObjectTest();
    OHOS::SetContextObjectTest();
    OHOS::FlushCommandsTest();
    OHOS::ResetCallingIdentityTest();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SetMaxWorkThreadNumTest(data, size);
    OHOS::SetCallingIdentityTest(data, size);
    OHOS::SetContextObjectFuzzTest(data, size);
    OHOS::FlushCommandsFuzzTest(data, size);
    OHOS::FuzzerTestInner1(data, size);
    return 0;
}

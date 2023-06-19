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

#include "ipcprocessskeleton_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <securec.h>
#include "iremote_object.h"
#include "ipc_process_skeleton.h"

namespace OHOS {
    bool AttachAppInfoToStubIndexTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint64_t)) {
            return false;
        }

        char tmp[DEVICE_ID_SIZE_MAX] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return false;
        }

        uint32_t pid = *(reinterpret_cast<const uint32_t*>(data));
        uint32_t uid = *(reinterpret_cast<const uint32_t*>(data));
        uint32_t tokenId = *(reinterpret_cast<const uint32_t*>(data));
        std::string deviceId = tmp;
        uint64_t stubIndex = *(reinterpret_cast<const uint64_t*>(data));
        uint32_t listenFd = *(reinterpret_cast<const uint32_t*>(data));
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

        bool ret = current->AttachAppInfoToStubIndex(pid, uid, tokenId,
        deviceId, stubIndex, listenFd);

        return ret;
    }

    bool AttachCommAuthInfoTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(uint32_t)) {
            return false;
        }

        char tmp[DEVICE_ID_SIZE_MAX] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return false;
        }

        sptr<IRemoteObject> remoteObj;
        IRemoteObject *stub = remoteObj.GetRefPtr();
        int pid = *(reinterpret_cast<const uint32_t*>(data));
        int uid = *(reinterpret_cast<const uint32_t*>(data));
        uint32_t tokenId = *(reinterpret_cast<const uint32_t*>(data));
        std::string deviceId = tmp;
        IPCProcessSkeleton *current = IPCProcessSkeleton::GetCurrent();

        bool ret = current->AttachCommAuthInfo(stub, pid, uid, tokenId,
        deviceId);

        return ret;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AttachAppInfoToStubIndexTest(data, size);
    OHOS::AttachCommAuthInfoTest(data, size);
    return 0;
}
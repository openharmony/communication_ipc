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

#include "attachbusnameobject_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include "dbinder_service.h"
#include "ipc_object_proxy.h"

namespace OHOS {

    void AttachBusNameObjectTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        IPCObjectProxy *callbackProxy = nullptr;
        char tmp[SESSION_NAME_SIZE_MAX] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return;
        }
        std::string sessionName = tmp;
        sptr<DBinderService> dBinderService = DBinderService::GetInstance();
        if (dBinderService == nullptr) {
            return;
        }
        if (!dBinderService->AttachBusNameObject(callbackProxy, sessionName)) {
            return;
        }
        return;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AttachBusNameObjectTest(data, size);
    return 0;
}


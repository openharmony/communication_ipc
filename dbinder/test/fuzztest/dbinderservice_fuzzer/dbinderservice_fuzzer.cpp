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

#include "dbinderservice_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "dbinder_service.h"
#include "dbinder_service_stub.h"
#include "string_ex.h"

namespace OHOS {
    void OnRemoteMessageTaskTest(const uint8_t* data, size_t size)
    {
        #define VERSION_NUM 1
        #define MESSAGE_INVALID 5
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        OHOS::DBinderService dBinderService;
        std::shared_ptr<struct DHandleEntryTxRx> handleEntry = std::make_shared<struct DHandleEntryTxRx>();
        handleEntry->head.len = sizeof(DHandleEntryTxRx);
        handleEntry->head.version = VERSION_NUM;
        handleEntry->dBinderCode = MESSAGE_INVALID;

        dBinderService.OnRemoteMessageTask(handleEntry);
    }
    
    void QuerySessionObjectTest(const uint8_t* data, size_t size)
    {
        #define INVALID 0
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        OHOS::DBinderService dBinderService;
        dBinderService.QuerySessionObject(INVALID);
    }

    void RegisterRemoteProxy1Test(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        OHOS::DBinderService dBinderService;
        std::string sessionNameTmp(reinterpret_cast<const char*>(data), size);
        std::u16string serviceName = Str8ToStr16(sessionNameTmp);
        sptr<IRemoteObject> binderObject = NULL;
        dBinderService.RegisterRemoteProxy(serviceName, binderObject);
    }

    void RegisterRemoteProxy2Test(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        OHOS::DBinderService dBinderService;
        std::string sessionNameTmp(reinterpret_cast<const char*>(data), size);
        std::u16string serviceName = Str8ToStr16(sessionNameTmp);
        int32_t abilityId = *(reinterpret_cast<const int32_t*>(data));
        dBinderService.RegisterRemoteProxy(serviceName, abilityId);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::OnRemoteMessageTaskTest(data, size);
    OHOS::QuerySessionObjectTest(data, size);
    OHOS::RegisterRemoteProxy1Test(data, size);
    OHOS::RegisterRemoteProxy2Test(data, size);
    return 0;
}


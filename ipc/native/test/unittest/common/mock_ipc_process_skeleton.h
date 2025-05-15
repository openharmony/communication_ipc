/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_IPC_PROCESS_SKELETON_H
#define OHOS_MOCK_IPC_PROCESS_SKELETON_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ipc_process_skeleton.h"

namespace OHOS {
class MockIPCProcessSkeleton : public IPCProcessSkeleton {
public:
    MockIPCProcessSkeleton() {
        SetMaxWorkThread(DEFAULT_WORK_THREAD_NUM);
    }
    MOCK_METHOD0(GetCurrent, IPCProcessSkeleton* ());
    MOCK_METHOD2(FindOrNewObject, sptr<IRemoteObject>(
        int handle, const dbinder_negotiation_data *data));
};
} // namespace OHOS
#endif // OHOS_MOCK_IPC_PROCESS_SKELETON_H

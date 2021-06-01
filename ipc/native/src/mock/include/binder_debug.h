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

#ifndef OHOS_IPC_BINDER_DEBUG_H
#define OHOS_IPC_BINDER_DEBUG_H

#include "ipc_debug.h"

namespace OHOS {
class BinderDebug : public ErrorBase {
public:
    BinderDebug() = default;
    ~BinderDebug() = default;
    static const std::string &ToString(int value);
    virtual ErrorMap &GetErrorMap() override;
};
} // namespace OHOS
#endif // OHOS_IPC_BINDER_DEBUG_H

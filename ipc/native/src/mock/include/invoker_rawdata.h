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

#ifndef OHOS_IPC_INVOKER_RAWDATA_H
#define OHOS_IPC_INVOKER_RAWDATA_H

#include <unistd.h>
#include <memory>
#include <sys/types.h>
#include <cinttypes>

#include "nocopyable.h"

namespace OHOS {
class InvokerRawData {
public:
    DISALLOW_COPY_AND_MOVE(InvokerRawData);
    explicit InvokerRawData(size_t size);
    ~InvokerRawData();
    std::shared_ptr<char> GetData() const;
    size_t GetSize() const;

private:
    std::shared_ptr<char> data_;
    size_t size_;
};
} // namespace OHOS
#endif // OHOS_IPC_INVOKER_RAWDATA_H
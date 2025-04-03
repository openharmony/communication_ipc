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

#include "invoker_rawdata.h"

#include "memory"
#include "new"
#include "ipc_debug.h"
#include "log_tags.h"

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_RPC_DBINDER_INVOKER, "InvokerRawData" };
static constexpr size_t MAX_RAWDATA_SIZE = 128 * 1024 * 1024; // 128M

InvokerRawData::InvokerRawData(size_t size)
{
    if (size == 0 || size > MAX_RAWDATA_SIZE) {
        ZLOGE(LOG_LABEL, "size:%{public}zu not ok", size);
        return;
    }
    /* size is guaranteed by caller, in MessageParcel max size is 1G */
    data_.reset(reinterpret_cast<char *>(::operator new(size)));
    size_ = size;
}

InvokerRawData::~InvokerRawData()
{
    data_ = nullptr;
}

std::shared_ptr<char> InvokerRawData::GetData() const
{
    return data_;
}

size_t InvokerRawData::GetSize() const
{
    return size_;
}
} // namespace OHOS
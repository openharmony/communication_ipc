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

namespace OHOS {
InvokerRawData::InvokerRawData(size_t size)
{
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
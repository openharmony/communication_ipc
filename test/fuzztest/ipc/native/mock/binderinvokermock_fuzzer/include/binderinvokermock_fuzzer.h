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
#ifndef BINDERINVOKERMOCK_FUZZER_H
#define BINDERINVOKERMOCK_FUZZER_H

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "binder_connector.h"
#include "binder_invoker.h"
#include "ipc_object_stub.h"
#include "ipc_process_skeleton.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
static const size_t MAX_STR_LEN = 100;
static const size_t MIN_BYTE_SIZE = 1;
static const size_t MAX_BYTE_SIZE = 50;
} // namespace OHOS

#define FUZZ_PROJECT_NAME "binderinvokermock_fuzzer"

#endif
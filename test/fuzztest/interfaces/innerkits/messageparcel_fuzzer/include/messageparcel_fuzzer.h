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

#ifndef MESSAGEPARCEL_FUZZER_H
#define MESSAGEPARCEL_FUZZER_H

#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "message_parcel.cpp"
#include "message_parcel.h"
#include "sys_binder.h"
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>

static constexpr size_t MAX_STR_LEN = 100;
static constexpr size_t MIN_BYTE_SIZE = 1;
static constexpr size_t MAX_BYTE_SIZE = 50;
static const std::vector<int> type {
    BINDER_TYPE_BINDER,
    BINDER_TYPE_WEAK_BINDER,
    BINDER_TYPE_HANDLE,
    BINDER_TYPE_WEAK_HANDLE,
    BINDER_TYPE_FD,
    BINDER_TYPE_FDA,
    BINDER_TYPE_PTR
};

#define FUZZ_PROJECT_NAME "messageparcel_fuzzer"

#endif // MESSAGEPARCEL_FUZZER_H
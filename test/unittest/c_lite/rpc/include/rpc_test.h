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

#ifndef OHOS_RPC_TEST_H
#define OHOS_RPC_TEST_H

#include <stdint.h>

constexpr int32_t SAID = 16;
constexpr int32_t INVALID_SAID = -1;
constexpr int32_t INVALID_HANDLE = -1;
constexpr int32_t IPC_LENGTH = 128;
constexpr int32_t NUMBER_A = 12;
constexpr int32_t NUMBER_B = 17;
constexpr int32_t NUMBER_ZERO = 0;
constexpr int32_t OP_ADD = 1;
constexpr int32_t OP_SUB = 2;
constexpr int32_t OP_MULTI = 3;
constexpr int32_t OP_DIVISION = 4;
constexpr int32_t OP_SERIALIZER = 5;
constexpr int32_t OP_INVALID = 1024;
constexpr int32_t GET_SYSTEM_ABILITY_TRANSACTION = 1;
constexpr int32_t ADD_SYSTEM_ABILITY_TRANSACTION = 2;
constexpr int32_t GET_REMOTE_SYSTEM_ABILITY_TRANSACTION = 3;
constexpr int32_t ADD_REMOTE_SYSTEM_ABILITY_TRANSACTION = 4;

#endif // OHOS_RPC_TEST_H
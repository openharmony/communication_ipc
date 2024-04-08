/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef IPC_RUST_CXX_SKELETON_H
#define IPC_RUST_CXX_SKELETON_H

#include "cxx.h"
#include "ipc_skeleton.h"
#include "remote_object_wrapper.h"

namespace OHOS {
namespace IpcRust {
bool SetMaxWorkThreadNum(int maxThreadNum);

void JoinWorkThread();

void StopWorkThread();

uint64_t GetCallingPid();

uint64_t GetCallingRealPid();

uint64_t GetCallingUid();

uint32_t GetCallingTokenID();

uint64_t GetCallingFullTokenID();

uint32_t GetFirstTokenID();

uint64_t GetFirstFullTokenID();

uint64_t GetSelfTokenID();

rust::string GetLocalDeviceID();

rust::string GetCallingDeviceID();

bool IsLocalCalling();

std::unique_ptr<IRemoteObjectWrapper> GetContextObject();

int FlushCommands(IRemoteObjectWrapper &object);

rust::string ResetCallingIdentity();

bool SetCallingIdentity(rust::str identity);

bool IsHandlingTransaction();

} // namespace IpcRust
} // namespace OHOS

#endif
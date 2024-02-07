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

#ifndef OHOS_IPC_DBINDER_SOFTBUS_ADAPTOR_H
#define OHOS_IPC_DBINDER_SOFTBUS_ADAPTOR_H
#include <memory>
#include <string>

#include "ISessionService.h"

using Communication::SoftBus::ISessionService;

std::shared_ptr<ISessionService> GetSessionService() asm("GetSessionService");
std::string GetLocalDeviceId(const char *pkgName) asm("GetLocalDeviceId");

#endif // OHOS_IPC_DBINDER_SOFTBUS_ADAPTOR_H
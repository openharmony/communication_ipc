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

#ifndef OHOS_IPC_TEST_SMALL_SERVER_BUSINESS_IMPL_H
#define OHOS_IPC_TEST_SMALL_SERVER_BUSINESS_IMPL_H

#include "iproxy_client.h"
#include "iproxy_server.h"
#include "serializer.h"

int32_t DispatchInvoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply);

#endif // OHOS_IPC_TEST_SMALL_SERVER_BUSINESS_IMPL_H
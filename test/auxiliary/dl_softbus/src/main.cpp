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

#include <iostream>
#include <string>

#include "dbinder_softbus_client.h"
#include "ipc_skeleton.h"

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
    std::string str;
    std::cout << "Please enter a string to start linking dynamic libraries." << std::endl;

    std::cin >> str;
    std::cout << str << std::endl;

    std::string pkgName = "dbinderService";
    std::string networkId;
    (void)OHOS::DBinderSoftbusClient::GetInstance().GetLocalNodeDeviceId(pkgName.c_str(), networkId);

    std::cout << "Please enter a string to exit the program." << std::endl;
    std::cin >> str;
    std::cout << str << std::endl;

    return 0;
}
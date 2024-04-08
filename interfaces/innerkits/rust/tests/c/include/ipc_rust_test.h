/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IPC_RUST_TEST_H
#define IPC_RUST_TEST_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "ipc_types.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "refbase.h"

namespace OHOS {

struct CStringWrapper {
public:
    CStringWrapper(std::string *);
    char *raw;
    size_t len;
};

extern "C" {
MessageParcel *GetTestMessageParcel();
MessageParcel *ReadAndWrite(MessageParcel &data);
CStringWrapper *GetCallingDeviceID();
uint64_t GetCallingFullTokenID();
uint64_t GetCallingPid();
uint64_t GetCallingRealPid();
uint32_t GetCallingTokenID();
uint64_t GetCallingUid();
uint64_t GetFirstFullTokenID();
uint32_t GetFirstTokenID();
uint64_t SelfTokenID();
bool IsLocalCalling();
CStringWrapper *LocalDeviceID();
CStringWrapper *ResetCallingIdentity();
};

struct RemoteServiceStub : public IPCObjectStub {
public:
    RemoteServiceStub();
    ~RemoteServiceStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int Dump(int fd, const std::vector<std::u16string> &args) override;
};

} // namespace OHOS

#endif
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NAPI_IPC_OHOS_REMOTE_OBJECT_INTERNAL_H
#define NAPI_IPC_OHOS_REMOTE_OBJECT_INTERNAL_H

#include <thread>

#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "message_option.h"
#include "napi/native_api.h"
#include "napi_remote_object.h"

namespace OHOS {
struct ThreadLockInfo {
    std::mutex mutex;
    std::condition_variable condition;
    bool ready = false;
};

struct CallbackParam {
    napi_env env;
    napi_ref thisVarRef;
    uint32_t code;
    MessageParcel *data;
    MessageParcel *reply;
    MessageOption *option;
    CallingInfo callingInfo;
    ThreadLockInfo *lockInfo;
    int result;
};

struct OperateJsRefParam {
    napi_env env;
    napi_ref thisVarRef;
    ThreadLockInfo *lockInfo;
};

class NAPIRemoteObject : public IPCObjectStub {
public:
    NAPIRemoteObject(std::thread::id jsThreadId, napi_env env, napi_ref jsObjectRef, const std::u16string &descriptor);

    ~NAPIRemoteObject() override;

    bool CheckObjectLegality() const override;

    int GetObjectType() const override;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    napi_ref GetJsObjectRef() const;

    void ResetJsEnv();
private:
    napi_env env_ = nullptr;
    std::thread::id jsThreadId_;
    static napi_value ThenCallback(napi_env env, napi_callback_info info);
    static napi_value CatchCallback(napi_env env, napi_callback_info info);
    napi_ref thisVarRef_ = nullptr;
    int OnJsRemoteRequest(CallbackParam *jsParam);
};

struct SendRequestParam {
    sptr<IRemoteObject> target;
    uint32_t code;
    std::shared_ptr<MessageParcel> data;
    std::shared_ptr<MessageParcel> reply;
    MessageOption &option;
    napi_async_work asyncWork;
    napi_deferred deferred;
    int errCode;
    napi_ref jsCodeRef;
    napi_ref jsDataRef;
    napi_ref jsReplyRef;
    napi_ref jsOptionRef;
    napi_ref callback;
    napi_env env;
    std::string traceValue;
    int32_t traceId;
};

napi_value MakeSendRequestResult(SendRequestParam *param);
} // namespace OHOS
#endif // NAPI_IPC_OHOS_REMOTE_OBJECT_H

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

#include "foo_service.h"
#include "ipc_debug.h"
#include "ipc_types.h"

namespace OHOS {
std::mutex FooStub::decTimeMutex_;
int FooStub::decTimes_ = 0;

int FooStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    int result = ERR_NONE;

    switch (code) {
        case GET_FOO_NAME: {
            ZLOGI(LABEL, "%{public}s:called\n", __func__);
            reply.WriteString(GetFooName());
            break;
        }
        case SEND_ASYNC_REPLY: {
            int32_t replyData = data.ReadInt32();
            SendAsyncReply(replyData);
            break;
        }
        case SEND_WRONG_REPLY: {
            return TestNestingSend(data.ReadInt32());
        }
        default:
            result = ERR_TRANSACTION_FAILED;
            break;
    }

    return result;
}

std::string FooStub::GetFooName()
{
    return "ReallFoo";
}

int FooStub::WaitForAsyncReply(int timeout)
{
    asyncReply_ = 0;
    std::unique_lock<std::mutex> lck(mutex_);
    cv_.wait_for(lck, std::chrono::milliseconds(timeout), [&]() {
        return asyncReply_ != 0;
    });
    return asyncReply_;
}

void FooStub::SendAsyncReply(int &replyValue)
{
    std::unique_lock<std::mutex> lck(mutex_);
    asyncReply_ = replyValue;
    cv_.notify_all();
}

FooStub::~FooStub()
{
    std::unique_lock<std::mutex> lck(decTimeMutex_);
    decTimes_++;
}

void FooStub::CleanDecTimes()
{
    std::unique_lock<std::mutex> lck(decTimeMutex_);
    decTimes_ = 0;
}

int FooStub::GetDecTimes()
{
    std::unique_lock<std::mutex> lck(decTimeMutex_);
    return decTimes_;
}

int FooStub::TestNestingSend(int sendCode)
{
    return sendCode;
}
FooProxy::FooProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IFoo>(impl)
{
}

std::string FooProxy::GetFooName()
{
    ZLOGI(LABEL, "%{public}s:called\n", __func__);
    MessageParcel data, reply;
    MessageOption option;
    Remote()->SendRequest(GET_FOO_NAME, data, reply, option);
    return reply.ReadString();
}

void FooProxy::SendAsyncReply(int &replyValue)
{
    ZLOGI(LABEL, "%{public}s:called\n", __func__);
    MessageParcel data, reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    data.WriteInt32(replyValue);
    Remote()->SendRequest(SEND_ASYNC_REPLY, data, reply, option);
}

int FooProxy::TestNestingSend(int sendCode)
{
    MessageOption option;
    MessageParcel dataParcel, replyParcel;
    if (!dataParcel.WriteInt32(sendCode)) {
        return -1;
    }
    int error = Remote()->SendRequest(SEND_WRONG_REPLY, dataParcel, replyParcel, option);
    ZLOGE(LABEL, "send foo result = %{public}d", error);
    return error;
}
} // namespace OHOS
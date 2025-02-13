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

#include "napi_remote_object_holder.h"

#include <uv.h>
#include <sstream>
#include <string_ex.h>
#ifdef HIVIEWDFX_BACKTRACE_SUPPORT
#include "backtrace_local.h"
#endif
#ifdef FFRT_SUPPORT
#include "ffrt.h"
#endif
#include "ipc_debug.h"
#include "ipc_thread_skeleton.h"
#include "log_tags.h"
#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"
namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, LOG_ID_IPC_NAPI, "napi_remoteObject_holder" };

static void OnEnvCleanUp(void *data)
{
    if (data == nullptr) {
        ZLOGE(LOG_LABEL, "data is null");
        return;
    }
    NAPIRemoteObjectHolder *holder = reinterpret_cast<NAPIRemoteObjectHolder *>(data);
    // js env has been destrcted, clear saved env info, and check befor use it
    holder->CleanJsEnv();
}

NAPIRemoteObjectHolder::NAPIRemoteObjectHolder(napi_env env, const std::u16string &descriptor, napi_value thisVar)
    : env_(env), descriptor_(descriptor), sptrCachedObject_(nullptr), wptrCachedObject_(nullptr),
      localInterfaceRef_(nullptr), attachCount_(1), jsObjectRef_(nullptr)
{
    jsThreadId_ = std::this_thread::get_id();
    DetectCreatedInIPCThread();
    // create weak ref, need call napi_delete_reference to release memory,
    // increase ref count when the JS object will transfer to another thread or process.
    napi_create_reference(env, thisVar, 0, &jsObjectRef_);

    // register listener for env destruction
    napi_status status = napi_add_env_cleanup_hook(env, OnEnvCleanUp, this);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "add cleanup hook failed");
    }
}

void NAPIRemoteObjectHolder::DeleteJsObjectRefInUvWork()
{
    if (env_ == nullptr) {
        ZLOGE(LOG_LABEL, "js env has been destructed");
        return;
    }
    OperateJsRefParam *param = new (std::nothrow) OperateJsRefParam {
        .env = env_,
        .thisVarRef = jsObjectRef_
    };
    NAPI_ASSERT_RETURN_VOID(env_, param != nullptr, "new OperateJsRefParam failed");

    auto task = [param]() {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(param->env, &scope);
        napi_status napiStatus = napi_delete_reference(param->env, param->thisVarRef);
        if (napiStatus != napi_ok) {
            ZLOGE(LOG_LABEL, "failed to delete ref");
        }
        napi_close_handle_scope(param->env, scope);
        delete param;
    };
    napi_status sendRet = napi_send_event(env_, task, napi_eprio_high);
    if (sendRet != napi_ok) {
        ZLOGE(LOG_LABEL, "napi_send_event failed, ret:%{public}d", sendRet);
        delete param;
    }
}

NAPIRemoteObjectHolder::~NAPIRemoteObjectHolder()
{
    if (env_ == nullptr) {
        ZLOGE(LOG_LABEL, "js env has been destructed");
        return;
    }

    napi_status status = napi_remove_env_cleanup_hook(env_, OnEnvCleanUp, this);
    if (status != napi_ok) {
        ZLOGE(LOG_LABEL, "remove cleanup hook failed");
    }

    if (localInterfaceRef_ != nullptr) {
        status = napi_delete_reference(env_, localInterfaceRef_);
        if (status != napi_ok) {
            ZLOGE(LOG_LABEL, "failed to delete ref");
        }
    }

    if (jsObjectRef_ != nullptr) {
        if (jsThreadId_ == std::this_thread::get_id()) {
            status = napi_delete_reference(env_, jsObjectRef_);
            if (status != napi_ok) {
                ZLOGE(LOG_LABEL, "failed to delete ref");
            }
        } else {
            DeleteJsObjectRefInUvWork();
        }
    }
}

sptr<IRemoteObject> NAPIRemoteObjectHolder::Get()
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    // grab an strong reference to the object,
    // so it will not be freed util this reference released.
    if (sptrCachedObject_ != nullptr) {
        return sptrCachedObject_;
    }

    sptr<IRemoteObject> tmp = wptrCachedObject_.promote();
    if (tmp == nullptr && env_ != nullptr) {
        tmp = new (std::nothrow) NAPIRemoteObject(jsThreadId_, env_, jsObjectRef_, descriptor_);
        if (tmp == nullptr) {
            ZLOGE(LOG_LABEL, "new NAPIRemoteObject failed");
            return nullptr;
        }
        wptrCachedObject_ = tmp;
    }
    return tmp;
}

void NAPIRemoteObjectHolder::Set(sptr<IRemoteObject> object)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    IPCObjectStub *tmp = static_cast<IPCObjectStub *>(object.GetRefPtr());
    if (tmp->GetObjectType() == IPCObjectStub::OBJECT_TYPE_JAVASCRIPT) {
        wptrCachedObject_ = object;
    } else {
        sptrCachedObject_ = object;
    }
}

napi_ref NAPIRemoteObjectHolder::GetJsObjectRef() const
{
    return jsObjectRef_;
}

napi_env NAPIRemoteObjectHolder::GetJsObjectEnv() const
{
    return env_;
}

void NAPIRemoteObjectHolder::CleanJsEnv()
{
    env_ = nullptr;
    jsObjectRef_ = nullptr;
    sptr<IRemoteObject> tmp = wptrCachedObject_.promote();
    if (tmp != nullptr) {
        NAPIRemoteObject *object = static_cast<NAPIRemoteObject *>(tmp.GetRefPtr());
        ZLOGI(LOG_LABEL, "reset env and napi_ref");
        object->ResetJsEnv();
    }
}

void NAPIRemoteObjectHolder::attachLocalInterface(napi_value localInterface, std::string &descriptor)
{
    if (env_ == nullptr) {
        ZLOGE(LOG_LABEL, "Js env has been destructed");
        return;
    }
    if (localInterfaceRef_ != nullptr) {
        napi_delete_reference(env_, localInterfaceRef_);
    }
    napi_create_reference(env_, localInterface, 0, &localInterfaceRef_);
    descriptor_ = Str8ToStr16(descriptor);
}

napi_value NAPIRemoteObjectHolder::queryLocalInterface(std::string &descriptor)
{
    if (env_ == nullptr) {
        ZLOGE(LOG_LABEL, "Js env has been destructed");
        return nullptr;
    }
    if (!descriptor_.empty() && strcmp(Str16ToStr8(descriptor_).c_str(), descriptor.c_str()) == 0) {
        napi_value ret = nullptr;
        napi_get_reference_value(env_, localInterfaceRef_, &ret);
        return ret;
    }
    napi_value result = nullptr;
    napi_get_null(env_, &result);
    return result;
}

void NAPIRemoteObjectHolder::DetectCreatedInIPCThread()
{
    if (IPCThreadSkeleton::GetThreadType() == ThreadType::IPC_THREAD && descriptor_.length() > 0 &&
        descriptor_.find(u"ServiceCallbackStubImpl") != std::string::npos) {
#ifdef HIVIEWDFX_BACKTRACE_SUPPORT
        std::string backtrace;
        if (!HiviewDFX::GetBacktrace(backtrace, false)) {
            ZLOGW(LOG_LABEL, "GetBacktrace failed");
        } else {
            ZLOGW(LOG_LABEL, "GetBacktrace info:\n%{public}s", backtrace.c_str());
        }
#else
        ZLOGW(LOG_LABEL, "GetBacktrace not support");
#endif
        uint64_t curTime = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        std::ostringstream stream;
        stream << jsThreadId_;
        ZLOGW(LOG_LABEL, "jsThreadId_:%{public}s, NativeEngine GetSysTid: %{public}u, "
#ifdef FFRT_SUPPORT
            "ffrt id:%{public}" PRIu64
#else
            "ffrt not support"
#endif
            ", GetCurSysTid:%{public}u, time:%{public}" PRIu64,
            stream.str().c_str(), (reinterpret_cast<NativeEngine *>(env_))->GetSysTid(),
#ifdef FFRT_SUPPORT
            ffrt_this_task_get_id(),
#endif
            NativeEngine::GetCurSysTid(), curTime);
    }
}
} // namespace OHOS
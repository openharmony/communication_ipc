# IPC 核心边界知识

本文记录 Native IPC 核心路径中容易被改错的边界。只记录仓内可定位的稳定信息，不替代具体代码阅读。

## 关键路径

| 场景 | 先读 |
| --- | --- |
| Native Proxy/Stub 接口 | `interfaces/innerkits/ipc_core/include/iremote_proxy.h`、`iremote_stub.h`、`iremote_object.h` |
| 请求码和 transaction 范围 | `interfaces/innerkits/ipc_core/include/ipc_types.h` |
| Parcel 读写和对象传递 | `interfaces/innerkits/ipc_core/include/message_parcel.h`、`ipc/native/src/core/framework/source/message_parcel.cpp` |
| 请求发送和本地/远端分发 | `interfaces/innerkits/ipc_core/include/ipc_object_proxy.h`、`ipc_object_stub.h`，以及 `ipc/native/src/core/` 下对应实现 |
| IPC 线程、进程和对象骨架 | `ipc/native/src/core/framework/`、`ipc/native/src/core/invoker/` |
| C API 对齐 | `interfaces/innerkits/c_api/include/`、`ipc/native/src/c_api/` |

## 高风险边界

- `interfaces/innerkits/ipc_core/include/` 是核心对内接口。改签名、返回值、错误码、默认参数或注释承诺前，先确认调用方和兼容性。
- `ipc_types.h` 中 transaction code 和错误码是通信双方共同依赖的协议边界。不要为了局部实现方便重排、复用或扩大含义。
- `MessageParcel` 的写入顺序、读取顺序、remote object、文件描述符、raw data、错误码处理必须成对维护。
- `IRemoteProxy::SendRequest`、`IRemoteStub::OnRemoteRequest`、`IPCObjectProxy`、`IPCObjectStub` 的 descriptor 校验、返回码和异常路径会影响所有上层服务。
- 内核 ioctl / render 拦截：render 对 ioctl 有拦截。新增内核 ioctl command 时，必须同步修改配套分支的 `openharmony-tpc/chromium_arkweb` 仓库中 `chromium_ext/sandbox/seccomp-bpf-helpers/baseline_policy_ohos.cc`，增加对应的 ioctl command；若 IPC 同时新增了该命令使用的参数结构体，则一并同步结构体定义。
- C API、NAPI、Rust 入口如果复用 Native 语义，修改 Native 侧时需要检查对应绑定层是否要同步。

## 改动前检查

改 IPC 核心逻辑前至少确认：

1. 请求是设备内 Binder IPC 还是跨设备 DBinder/RPC。
2. 是否触达 `interfaces/innerkits/` 或 `interfaces/kits/` 的接口契约。
3. 是否改变 transaction code、Parcel 数据布局、错误码或 fd/remote object 生命周期。
4. 是否新增内核 ioctl command；如有，是否已同步修改配套分支的 `openharmony-tpc/chromium_arkweb` 仓库中 `chromium_ext/sandbox/seccomp-bpf-helpers/baseline_policy_ohos.cc`，增加对应的 ioctl command，并在 IPC 同时新增该命令使用的参数结构体时同步结构体定义。
5. 是否需要同步 C API、NAPI、Rust、ANI 或 Taihe 入口。

## 测试路由

优先使用最近测试：

| 改动 | 测试入口 |
| --- | --- |
| MessageParcel、IPCObject、Skeleton、ThreadPool、Invoker 等核心逻辑 | `test/unittest/common/`、`test/unittest/ipc/native/` |
| C API 行为 | `test/moduletest/ipc/capi/`、`test/unittest/` 中相关 C API 用例 |
| Native API 行为 | `test/moduletest/ipc/cppapi/`、`test/unittest/common/` |
| fuzz 覆盖 | `test/fuzztest/interfaces/innerkits/`、`test/fuzztest/ipc/native/` |

测试目标和构建方式见 `docs/knowledge/build-and-verification.md`。

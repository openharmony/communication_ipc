# IPC 组件 Agent 指引

## 基本信息

| 属性 | 值 |
| --- | --- |
| 代码仓名称 | communication_ipc |
| 所属子系统 | foundation/communication |
| 组件名 | ipc |
| 主要语言 | C/C++、Rust、JavaScript/ArkTS NAPI、C API、CJ/Taihe/ANI |

## 项目定位

本仓库对应 OpenHarmony `foundation/communication/ipc`，提供 IPC/RPC 通信基础能力。仓内主要覆盖设备内 Binder IPC、跨设备 DBinder/RPC、Native Proxy/Stub 基础接口、JS NAPI、C API、Rust 接口以及相关测试。

处理问题时优先确认调用链属于设备内 IPC 还是跨设备 RPC/DBinder。涉及 Proxy/Stub、`IRemoteObject`、`MessageParcel`、SAMgr、SoftBus 或权限认证时，先读相邻接口、实现和测试，不要凭通用 IPC 知识推断仓内行为。

## 代码地图

优先按这些目录定位问题：

当前 `foundation/communication/ipc` 下未发现更深层 `AGENTS.md`。若后续子目录新增 agent 指引，修改该子目录时以最近的指引为准，并同时遵循本文件的公共边界。

表格中的“风险”表示 agent 修改该目录时的兼容性影响面、误改后果和验证成本，不代表代码质量。高风险通常涉及公共接口、协议边界、跨设备行为或多调用方；中风险通常需要同步接口/构建/绑定层并做针对性验证；低风险通常更局部，但仍需就近验证。

| 目录 | 用途 | 风险 |
| --- | --- | --- |
| `interfaces/innerkits/ipc_core/include/` | Native IPC 核心对内接口，如 `IRemoteObject`、`IRemoteProxy`、`IRemoteStub`、`MessageParcel` | 高：公共接口和序列化语义影响调用方 |
| `interfaces/innerkits/c_api/include/` | C API 头文件 | 高：接口签名和错误码变更需要兼容性确认 |
| `interfaces/innerkits/libdbinder/include/` | 供 SAMgr 使用的 DBinder 接口 | 高：跨设备通信和服务生命周期风险 |
| `interfaces/innerkits/rust/` | Rust IPC crate 和 CXX 桥接相关代码 | 中：Rust/C++ 接口需同步 |
| `interfaces/kits/js/napi/`、`ipc/native/src/napi*` | JS/ArkTS NAPI RPC 接口与公共 NAPI 实现 | 中：IPC 行为结合 ACTS 验证，RPC 行为结合 DCTS 验证 |
| `ipc/native/src/core/framework/` | IPC 核心框架对象、Parcel、线程与进程骨架 | 高：高频基础路径 |
| `ipc/native/src/core/invoker/` | Binder/DBinder invoker 和 trace 相关逻辑 | 高：请求发送、调度和错误传播风险 |
| `ipc/native/src/core/dbinder/`、`dbinder/` | DBinder 服务、会话、跨设备调用相关实现 | 高：跨设备兼容、死亡通知、引用计数风险 |
| `ipc/native/src/c_api/` | C API native 实现 | 中：需和 `interfaces/innerkits/c_api/include/` 对齐 |
| `ipc/native/src/ani/`、`ipc/native/src/taihe/` | ANI、Taihe 相关接口和实现 | 中：接口生成物和包目标需同步确认 |
| `utils/` | IPC 本仓共享工具 | 中：可能被 IPC/DBinder 共同依赖 |
| `config/`、`config.gni`、`bundle.json`、`BUILD.gn` | 构建、特性宏、组件元数据 | 中：依赖方向和 feature 开关影响多目标 |
| `test/`、`example/` | 单元测试、模块测试、分布式测试、fuzz、示例 | 低到高：按覆盖场景选择最近验证 |

## 知识索引

稳定背景知识放在 `docs/knowledge/`。改动前按场景读取对应文件：

| 场景 | 先读 |
| --- | --- |
| Native IPC、Proxy/Stub、`IRemoteObject`、`MessageParcel`、`MessageOption`、transaction code、Parcel 读写顺序 | `docs/knowledge/ipc-core-boundaries.md` |
| DBinder/RPC、跨设备通信、SoftBus/SAMgr 依赖、服务死亡通知、会话名、引用计数、权限认证 | `docs/knowledge/dbinder-boundaries.md` |
| 构建目标、测试目标、验证证据、无法本地验证时的回复要求 | `docs/knowledge/build-and-verification.md` |

改动前先在工作说明中确认：

1. 任务分类：Native IPC / DBinder-RPC / C API / NAPI-ANI-Taihe / Rust / 构建配置 / 测试。
2. 已读取的 `docs/knowledge/*` 文件。
3. 本次触达的高风险约束；若没有触达，也明确说明。

## 项目约束

- **兼容与安全边界**：修改公共接口签名、语义或错误码，transaction code、Parcel/跨设备协议布局，或权限认证逻辑时，必须先检查调用方、通信双方和相邻测试，并说明兼容性或安全影响；可能造成不兼容或放宽权限边界的，取得用户确认后再实施。
- **NAPI 兼容性**：修改 NAPI 相关代码时，必须检查 JS/ArkTS 对外接口兼容性，不得无意改变导出名称、参数和返回值、同步/异步行为、错误码与异常语义以及对象生命周期；确需进行不兼容变更时，实施前必须取得用户确认，并同步接口声明和相关 ACTS/DCTS 用例。
- **ABI 兼容性**：修改 `ipc_object_proxy.h` 或 `ipc_object_stub.h` 时，必须评估 ABI 兼容性，重点检查类继承关系，虚函数的新增、删除、顺序和签名，成员变量的新增、删除、顺序和类型，构造与析构语义，以及不同条件编译配置下的对象布局；确需进行不兼容变更时，实施前必须取得用户确认，并说明影响范围和兼容方案。
- **ioctl**：新增内核 ioctl command 时，必须同步修改配套分支的 `openharmony-tpc/chromium_arkweb` 仓库中 `chromium_ext/sandbox/seccomp-bpf-helpers/baseline_policy_ohos.cc`，增加对应的 ioctl command；若 IPC 同时新增了该命令使用的参数结构体，则一并同步结构体定义。修改已有 command、参数结构体或调用路径时，也必须重新检查并同步对应的 ArkWeb 拦截策略。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。以下统一使用 `rk3568` 产品。

```sh
./build.sh --product-name rk3568 --ccache --build-target ipc_components
./build.sh --product-name rk3568 --ccache --build-target //foundation/communication/ipc:ipc_components
./build.sh --product-name rk3568 --ccache --build-target //foundation/communication/ipc/test:ipc_test
```

常用测试聚合目标：

```sh
./build.sh --product-name rk3568 --ccache --build-target //foundation/communication/ipc/test/unittest:ipc_unittest
./build.sh --product-name rk3568 --ccache --build-target //foundation/communication/ipc/test/fuzztest:ipc_fuzztest
./build.sh --product-name rk3568 --ccache --build-target //foundation/communication/ipc/test/moduletest:ipc_moduletest
```

按变更类型选择最低验证：

| 任务类型 | 最少验证 |
| --- | --- |
| 修改核心 Native IPC | 构建相关库 + 最近的 common/native 单测 |
| 修改公共接口头文件 | 构建组件 + 构建相关 API/单元测试 |
| 修改 DBinder/RPC | 构建 DBinder 相关单测、分布式测试或 fuzz 目标 |
| 修改 NAPI/JS 接口 | 构建 JS/NAPI 相关目标；IPC 行为结合 ACTS 验证，RPC 行为结合 DCTS 验证 |
| 修改 Rust 接口 | 构建 `interfaces/innerkits/rust` 相关目标，并确认 CXX 桥接同步 |
| 修改 BUILD.gn、bundle.json 或 config.gni | 构建受影响目标，并说明 feature/os_level 覆盖情况 |

如果无法在本地执行构建或测试，回复中必须说明未验证项、原因、需要人工执行的命令和风险，不得将未执行项描述为已通过。

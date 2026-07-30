# 构建与验证知识

本文记录 IPC 仓常用构建和验证入口。命令从 OpenHarmony 源码根目录执行，不在 `foundation/communication/ipc` 子目录执行。

## 构建入口

以下统一使用 `rk3568` 产品：

```sh
./build.sh --product-name rk3568 --ccache --build-target ipc_components
./build.sh --product-name rk3568 --ccache --build-target //foundation/communication/ipc:ipc_components
./build.sh --product-name rk3568 --ccache --build-target //foundation/communication/ipc/test:ipc_test
```

仓内已确认的聚合 target：

| target | 来源 |
| --- | --- |
| `//foundation/communication/ipc:ipc_components` | 根目录 `BUILD.gn` |
| `//foundation/communication/ipc:ipc_components_test` | 根目录 `BUILD.gn` |
| `//foundation/communication/ipc/test:ipc_test` | `bundle.json` 和 `test/BUILD.gn` |
| `//foundation/communication/ipc/test/unittest:ipc_unittest` | `test/unittest/BUILD.gn` |
| `//foundation/communication/ipc/test/fuzztest:ipc_fuzztest` | `test/fuzztest/BUILD.gn` |
| `//foundation/communication/ipc/test/moduletest:ipc_moduletest` | `test/moduletest/BUILD.gn` |
| `//foundation/communication/ipc/test/distributedtest:ipc_distributedtest` | `test/distributedtest/BUILD.gn` |

## 场景化验证

| 变更类型 | 最少验证 |
| --- | --- |
| Native IPC 核心实现 | 构建受影响库或 `ipc_components`，并构建最近的 common/native 单测 |
| 公共接口头文件 | 构建组件聚合目标，并构建相关 API/模块测试 |
| C API | 构建 `interfaces/innerkits/c_api` 相关目标和 C API 模块测试 |
| JS/NAPI | 构建 JS/NAPI 相关目标；IPC 行为结合 ACTS 验证，RPC 行为结合 DCTS 验证 |
| 新增/修改内核 ioctl 命令 | 构建受影响 IPC 目标 + 最近 IPC 单测；新增内核 ioctl command 时，必须同步修改配套分支的 `openharmony-tpc/chromium_arkweb` 仓库中 `chromium_ext/sandbox/seccomp-bpf-helpers/baseline_policy_ohos.cc`，增加对应的 ioctl command；若 IPC 同时新增了该命令使用的参数结构体，则一并同步结构体定义 |
| DBinder/RPC | 构建 DBinder 单测、分布式测试或 DBinder fuzz 中最接近的目标 |
| Rust | 构建 `interfaces/innerkits/rust` 相关目标，并确认 CXX 桥接同步 |
| BUILD.gn、bundle.json、config.gni | 构建受影响 target；如 feature 或 os_level 条件变化，说明覆盖范围 |

## 选择测试的原则

- 先构建最小受影响 target，再按影响面扩大到聚合目标。
- 代码附近已有单测时优先补充或运行相邻测试，不只依赖全量构建。
- 涉及 DBinder、SoftBus、SAMgr、设备状态或跨设备互通时，说明是否需要板侧或分布式环境。
- fuzz 相关改动优先构建对应 fuzz target；如果没有运行环境，至少说明只完成了构建验证。

## 无法本地验证时

如果当前环境不能执行 OpenHarmony 构建或板侧测试，回复中明确列出：

```text
未本地验证：
- 命令：<需要执行的命令>
- 原因：<缺少产品 out、工具链、设备、权限或环境>
- 风险：<哪些行为仍需人工确认>
```

不要把未执行的构建、单测、分布式测试或板侧测试描述为已通过。

# DBinder 边界知识

本文记录 DBinder/RPC 跨设备路径中容易被改错的边界。DBinder 变更通常同时涉及 IPC 对象模型、SoftBus 通信、SAMgr 交互和服务生命周期。

## 关键路径

| 场景 | 先读 |
| --- | --- |
| SAMgr 使用的 DBinder 接口 | `interfaces/innerkits/libdbinder/include/` |
| DBinder 核心实现 | `ipc/native/src/core/dbinder/`、`dbinder/` |
| 跨设备 invoker | `ipc/native/src/core/invoker/` 中 DBinder 相关实现 |
| SoftBus 头依赖和动态加载 | `config/`、`dl_deps/`、`test/auxiliary/dl_softbus/` |
| SAMgr 和服务注册测试 | `test/distributedtest/`、`test/auxiliary/native/` |
| DBinder 单测和 fuzz | `test/unittest/dbinder_service/`、`test/fuzztest/dbinder_service/` |

## 高风险边界

- 跨设备 RPC 与设备内 Binder IPC 不是同一条路径。不要把 DBinder 会话、设备标识、SoftBus 连接或远端死亡通知逻辑塞进本地 Binder 默认路径。
- 会话名、服务名、stub/proxy 映射、引用计数和死亡通知属于跨进程/跨设备生命周期边界。修改前需要确认已有测试和兼容性影响。
- SoftBus/SAMgr 交互、权限认证、通信认证和设备信任相关逻辑是安全边界。任务没有明确要求时不要顺手改。
- 协议数据布局、Parcel 字段顺序、状态机转换和错误码传播会影响跨设备互通。不能只用本地单测证明兼容性。
- DBinder 相关逻辑经常有 feature、os_level 或动态依赖差异。改构建配置时检查 `config.gni`、`BUILD.gn` 和测试配置。

## 改动前检查

改 DBinder/RPC 前至少确认：

1. 是否改变跨设备协议、会话状态、死亡通知或引用计数。
2. 是否改变 SoftBus/SAMgr 调用时机、错误处理或权限认证路径。
3. 是否影响 `interfaces/innerkits/libdbinder/include/` 供 SAMgr 使用的接口语义。
4. 是否需要分布式测试、板侧验证或人工提供跨设备环境证据。

## 测试路由

优先使用最近测试：

| 改动 | 测试入口 |
| --- | --- |
| DBinder 服务、监听、死亡通知、基础 invoker | `test/unittest/dbinder_service/` |
| 跨设备流程和测试服务 | `test/distributedtest/` |
| DBinder fuzz | `test/fuzztest/dbinder_service/` |
| 动态加载 SoftBus 相关行为 | `test/auxiliary/dl_softbus/` |

如果变更依赖真实设备、SoftBus 网络、SAMgr 集成或跨设备互通，本地构建只能作为基础证据，回复中需要明确还缺哪些环境验证。

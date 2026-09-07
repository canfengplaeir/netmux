# NetMux — Linux 多网口带宽聚合工具

![Rust](https://img.shields.io/badge/Rust-1.85+-orange.svg)
![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)

NetMux 是一款基于 **Rust** 与 **GPUI**（GPU 加速 UI 框架）开发的 Linux 网络聚合软件。它能够将多个物理网络接口（以太网、Wi-Fi、移动数据等）的带宽合并管理，实现：

- **带宽聚合**：通过 TUN 虚拟设备汇聚多网口流量，按流分发调度
- **负载均衡**：哈希 / 加权轮询 / 最小负载三种算法在多网口间分配新连接
- **故障转移**：按优先级自动选择最高优先级的在线接口
- **实时监控**：GPUI 图形界面实时展示接口状态、带宽占用与网络性能统计

## 功能特性

- 多网络接口发现与分类（以太网 / Wi-Fi / 移动数据 / 虚拟设备）
- 实时接口健康检测（内核 flags + carrier，兼容 operstate 为 unknown 的 USB 网卡）
- 流级调度（五元组哈希、加权轮询、最小负载），连接优先级与权重可配置
- 每接口实时 TX/RX 吞吐统计（读取 `/sys/class/net`，Linux 原生数据源）
- 直观 GPUI 界面：仪表盘、接口监控、策略配置、性能统计四个标签页
- **模拟演示模式**：无需 root 即可展示负载均衡/故障转移调度
- **真实隧道模式**（`--tun`）：读取真实内核路由进 TUN 的报文并调度
- 完善的错误处理与日志记录（tracing，文件 + 标准输出）

## 架构

```
netmux/                          # Cargo workspace
├── crates/
│   ├── netmux-core/             # 聚合引擎（无 GUI 依赖，可独立测试）
│   │   ├── src/interface.rs     # 接口枚举与健康检测
│   │   ├── src/policy.rs        # 聚合策略与调度算法
│   │   ├── src/aggregator.rs    # 聚合器：路由决策 + 流表 + 模拟流量生成
│   │   ├── src/tun.rs           # Linux TUN 虚拟设备（ioctl，无外部依赖）
│   │   ├── src/packet.rs        # IP 报文解析与五元组提取
│   │   ├── src/stats.rs         # 吞吐统计采集器
│   │   ├── src/logging.rs       # 日志初始化
│   │   └── src/error.rs         # 统一错误类型
│   └── netmux-app/              # GPUI 图形界面
│       └── src/main.rs          # 应用状态、渲染与事件处理
└── Cargo.toml
```

### 聚合原理

应用通过 **TUN 虚拟设备**（`netmux0`）接收内核路由进设备的所有 IP 报文：

1. 内核按路由规则将流量送入 `netmux0`
2. 应用从 TUN fd 非阻塞读取报文，解析出五元组（流）
3. 按当前策略（负载均衡 / 故障转移）从健康接口中选择出口
4. 记录流→接口映射并统计转发量

> 说明：当前版本完成「读入 → 按策略选路 → 计数/统计」的调度引擎；报文从物理接口真正转发出去（raw socket 出口）是生产化的下一步。

## 快速开始

### 依赖

- Rust 1.85+（需要 2024 edition 支持）
- Linux 桌面（Wayland 或 X11）、Vulkan 驱动的 GPU
- 系统库：`libxkbcommon`、`fontconfig` 等（GPUI 依赖，见 gpui-unofficial 文档）

### 编译

```bash
cargo build --release
```

### 模拟演示模式（无需 root）

```bash
./target/release/netmux-app
```

程序以模拟模式启动，内置合成流量生成器驱动负载均衡/故障转移调度，无物理接口时也会注入演示接口。

### 真实隧道模式（需 CAP_NET_ADMIN）

创建 TUN 设备需要 `CAP_NET_ADMIN` 能力。推荐用 `setcap` 替代 sudo 运行（避免 X11 授权问题）：

```bash
# 一次授予（注意：cargo build 会清除该能力，需重新授予）
sudo setcap cap_net_admin+ep target/release/netmux-app

# 以普通用户运行
./target/release/netmux-app --tun
```

将流量路由进 `netmux0` 即可被聚合引擎调度：

```bash
sudo ip link set dev netmux0 up
sudo ip route add <目标网段> dev netmux0
```

## 使用说明

界面提供四个标签页：

| 标签页 | 功能 |
|---|---|
| 仪表盘 | 已启用接口数、聚合带宽估算、转发包数、当前负载与负载均衡示意条 |
| 接口监控 | 各接口在线状态、优先级/权重调节、TX/RX 带宽条 |
| 策略配置 | 选择聚合策略（负载均衡/故障转移）与算法（哈希/轮询/最小负载） |
| 性能统计 | 总计与各接口吞吐、当前活跃流记录数 |

## 测试

```bash
cargo test
```

核心引擎包含接口分类、策略选择（哈希稳定性、故障转移优先级、轮询）、报文解析、聚合器模拟路由等 12 项单元测试。

## 日志

日志写入 `$XDG_STATE_HOME/netmux/`（未设置时使用 `/tmp/netmux/`），同时输出到标准输出。

## 已知限制（MVP）

- 报文出口转发（从物理接口发出）尚未实现，调度决策与统计已完整
- 故障转移依赖接口健康状态轮询（默认 5s）
- 仅支持 Linux（遵循 Linux 网络管理规范，读取 `/sys/class/net`、ioctl TUN）

## 许可证

[Apache-2.0](./LICENSE)

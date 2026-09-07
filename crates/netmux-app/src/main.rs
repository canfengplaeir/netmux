//! NetMux — a Linux network aggregation tool built on GPUI and netmux-core.
//!
//! Runs in:
//!   * `Simulation` mode by default — exercises load-balancing / failover with
//!     synthetic flows so the whole UI is demonstrable without root.
//!   * `Tunnelling` mode when launched with `--tun` (requires root / CAP_NET_ADMIN)
//!     to create the `netmux0` TUN device and forward real traffic.

use std::time::Duration;

use gpui::prelude::*;
use gpui::*;

use netmux_core::{
    aggregator::PcapGenerator, policy::Strategy, tun, Aggregator, AggregatorConfig, BalanceAlgorithm,
    InterfaceKind, Mode, NetmuxError,
};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct NetMuxApp {
    aggregator: Aggregator,
    generator: PcapGenerator,
    /// Live TUN device in real (non-simulation) mode.
    tun: Option<tun::Tun>,
    /// Named tab that is currently active.
    tab: Tab,
    /// Tunnel error surfaced in banner when real mode is unavailable.
    banner: Option<String>,
    /// Bytes forwarded per nds (tracked for the summary line).
    forwarded_packets: u64,
    total_speed: f64,
    /// Last time a tunnelling-mode summary was logged.
    last_summary: std::time::Instant,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Dashboard,
    Interfaces,
    Policy,
    Statistics,
}

#[derive(Clone, PartialEq)]
enum IfaceAction {
    Enable(String, bool),
    Priority(String, i32),
    Weight(String, i32),
}

impl NetMuxApp {
    fn new(_cx: &mut Context<Self>) -> Self {
        let config = AggregatorConfig::default();

        // Prefer real TUN mode when explicitly requested and we can obtain it.
        let (mode, banner, tun) = if std::env::args().any(|a| a == "--tun") {
            match tun::Tun::create("netmux0") {
                Ok(t) => {
                    // Keep the device open for the app's lifetime; a closed fd
                    // would destroy the interface. Bring it up so the kernel
                    // actually routes traffic into it.
                    if let Err(e) = t.set_nonblocking() {
                        tracing::warn!("set nonblocking on {}: {e}", t.name);
                    }
                    if let Err(e) = tun::set_up(&t.name) {
                        tracing::warn!("ip link set {0} up: {e}", t.name);
                    }
                    (Mode::Tunnelling, None, Some(t))
                }
                Err(NetmuxError::Permission(msg)) => (Mode::Simulation, Some(msg), None),
                Err(e) => (Mode::Simulation, Some(e.to_string()), None),
            }
        } else {
            (
                Mode::Simulation,
                Some("未以 --tun（需 CAP_NET_ADMIN）运行，当前处于模拟演示模式".into()),
                None,
            )
        };

        let mut app = NetMuxApp {
            aggregator: Aggregator::new(config, mode).expect("valid config"),
            generator: PcapGenerator::default(),
            tun,
            tab: Tab::Dashboard,
            banner,
            forwarded_packets: 0,
            total_speed: 0.0,
            last_summary: std::time::Instant::now(),
        };
        app.aggregator.refresh_candidates();
        app
    }

    /// Advance the aggregator: synthetic packets (simulation) or real packets
    /// drained from the TUN device (tunnelling).
    fn tick(&mut self) {
        if self.aggregator.mode == Mode::Simulation {
            // Ensure we always have schedulable links for the demo.
            if self.aggregator.candidates().is_empty() {
                self.aggregator.inject_sim_candidates(&[
                    ("eth0 (模拟)", InterfaceKind::Ethernet, 30, 3),
                    ("wlan0 (模拟)", InterfaceKind::Wifi, 20, 2),
                    ("wwan0 (模拟)", InterfaceKind::Cellular, 25, 1),
                ]);
            }
            let dt = self.aggregator.config.health_check_interval_secs.max(1) as f64 * 0.016;
            let n = self.generator.per_tick(Duration::from_secs_f64(dt));
            for _ in 0..n.min(2000) {
                let pkt = self.generator.next_packet(96 + (self.forwarded_packets % 5) as usize * 64);
                if let Some(d) = self.aggregator.route(&pkt) {
                    if d.interface.is_some() {
                        self.forwarded_packets += 1;
                        // accumulate a guessed throughput: each simulated packet ≈ 150 B
                        self.total_speed += 150.0;
                    }
                } else {
                    break;
                }
            }
        } else if let Some(tun) = &self.tun {
            // Real mode: drain the TUN device and schedule every packet.
            let mut buf = [0u8; tun::MAX_PACKET];
            loop {
                match tun.read(&mut buf) {
                    Ok(0) | Err(_) => break, // EAGAIN / EOF / error — nothing more now
                    Ok(n) => {
                        if let Some(d) = self.aggregator.route(&buf[..n]) {
                            if d.interface.is_some() {
                                self.forwarded_packets += 1;
                                self.total_speed += n as f64;
                            }
                        }
                    }
                }
            }
            self.aggregator.tick();
            if self.last_summary.elapsed() >= std::time::Duration::from_secs(10) {
                let mut per_iface: std::collections::BTreeMap<&str, usize> = Default::default();
                for iface in self.aggregator.flow_table.values() {
                    *per_iface.entry(iface).or_insert(0) += 1;
                }
                let dist = per_iface
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                tracing::info!(
                    "tun summary: forwarded={} packets ({:.1} KiB), active_flows={}, distribution: {}",
                    self.forwarded_packets,
                    self.total_speed / 1024.0,
                    self.aggregator.flow_table.len(),
                    dist,
                );
                self.last_summary = std::time::Instant::now();
            }
        }
    }

    fn toggle_enabled(&mut self) {
        self.aggregator.config.enabled = !self.aggregator.config.enabled;
    }

    fn set_strategy(&mut self, s: Strategy) {
        self.aggregator.config.strategy = s;
    }

    fn set_algorithm(&mut self, a: BalanceAlgorithm) {
        self.aggregator.config.algorithm = a;
    }

    fn iface_action(&mut self, action: IfaceAction) {
        use netmux_core::policy::InterfacePolicy;
        let cfg = &mut self.aggregator.config;
        match action {
            IfaceAction::Enable(name, enable) => {
                let p = cfg
                    .interfaces
                    .entry(name)
                    .or_insert_with(InterfacePolicy::default);
                p.enabled = enable;
            }
            IfaceAction::Priority(name, delta) => {
                let p = cfg
                    .interfaces
                    .entry(name)
                    .or_insert_with(InterfacePolicy::default);
                p.priority = (p.priority as i32 + delta).clamp(1, 99) as u32;
            }
            IfaceAction::Weight(name, delta) => {
                let p = cfg
                    .interfaces
                    .entry(name)
                    .or_insert_with(InterfacePolicy::default);
                p.weight = (p.weight as i32 + delta).clamp(1, 100) as u32;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

fn kind_label(k: InterfaceKind) -> &'static str {
    match k {
        InterfaceKind::Ethernet => "以太网",
        InterfaceKind::Wifi => "Wi-Fi",
        InterfaceKind::Cellular => "移动数据",
        InterfaceKind::Loopback => "回环",
        InterfaceKind::Virtual => "虚拟",
        InterfaceKind::Other => "其他",
    }
}

/// A proportional ASCII bar (avoids Length/px styling — robust across GPUI).
fn bar(ratio: f64, cells: usize) -> String {
    let ratio = ratio.clamp(0.0, 1.0);
    let filled = (ratio * cells as f64).round() as usize;
    let mut s = String::new();
    for i in 0..cells {
        s.push(if i < filled { '█' } else { '░' });
    }
    s
}

fn header_row() -> Div {
    div().flex().flex_row().w_full().p_2().gap_1()
}

// ---------------------------------------------------------------------------
// GPUI application
// ---------------------------------------------------------------------------

impl Render for NetMuxApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let enabled = self.aggregator.config.enabled;
        let mode_label = self.aggregator.mode.label();
        let candidates = self.aggregator.candidates().clone();
        let max_speed = candidates
            .iter()
            .map(|c| c.tx_bps + c.rx_bps)
            .fold(0.0, f64::max)
            .max(1.0);

        let header = header_row()
            .child(
                div()
                    .flex_1()
                    .child("NetMux — Linux 多网口带宽聚合")
            )
            .child(format!("模式: {mode_label}"))
            .child(
                div().id("toggle").on_click(cx.listener(|app, _e: &ClickEvent, _w, _cx| app.toggle_enabled())).child(
                    if enabled { "[●] 聚合已启用" } else { "[○] 聚合已暂停" },
                ),
            );

        // Explicit dark palette so the dashboard is visible regardless of the
        // host theme (GPUI defaults to a *light* text color on a transparent
        // window, which is near-invisible on a black background).
        let mut col = div()
            .id("root")
            .bg(rgb(0x16161e))
            .text_color(rgb(0xe6e6e6))
            .flex()
            .flex_col()
            .size_full()
            .p_3()
            .overflow_y_scroll();

        // Header row
        col = col.child(
            div().flex().flex_row().gap_2().w_full().justify_center().p_2().child(header),
        );

        // Banner
        if enabled && self.aggregator.mode == Mode::Simulation {
            col = col.child(
                div().mt_2().p_2().child(
                    "模拟演示模式：展示负载均衡/故障转移调度。以 sudo/root 运行并加 --tun 可启用真实 TUN 聚合。",
                ),
            );
        }
        if let Some(b) = &self.banner {
            col = col.child(div().mt_1().child(b.clone()));
        }

        // Tabs
        col = col.child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .mt_2()
                .child(self.tab_button("仪表盘", Tab::Dashboard, cx))
                .child(self.tab_button("接口监控", Tab::Interfaces, cx))
                .child(self.tab_button("策略配置", Tab::Policy, cx))
                .child(self.tab_button("性能统计", Tab::Statistics, cx)),
        );

        match self.tab {
            Tab::Dashboard => col = col.child(self.render_dashboard(candidates, max_speed)),
            Tab::Interfaces => col = col.child(self.render_interfaces(candidates, max_speed, cx)),
            Tab::Policy => col = col.child(self.render_policy(cx)),
            Tab::Statistics => col = col.child(self.render_statistics(candidates, max_speed)),
        }

        col
    }
}

impl NetMuxApp {
    fn tab_button(&self, label: &str, tab: Tab, cx: &mut Context<Self>) -> impl IntoElement {
        let active = self.tab == tab;
        let b = div().id(format!("tab-{label}")).px_3().py_1();
        if active {
            b.child(format!("▶ {label}")).into_any()
        } else {
            b.on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| app.tab = tab))
                .child(label.to_string())
                .into_any()
        }
    }

    fn render_dashboard(&self, candidates: Vec<netmux_core::CandidateIface>, max_speed: f64) -> impl IntoElement {
        let mut used: u64 = 0;
        let mut healthy: usize = 0;
        let mut total_cap: f64 = 0.0;
        for c in &candidates {
            if c.policy.enabled {
                used += 1;
                total_cap += (c.tx_bps + c.rx_bps) * 8.0;
            }
            if c.healthy {
                healthy += 1;
            }
        }

        div()
            .flex()
            .flex_col()
            .mt_3()
            .gap_2()
            .child(
                div().flex().flex_row().gap_2().flex_wrap()
                    .child(kpi("已启用接口", &format!("{used}/{healthy}")))
                    .child(kpi("聚合带宽(估算)", &netmux_core::stats::fmt_bps(self.total_speed)))
                    .child(kpi("转发包数", &format!("{}", self.forwarded_packets)))
                    .child(kpi("当前负载(Mbps)", &format!("{:.1}", total_cap / 1e6))),
            )
            .child(div().mt_2().child("—— 负载均衡示意 ——"))
            .child(self.aggregated_bar(candidates, max_speed))
    }

    fn aggregated_bar(&self, candidates: Vec<netmux_core::CandidateIface>, max_speed: f64) -> impl IntoElement {
        let mut body = div().flex().flex_col().gap_1().mt_2();
        for c in candidates {
            if !c.policy.enabled {
                continue;
            }
            let load = (c.tx_bps + c.rx_bps) / max_speed.max(1.0);
            let status = if c.healthy { "UP" } else { "DOWN" };
            let tx = netmux_core::stats::fmt_bps(c.tx_bps);
            let rx = netmux_core::stats::fmt_bps(c.rx_bps);
            body = body.child(
                div()
                    .child(format!(
                        "{:<12} [{}] {}  TX {}  RX {}",
                        c.name,
                        status,
                        c.policy.enabled,
                        tx,
                        rx
                    ))
                    .child(format!("    {}", bar(load, 24))),
            );
        }
        body
    }

    fn render_interfaces(
        &self,
        candidates: Vec<netmux_core::CandidateIface>,
        max_speed: f64,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let mut rows = div().flex().flex_col().gap_1().mt_3();

        if candidates.is_empty() {
            rows = rows.child("未发现物理网络接口。");
        }

        for c in candidates {
            let cb_label = if c.policy.enabled { "[x]" } else { "[ ]" };
            let name_for_toggle = c.name.clone();
            let enable_state = c.policy.enabled;
            let mut row = div().flex().flex_col().mt_2();
            row = row.child(
                div().flex().flex_row().gap_2()
                    .child(
                        div()
                            .id(format!("enable-{name_for_toggle}"))
                            .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| {
                                app.iface_action(IfaceAction::Enable(
                                    name_for_toggle.clone(),
                                    !enable_state,
                                ));
                            }))
                            .child(cb_label.to_string()),
                    )
                    .child(format!("{} ({})", c.name, kind_label(c.kind)))
                    .child(if c.healthy { "●在线" } else { "○离线" }.to_string())
                    .child(format!("优先级:{}", c.policy.priority))
                    .child(format!("权重:{}", c.policy.weight)),
            );
            row = row.child(format!("    TX ↓ {}", bar(c.tx_bps / max_speed.max(1.0), 20)));
            row = row.child(format!("    RX ↑ {}", bar(c.rx_bps / max_speed.max(1.0), 20)));
            row = row.child(
                div().flex().flex_row().gap_2().mt_1()
                    .child({
                        let n = c.name.clone();
                        div()
                            .id(format!("pri-plus-{}", c.name))
                            .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| {
                                app.iface_action(IfaceAction::Priority(n.clone(), 1));
                            }))
                            .child("优先级+".to_string())
                    })
                    .child({
                        let n = c.name.clone();
                        div()
                            .id(format!("pri-minus-{}", c.name))
                            .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| {
                                app.iface_action(IfaceAction::Priority(n.clone(), -1));
                            }))
                            .child("优先级-".to_string())
                    })
                    .child({
                        let n = c.name.clone();
                        div()
                            .id(format!("wei-plus-{}", c.name))
                            .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| {
                                app.iface_action(IfaceAction::Weight(n.clone(), 1));
                            }))
                            .child("权重+".to_string())
                    })
                    .child({
                        let n = c.name.clone();
                        div()
                            .id(format!("wei-minus-{}", c.name))
                            .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| {
                                app.iface_action(IfaceAction::Weight(n.clone(), -1));
                            }))
                            .child("权重-".to_string())
                    }),
            );
            rows = rows.child(row.into_any());
        }
        rows
    }

    fn render_policy(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let strategy = self.aggregator.config.strategy;
        let algo = self.aggregator.config.algorithm;
        let mut s = div().flex().flex_col().mt_3().gap_2();

        s = s.child(div().child("聚合策略（选择负载均衡或故障转移）："));
        s = s.child(strategy_row("负载均衡", Strategy::LoadBalance, strategy, cx));
        s = s.child(strategy_row("故障转移（按优先级）", Strategy::Failover, strategy, cx));

        s = s.child(div().mt_2().child("负载均衡算法（仅负载均衡模式生效）："));
        s = s.child(algo_row("哈希（按五元组固定分配）", BalanceAlgorithm::Hash, algo, cx));
        s = s.child(algo_row("轮询（加权轮转）", BalanceAlgorithm::RoundRobin, algo, cx));
        s = s.child(algo_row("最小负载（实时负载最低优先）", BalanceAlgorithm::LeastLoaded, algo, cx));

        s = s.child(
            div().mt_3().p_2().child(
                "说明：故障转移模式按优先级选择最高的在线接口；负载均衡模式通过上述算法在多个接口间分配新建连接。接口可与下方接口监控联动设置优先级/权重。",
            ),
        );
        s
    }

    fn render_statistics(
        &self,
        candidates: Vec<netmux_core::CandidateIface>,
        max_speed: f64,
    ) -> impl IntoElement {
        let mut rows = div().flex().flex_col().mt_3().gap_1();
        let total_tx: f64 = candidates.iter().map(|c| c.tx_bps).sum();
        let total_rx: f64 = candidates.iter().map(|c| c.rx_bps).sum();
        rows = rows.child(format!("总计  ↑TX {}     ↓RX {}", netmux_core::stats::fmt_bps(total_tx), netmux_core::stats::fmt_bps(total_rx)));
        for c in candidates {
            let load = (c.tx_bps + c.rx_bps) / max_speed.max(1.0);
            rows = rows.child(
                format!("{:<12} ↑ {:<10} ↓ {:<10} {}",
                    c.name,
                    netmux_core::stats::fmt_bps(c.tx_bps),
                    netmux_core::stats::fmt_bps(c.rx_bps),
                    bar(load, 12)),
            );
        }
        rows.child(format!("\n当前活跃流记录: {} 条", self.aggregator.flow_table.len()))
    }
}

fn strategy_row(label: &str, value: Strategy, current: Strategy, cx: &mut Context<NetMuxApp>) -> impl IntoElement {
    let marker = if value == current { "[●]" } else { "[○]" };
    div()
        .id(format!("strategy-{label}"))
        .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| app.set_strategy(value)))
        .child(format!("{marker} {label}"))
}

fn algo_row(label: &str, value: BalanceAlgorithm, current: BalanceAlgorithm, cx: &mut Context<NetMuxApp>) -> impl IntoElement {
    let marker = if value == current { "[●]" } else { "[○]" };
    div()
        .id(format!("algo-{label}"))
        .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| app.set_algorithm(value)))
        .child(format!("{marker} {label}"))
}

fn kpi(label: &str, value: &str) -> Div {
    div().flex().flex_col().p_2().child(format!("{label}")).child(format!("{value}"))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let log_dir = std::env::var("XDG_STATE_HOME")
        .ok()
        .filter(|d| !d.is_empty())
        .map(std::path::PathBuf::from)
        .map(|d| d.join("netmux"))
        .or_else(|| Some(std::path::PathBuf::from("/tmp/netmux")));

    if let Err(e) = netmux_core::logging::init("netmux", log_dir.as_deref(), "info") {
        eprintln!("logging init warning: {e}");
    }

    tracing::info!("starting NetMux app");

    gpui_platform::application()
        .with_quit_mode(QuitMode::Explicit)
        .run(|cx: &mut App| {
            cx.init_colors();
            cx.open_window(WindowOptions::default(), |_window, cx| {
                cx.new(|view_cx: &mut Context<NetMuxApp>| {
                    let app = NetMuxApp::new(view_cx);
                    // periodic update loop
                    view_cx
                        .spawn(async move |weak, cx| {
                            loop {
                                cx.background_executor()
                                    .timer(Duration::from_millis(250))
                                    .await;
                                weak.update(cx, |view, view_cx| {
                                    view.tick();
                                    view_cx.notify();
                                })
                                .ok();
                            }
                        })
                        .detach();
                    app
                })
            })
            .expect("opening window");
        });
}
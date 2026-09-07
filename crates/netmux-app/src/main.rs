//! NetMux — a Linux network aggregation tool built on GPUI and netmux-core.
//!
//! Runs in:
//!   * `Simulation` mode by default — exercises load-balancing / failover with
//!     synthetic flows so the whole UI is demonstrable without root.
//!   * `Tunnelling` mode when launched with `--tun` (requires root / CAP_NET_ADMIN)
//!     to create the `netmux0` TUN device and forward real traffic.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gpui::prelude::*;
use gpui::*;

use netmux_core::{
    aggregator::PcapGenerator, packet, policy::Strategy, tun, Aggregator, AggregatorConfig,
    BalanceAlgorithm, InterfaceKind, Mode, NatTable, NetmuxError, RawCapture, RawEgress,
};

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

/// Semantic color palette. All UI colors come from here so light / dark /
/// follow-system themes stay consistent and restrained.
#[derive(Clone, Copy)]
struct Theme {
    bg: Rgba,
    sidebar: Rgba,
    panel: Rgba,
    panel_hover: Rgba,
    panel_active: Rgba,
    border: Rgba,
    text: Rgba,
    text_muted: Rgba,
    text_on_accent: Rgba,
    accent: Rgba,
    accent_bright: Rgba,
    success: Rgba,
    success_bright: Rgba,
    danger: Rgba,
    idle: Rgba,
    track: Rgba,
    bar_tx: Rgba,
    bar_rx: Rgba,
    bar_neutral: Rgba,
}

impl Theme {
    fn dark() -> Self {
        Self {
            bg: rgb(0x0d1117),
            sidebar: rgb(0x010409),
            panel: rgb(0x161b22),
            panel_hover: rgb(0x1c2128),
            panel_active: rgb(0x111d2e),
            border: rgb(0x2d333b),
            text: rgb(0xe6edf3),
            text_muted: rgb(0x8b949e),
            text_on_accent: rgb(0xffffff),
            accent: rgb(0x1f6feb),
            accent_bright: rgb(0x2f81f7),
            success: rgb(0x238636),
            success_bright: rgb(0x3fb950),
            danger: rgb(0xf85149),
            idle: rgb(0x6e7681),
            track: rgb(0x21262d),
            bar_tx: rgb(0x58a6ff),
            bar_rx: rgb(0x3fb950),
            bar_neutral: rgb(0x8b949e),
        }
    }

    fn light() -> Self {
        Self {
            bg: rgb(0xffffff),
            sidebar: rgb(0xf6f8fa),
            panel: rgb(0xffffff),
            panel_hover: rgb(0xf3f4f6),
            panel_active: rgb(0xeff3fb),
            border: rgb(0xd0d7de),
            text: rgb(0x1f2328),
            text_muted: rgb(0x656d76),
            text_on_accent: rgb(0xffffff),
            accent: rgb(0x1f6feb),
            accent_bright: rgb(0x0969da),
            success: rgb(0x1a7f37),
            success_bright: rgb(0x1f8834),
            danger: rgb(0xcf222e),
            idle: rgb(0x6e7781),
            track: rgb(0xeaeef2),
            bar_tx: rgb(0x0969da),
            bar_rx: rgb(0x1a7f37),
            bar_neutral: rgb(0x6e7781),
        }
    }
}

/// Theme selection mode.
#[derive(Clone, Copy, PartialEq)]
enum ThemeMode {
    Dark,
    Light,
    System,
}

impl ThemeMode {
    fn label(self) -> &'static str {
        match self {
            ThemeMode::Dark => "暗色",
            ThemeMode::Light => "亮色",
            ThemeMode::System => "跟随系统",
        }
    }

    fn cycle(self) -> Self {
        match self {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::System,
            ThemeMode::System => ThemeMode::Dark,
        }
    }
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct NetMuxApp {
    /// Aggregation engine (shared with the data-plane thread).
    aggregator: Arc<Mutex<Aggregator>>,
    generator: PcapGenerator,
    /// Userspace NAT session table (shared with the data-plane threads).
    nat: Arc<Mutex<NatTable>>,
    /// Outbound packets / bytes forwarded (updated by the data plane).
    tx_packets: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    /// Packets injected back into the TUN by the return path.
    nat_rx_packets: Arc<AtomicU64>,
    /// Named tab that is currently active.
    tab: Tab,
    /// Tunnel error surfaced in banner when real mode is unavailable.
    banner: Option<String>,
    /// Last time a tunnelling-mode summary was logged.
    last_summary: std::time::Instant,
    /// User-selected theme mode (dark / light / follow system).
    theme_mode: ThemeMode,
    /// Resolved palette for the current render pass.
    active_theme: Theme,
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
                    (Mode::Tunnelling, None, Some(Arc::new(t)))
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
            aggregator: Arc::new(Mutex::new(
                Aggregator::new(config, mode).expect("valid config"),
            )),
            generator: PcapGenerator::default(),
            nat: Arc::new(Mutex::new(NatTable::new())),
            tx_packets: Arc::new(AtomicU64::new(0)),
            tx_bytes: Arc::new(AtomicU64::new(0)),
            nat_rx_packets: Arc::new(AtomicU64::new(0)),
            tab: Tab::Dashboard,
            banner,
            last_summary: std::time::Instant::now(),
            theme_mode: ThemeMode::System,
            active_theme: Theme::dark(),
        };
        {
            let mut agg = app.aggregator.lock().expect("aggregator lock");
            agg.refresh_candidates();
        }
        // Real mode: open raw sockets and start the data-plane threads
        // (independent of the window's lifetime).
        if mode == Mode::Tunnelling {
            app.start_data_plane(tun.expect("tun in tunnelling mode"));
        }
        app
    }

    /// Build egress/capture sockets for every schedulable physical interface
    /// and spawn the data-plane thread (TUN drain + NAT egress) plus one
    /// return-path thread per interface.
    fn start_data_plane(&mut self, tun: Arc<tun::Tun>) {
        let ips = if_addrs::get_if_addrs().unwrap_or_default();
        let mut ipv4 = HashMap::new();
        for ifa in &ips {
            if let std::net::IpAddr::V4(v4) = ifa.ip() {
                ipv4.insert(ifa.name.clone(), v4);
            }
        }

        let candidates = {
            let agg = self.aggregator.lock().expect("aggregator lock");
            agg.candidates()
        };
        let mut egress = HashMap::new();
        let mut iface_ips = HashMap::new();

        for c in candidates {
            if !c.policy.enabled || !c.healthy {
                continue;
            }
            let Some(ip) = ipv4.get(&c.name).copied() else {
                tracing::warn!("no IPv4 for {}, skipping egress", c.name);
                continue;
            };
            match RawEgress::open(&c.name) {
                Ok(sock) => {
                    iface_ips.insert(c.name.clone(), ip);
                    egress.insert(c.name.clone(), sock);
                }
                Err(e) => {
                    tracing::warn!("RawEgress {}: {e}", c.name);
                    continue;
                }
            }
            match RawCapture::open(&c.name) {
                Ok(cap) => {
                    let tun = tun.clone();
                    let nat = self.nat.clone();
                    let rx = self.nat_rx_packets.clone();
                    let ifname = c.name.clone();
                    std::thread::spawn(move || capture_loop(&cap, &ifname, &tun, &nat, &rx));
                }
                Err(e) => tracing::warn!("RawCapture {}: {e}", c.name),
            }
        }

        // Main data-plane thread: drain the TUN and egress NAT'd packets.
        let egress_count = egress.len();
        {
            let nat = self.nat.clone();
            let aggregator = self.aggregator.clone();
            let tx_pkts = self.tx_packets.clone();
            let tx_bytes = self.tx_bytes.clone();
            std::thread::spawn(move || {
                egress_loop(&tun, &nat, &aggregator, &egress, &iface_ips, &tx_pkts, &tx_bytes);
            });
        }

        tracing::info!(
            "data plane ready: {} egress interfaces, {} capture threads",
            egress_count,
            egress_count,
        );
    }

    /// Advance the aggregator: synthetic packets (simulation) or stats refresh
    /// (tunnelling — the actual forwarding runs on the data-plane thread).
    fn tick(&mut self) {
        let mut agg = self.aggregator.lock().expect("aggregator lock");
        if agg.mode == Mode::Simulation {
            // Ensure we always have schedulable links for the demo.
            if agg.candidates().is_empty() {
                agg.inject_sim_candidates(&[
                    ("eth0 (模拟)", InterfaceKind::Ethernet, 30, 3),
                    ("wlan0 (模拟)", InterfaceKind::Wifi, 20, 2),
                    ("wwan0 (模拟)", InterfaceKind::Cellular, 25, 1),
                ]);
            }
            let dt = agg.config.health_check_interval_secs.max(1) as f64 * 0.016;
            let n = self.generator.per_tick(Duration::from_secs_f64(dt));
            for _ in 0..n.min(2000) {
                let pkt = self.generator.next_packet(96 + (self.tx_packets.load(Ordering::Relaxed) % 5) as usize * 64);
                if let Some(d) = agg.route(&pkt) {
                    if d.interface.is_some() {
                        self.tx_packets.fetch_add(1, Ordering::Relaxed);
                        // accumulate a guessed throughput: each simulated packet ≈ 150 B
                        self.tx_bytes.fetch_add(150, Ordering::Relaxed);
                    }
                } else {
                    break;
                }
            }
        } else {
            agg.tick();
            if self.last_summary.elapsed() >= std::time::Duration::from_secs(10) {
                let mut per_iface: std::collections::BTreeMap<&str, usize> = Default::default();
                for iface in agg.flow_table.values() {
                    *per_iface.entry(iface).or_insert(0) += 1;
                }
                let dist = per_iface
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let sessions = self.nat.lock().map(|n| n.sessions()).unwrap_or(0);
                let tx = self.tx_packets.load(Ordering::Relaxed);
                let rx = self.nat_rx_packets.load(Ordering::Relaxed);
                tracing::info!(
                    "tun summary: tx={} packets ({:.1} KiB), rx={} packets, sessions={}, distribution: {}",
                    tx,
                    self.tx_bytes.load(Ordering::Relaxed) as f64 / 1024.0,
                    rx,
                    sessions,
                    dist,
                );
                self.last_summary = std::time::Instant::now();
            }
        }
    }

    fn toggle_enabled(&mut self) {
        let mut agg = self.aggregator.lock().expect("aggregator lock");
        agg.config.enabled = !agg.config.enabled;
    }

    fn cycle_theme(&mut self) {
        self.theme_mode = self.theme_mode.cycle();
    }

    fn set_strategy(&mut self, s: Strategy) {
        let mut agg = self.aggregator.lock().expect("aggregator lock");
        agg.config.strategy = s;
    }

    fn set_algorithm(&mut self, a: BalanceAlgorithm) {
        let mut agg = self.aggregator.lock().expect("aggregator lock");
        agg.config.algorithm = a;
    }

    fn iface_action(&mut self, action: IfaceAction) {
        use netmux_core::policy::InterfacePolicy;
        let mut agg = self.aggregator.lock().expect("aggregator lock");
        let cfg = &mut agg.config;
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

/// Per-interface return-path thread: capture inbound packets, reverse-NAT them
/// and inject them back into the TUN so the client sees the reply.
fn capture_loop(
    cap: &RawCapture,
    ifname: &str,
    tun: &Arc<tun::Tun>,
    nat: &Arc<Mutex<NatTable>>,
    rx: &Arc<AtomicU64>,
) {
    tracing::info!("capture thread started on {ifname}");
    let mut buf = [0u8; 65536];
    loop {
        let n = match cap.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("capture {ifname} recv: {e}");
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };
        if n < 20 || buf[0] >> 4 != 4 {
            continue;
        }
        let Some(flow) = packet::parse(&buf[..n]) else {
            continue;
        };
        let (Ok(src_ip), Ok(dst_ip)) = (
            flow.src.parse::<Ipv4Addr>(),
            flow.dst.parse::<Ipv4Addr>(),
        ) else {
            continue;
        };
        let session = {
            let table = nat.lock().expect("nat lock");
            table.lookup_return(flow.proto, src_ip, flow.sport, dst_ip, flow.dport)
        };
        let Some(session) = session else {
            continue;
        };
        // Rewrite dst to the client's TUN address; the port already matches.
        if !packet::rewrite_ipv4_dest(&mut buf[..n], session.client_ip) {
            continue;
        }
        if let Err(e) = tun.write(&buf[..n]) {
            tracing::debug!("tun write: {e}");
        } else {
            rx.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Main data-plane thread: drain the TUN device, NAT every packet to the
/// chosen interface's address and send it out the raw egress socket.
/// Runs for the lifetime of the process, independent of the window.
fn egress_loop(
    tun: &Arc<tun::Tun>,
    nat: &Arc<Mutex<NatTable>>,
    aggregator: &Arc<Mutex<Aggregator>>,
    egress: &HashMap<String, RawEgress>,
    iface_ips: &HashMap<String, Ipv4Addr>,
    tx_pkts: &Arc<AtomicU64>,
    tx_bytes: &Arc<AtomicU64>,
) {
    tracing::info!("data plane: TUN drain thread started");
    let mut buf = [0u8; tun::MAX_PACKET];
    loop {
        let n = match tun.read(&mut buf) {
            Ok(0) | Err(_) => {
                // No packet right now; yield briefly.
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            Ok(n) => n,
        };
        let Some(flow) = packet::parse(&buf[..n]) else {
            continue;
        };
        // Pick the egress interface per the current policy.
        let iface = {
            let mut agg = aggregator.lock().expect("aggregator lock");
            agg.route(&buf[..n]).and_then(|d| d.interface)
        };
        let Some(iface) = iface else {
            continue;
        };
        let Some(egress_ip) = iface_ips.get(&iface).copied() else {
            continue;
        };
        let Some(sock) = egress.get(&iface) else {
            continue;
        };
        let Ok(dst) = flow.dst.parse::<Ipv4Addr>() else {
            continue;
        };
        // Register the NAT session (port-preserving).
        let _session = {
            let mut table = nat.lock().expect("nat lock");
            table.register(&flow, &iface, egress_ip)
        };
        let Some(_session) = _session else {
            continue;
        };
        // Rewrite src to the egress IP, fix checksums, then send.
        let mut out = buf[..n].to_vec();
        if !packet::rewrite_ipv4_source(&mut out, egress_ip) {
            continue;
        }
        match sock.send(&out, dst) {
            Ok(_) => {
                tx_pkts.fetch_add(1, Ordering::Relaxed);
                tx_bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::debug!("egress {iface} send: {e}");
            }
        }
    }
}

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

/// Card container: clean panel, large radius, subtle border.
fn card(t: &Theme) -> Div {
    div()
        .bg(t.panel)
        .border_1()
        .border_color(t.border)
        .rounded_lg()
        .p_4()
}

/// Snappy spring used for UI motion.
fn spring() -> SpringConfig {
    SpringConfig::new(180.0, 26.0, 1.0)
}

/// Fade-in entrance for cards on mount / tab switch (id must be stable).
fn entrance(el: Div, id: &str) -> impl IntoElement {
    el.with_spring(
        format!("{id}-entrance"),
        SpringAnimation::new(spring())
            .to(AnimationPhase(1.0))
            .from(AnimationPhase(0.0)),
        |this, phase| this.opacity(phase.0),
    )
}

/// A proportional fill bar with a spring-animated width.
fn bar_fill(t: &Theme, id: &str, ratio: f64, color: Rgba) -> impl IntoElement {
    let ratio = ratio.clamp(0.0, 1.0) as f32;
    div()
        .flex()
        .w_full()
        .h(px(6.0))
        .bg(t.track)
        .rounded_full()
        .child(
            div()
                .h(px(6.0))
                .bg(color)
                .rounded_full()
                .with_spring(
                    format!("{id}-fill"),
                    SpringAnimation::new(spring())
                        .to(AnimationPhase(ratio))
                        .from(AnimationPhase(0.0)),
                    |this, phase| {
                        this.w(Length::Definite(DefiniteLength::Fraction(phase.0.max(0.0))))
                    },
                ),
        )
}

/// Small muted action button (needs a unique `id` for interactivity).
fn small_btn(
    t: &Theme,
    id: &str,
    label: &str,
    cx: &mut Context<NetMuxApp>,
    f: impl Fn(&mut NetMuxApp) + 'static,
) -> impl IntoElement {
    div()
        .id(id.to_string())
        .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| f(app)))
        .px_3()
        .py_1()
        .rounded_lg()
        .text_sm()
        .bg(t.track)
        .hover(|s| s.bg(t.border))
        .text_color(t.text_muted)
        .child(label.to_string())
}

/// Mode chip (blue for tunnelling, neutral for simulation).
fn mode_chip(t: &Theme, label: &str) -> Div {
    let (bgc, fgc) = if label.contains("TUN") {
        (t.accent, t.text_on_accent)
    } else {
        (t.track, t.text_muted)
    };
    div()
        .bg(bgc)
        .text_color(fgc)
        .rounded_full()
        .px_3()
        .py_1()
        .text_sm()
        .child(label.to_string())
}

/// Neutral informational banner.
fn notice_box(t: &Theme, text: &str) -> Div {
    div()
        .bg(t.panel)
        .border_1()
        .border_color(t.border)
        .rounded_lg()
        .px_4()
        .py_2()
        .text_sm()
        .text_color(t.text_muted)
        .child(text.to_string())
}

/// Aggregation enable/disable pill in the header.
fn toggle_pill(t: &Theme, enabled: bool, cx: &mut Context<NetMuxApp>) -> impl IntoElement {
    let (bgc, label) = if enabled {
        (t.success, "● 聚合运行中")
    } else {
        (t.idle, "○ 聚合已暂停")
    };
    div()
        .id("toggle")
        .on_click(cx.listener(|app, _e: &ClickEvent, _w, _cx| app.toggle_enabled()))
        .bg(bgc)
        .hover(|s| {
            s.bg(if enabled {
                t.success_bright
            } else {
                t.text_muted
            })
        })
        .text_color(t.text_on_accent)
        .rounded_full()
        .px_4()
        .py_1()
        .text_sm()
        .font_weight(FontWeight::MEDIUM)
        .child(label.to_string())
}

/// Theme cycling button.
fn theme_button(t: &Theme, mode: ThemeMode, cx: &mut Context<NetMuxApp>) -> impl IntoElement {
    let icon = match mode {
        ThemeMode::Dark => "🌙",
        ThemeMode::Light => "☀️",
        ThemeMode::System => "🖥",
    };
    div()
        .id("theme")
        .on_click(cx.listener(|app, _e: &ClickEvent, _w, _cx| app.cycle_theme()))
        .px_3()
        .py_1()
        .rounded_lg()
        .text_sm()
        .bg(t.track)
        .hover(|s| s.bg(t.border))
        .text_color(t.text_muted)
        .child(format!("{icon} 主题: {}", mode.label()))
}

// ---------------------------------------------------------------------------
// GPUI application
// ---------------------------------------------------------------------------

impl Render for NetMuxApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Resolve the active palette (light / dark / follow-system).
        self.active_theme = match self.theme_mode {
            ThemeMode::Dark => Theme::dark(),
            ThemeMode::Light => Theme::light(),
            ThemeMode::System => match window.appearance() {
                WindowAppearance::Dark | WindowAppearance::VibrantDark => Theme::dark(),
                _ => Theme::light(),
            },
        };
        let t = self.active_theme;

        // Responsive breakpoint: below this width the sidebar collapses into a
        // horizontal nav row to keep the layout usable on small windows.
        let narrow = window.bounds().size.width < px(720.0);

        let (enabled, mode, candidates) = {
            let agg = self.aggregator.lock().expect("aggregator lock");
            (agg.config.enabled, agg.mode, agg.candidates())
        };
        let mode_label = mode.label();
        let max_speed = candidates
            .iter()
            .map(|c| c.tx_bps + c.rx_bps)
            .fold(0.0, f64::max)
            .max(1.0);

        div()
            .id("root")
            .bg(t.bg)
            .text_color(t.text)
            .flex()
            .flex_row()
            .size_full()
            // Left sidebar navigation (hidden on narrow windows).
            .child(if narrow {
                div().into_any_element()
            } else {
                self.sidebar(t, enabled, cx).into_any_element()
            })
            // Main content: page header + scrollable body.
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .size_full()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap_3()
                            .px_5()
                            .py_4()
                            .border_b_1()
                            .border_color(t.border)
                            .child(div().text_lg().font_weight(FontWeight::SEMIBOLD).child(self.tab_title()))
                            .child(div().flex_1())
                            .child(if narrow {
                                theme_button(&t, self.theme_mode, cx).into_any_element()
                            } else {
                                div().into_any_element()
                            })
                            .child(mode_chip(&t, mode_label))
                            .child(toggle_pill(&t, enabled, cx)),
                    )
                    .child(
                        div()
                            .id("content")
                            .flex_1()
                            .flex()
                            .flex_col()
                            .px_5()
                            .py_4()
                            .gap_3()
                            .overflow_y_scroll()
                            // Narrow windows get a horizontal nav row instead of the sidebar.
                            .child(if narrow {
                                self.nav_row(t, cx).into_any_element()
                            } else {
                                div().into_any_element()
                            })
                            .child(if enabled && mode == Mode::Simulation {
                                notice_box(&t, "模拟演示模式：展示负载均衡/故障转移调度。以 CAP_NET_ADMIN 运行并加 --tun 可启用真实 TUN 聚合。")
                            } else {
                                div()
                            })
                            .child(if let Some(b) = &self.banner {
                                notice_box(&t, b)
                            } else {
                                div()
                            })
                            .child(match self.tab {
                                Tab::Dashboard => self.render_dashboard(t, candidates, max_speed).into_any_element(),
                                Tab::Interfaces => self.render_interfaces(t, candidates, max_speed, narrow, cx).into_any_element(),
                                Tab::Policy => self.render_policy(t, cx).into_any_element(),
                                Tab::Statistics => self.render_statistics(t, candidates, max_speed, narrow).into_any_element(),
                            }),
                    ),
            )
    }
}

impl NetMuxApp {
    fn tab_title(&self) -> String {
        match self.tab {
            Tab::Dashboard => "仪表盘".into(),
            Tab::Interfaces => "接口监控".into(),
            Tab::Policy => "策略配置".into(),
            Tab::Statistics => "性能统计".into(),
        }
    }

    /// Left navigation sidebar.
    fn sidebar(&self, t: Theme, enabled: bool, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .w(px(220.0))
            .h_full()
            .flex()
            .flex_col()
            .bg(t.sidebar)
            .border_r_1()
            .border_color(t.border)
            .p_4()
            .gap_1()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py_2()
                    .child(div().size(px(10.0)).rounded_full().bg(t.accent_bright))
                    .child(div().text_lg().font_weight(FontWeight::BOLD).child("NetMux"))
                    .child(div().text_xs().text_color(t.text_muted).child("v0.1.0")),
            )
            .child(div().h(px(1.0)).w_full().bg(t.border).my_3())
            .child(self.nav_item(t, "仪表盘", Tab::Dashboard, cx))
            .child(self.nav_item(t, "接口监控", Tab::Interfaces, cx))
            .child(self.nav_item(t, "策略配置", Tab::Policy, cx))
            .child(self.nav_item(t, "性能统计", Tab::Statistics, cx))
            .child(div().flex_1())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .px_2()
                    .py_2()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .size(px(6.0))
                                    .rounded_full()
                                    .bg(if enabled { t.success_bright } else { t.text_muted }),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(t.text_muted)
                                    .child(if enabled { "聚合运行中" } else { "聚合已暂停" }.to_string()),
                            ),
                    )
                    .child(theme_button(&t, self.theme_mode, cx)),
            )
    }

    /// Vertical sidebar navigation item.
    fn nav_item(&self, t: Theme, label: &str, tab: Tab, cx: &mut Context<Self>) -> impl IntoElement {
        let active = self.tab == tab;
        let b = div()
            .id(format!("nav-{label}"))
            .w_full()
            .px_3()
            .py_2()
            .rounded_lg()
            .text_sm();
        if active {
            b.bg(t.accent)
                .text_color(t.text_on_accent)
                .font_weight(FontWeight::SEMIBOLD)
                .child(label.to_string())
                .into_any()
        } else {
            b.text_color(t.text_muted)
                .hover(|s| s.bg(t.panel).text_color(t.text))
                .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| app.tab = tab))
                .child(label.to_string())
                .into_any()
        }
    }

    /// Horizontal nav row used on narrow windows.
    fn nav_row(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .gap_2()
            .flex_wrap()
            .child(self.nav_item(t, "仪表盘", Tab::Dashboard, cx))
            .child(self.nav_item(t, "接口监控", Tab::Interfaces, cx))
            .child(self.nav_item(t, "策略配置", Tab::Policy, cx))
            .child(self.nav_item(t, "性能统计", Tab::Statistics, cx))
    }

    fn render_dashboard(
        &self,
        t: Theme,
        candidates: Vec<netmux_core::CandidateIface>,
        max_speed: f64,
    ) -> impl IntoElement {
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
            .gap_3()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_3()
                    .flex_wrap()
                    .child(entrance(kpi(&t, "已启用接口", format!("{used}/{healthy}")), "kpi-1"))
                    .child(entrance(
                        kpi(
                            &t,
                            "聚合带宽(估算)",
                            netmux_core::stats::fmt_bps(self.tx_bytes.load(Ordering::Relaxed) as f64),
                        ),
                        "kpi-2",
                    ))
                    .child(entrance(
                        kpi(&t, "转发包数", format!("{}", self.tx_packets.load(Ordering::Relaxed))),
                        "kpi-3",
                    ))
                    .child(entrance(kpi(&t, "当前负载", format!("{:.1} Mbps", total_cap / 1e6)), "kpi-4")),
            )
            .child(div().text_sm().text_color(t.text_muted).child("负载均衡示意"))
            .child(self.aggregated_bar(t, candidates, max_speed))
    }

    fn aggregated_bar(
        &self,
        t: Theme,
        candidates: Vec<netmux_core::CandidateIface>,
        max_speed: f64,
    ) -> impl IntoElement {
        let mut body = div().flex().flex_col().gap_2();
        for c in candidates {
            if !c.policy.enabled {
                continue;
            }
            let load = (c.tx_bps + c.rx_bps) / max_speed.max(1.0);
            let tx = netmux_core::stats::fmt_bps(c.tx_bps);
            let rx = netmux_core::stats::fmt_bps(c.rx_bps);
            let status_color = if c.healthy { t.success_bright } else { t.danger };
            let card_el = card(&t)
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(div().size(px(8.0)).rounded_full().bg(status_color))
                        .child(div().font_weight(FontWeight::SEMIBOLD).child(c.name.clone()))
                        .child(div().text_xs().text_color(t.text_muted).child(kind_label(c.kind)))
                        .child(div().flex_1())
                        .child(div().text_xs().text_color(t.text_muted).child(format!("TX {tx}  RX {rx}"))),
                )
                .child(bar_fill(&t, &format!("agg-{}", c.name), load, t.accent_bright));
            body = body.child(entrance(card_el, &format!("aggcard-{}", c.name)));
        }
        body
    }

    fn render_interfaces(
        &self,
        t: Theme,
        candidates: Vec<netmux_core::CandidateIface>,
        max_speed: f64,
        _narrow: bool,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let mut rows = div().flex().flex_col().gap_2();

        if candidates.is_empty() {
            rows = rows.child(card(&t).child("未发现物理网络接口。"));
        }

        for c in candidates {
            let name_for_toggle = c.name.clone();
            let enable_state = c.policy.enabled;
            let status_color = if c.healthy { t.success_bright } else { t.danger };
            let mut row = card(&t).flex().flex_col().gap_2();
            row = row.child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .id(format!("enable-{name_for_toggle}"))
                            .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| {
                                app.iface_action(IfaceAction::Enable(
                                    name_for_toggle.clone(),
                                    !enable_state,
                                ));
                            }))
                            .px_3()
                            .py_1()
                            .rounded_full()
                            .text_sm()
                            .bg(if enable_state { t.success } else { t.idle })
                            .text_color(t.text_on_accent)
                            .child(if enable_state { "已启用" } else { "已停用" }.to_string()),
                    )
                    .child(div().size(px(8.0)).rounded_full().bg(status_color))
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(c.name.clone()))
                    .child(div().text_xs().text_color(t.text_muted).child(kind_label(c.kind)))
                    .child(div().flex_1())
                    .child(div().text_xs().text_color(t.text_muted).child(format!("优先级 {}", c.policy.priority)))
                    .child(div().text_xs().text_color(t.text_muted).child(format!("权重 {}", c.policy.weight))),
            );
            row = row.child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(div().text_xs().text_color(t.bar_tx).child("↓ TX"))
                    .child(bar_fill(&t, &format!("tx-{}", c.name), c.tx_bps / max_speed.max(1.0), t.bar_tx)),
            );
            row = row.child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_2()
                    .child(div().text_xs().text_color(t.bar_rx).child("↑ RX"))
                    .child(bar_fill(&t, &format!("rx-{}", c.name), c.rx_bps / max_speed.max(1.0), t.bar_rx)),
            );
            row = row.child(
                div()
                    .flex()
                    .flex_row()
                    .flex_wrap()
                    .gap_2()
                    .child({
                        let n = c.name.clone();
                        small_btn(&t, &format!("pri-plus-{n}"), "优先级 +", cx, move |app| {
                            app.iface_action(IfaceAction::Priority(n.clone(), 1));
                        })
                    })
                    .child({
                        let n = c.name.clone();
                        small_btn(&t, &format!("pri-minus-{n}"), "优先级 -", cx, move |app| {
                            app.iface_action(IfaceAction::Priority(n.clone(), -1));
                        })
                    })
                    .child({
                        let n = c.name.clone();
                        small_btn(&t, &format!("wei-plus-{n}"), "权重 +", cx, move |app| {
                            app.iface_action(IfaceAction::Weight(n.clone(), 1));
                        })
                    })
                    .child({
                        let n = c.name.clone();
                        small_btn(&t, &format!("wei-minus-{n}"), "权重 -", cx, move |app| {
                            app.iface_action(IfaceAction::Weight(n.clone(), -1));
                        })
                    }),
            );
            rows = rows.child(entrance(row, &format!("iface-{}", c.name)));
        }
        rows
    }

    fn render_policy(&self, t: Theme, cx: &mut Context<Self>) -> impl IntoElement {
        let (strategy, algo) = {
            let agg = self.aggregator.lock().expect("aggregator lock");
            (agg.config.strategy, agg.config.algorithm)
        };
        let mut s = div().flex().flex_col().gap_3();

        s = s.child(div().text_sm().text_color(t.text_muted).child("聚合策略"));
        s = s.child(
            div()
                .flex()
                .flex_row()
                .gap_3()
                .flex_wrap()
                .child(strategy_card(&t, "负载均衡", "在多接口间分配新连接，聚合带宽", Strategy::LoadBalance, strategy, cx))
                .child(strategy_card(&t, "故障转移", "按优先级自动切换到最高在线接口", Strategy::Failover, strategy, cx)),
        );

        s = s.child(div().mt_2().text_sm().text_color(t.text_muted).child("负载均衡算法（仅负载均衡模式生效）"));
        s = s.child(
            div()
                .flex()
                .flex_row()
                .gap_3()
                .flex_wrap()
                .child(algo_card(&t, "哈希", "按五元组固定分配，连接保持稳定", BalanceAlgorithm::Hash, algo, cx))
                .child(algo_card(&t, "轮询", "加权轮转，均匀分配新连接", BalanceAlgorithm::RoundRobin, algo, cx))
                .child(algo_card(&t, "最小负载", "实时负载最低的接口优先", BalanceAlgorithm::LeastLoaded, algo, cx)),
        );

        s = s.child(
            div()
                .bg(t.panel)
                .border_1()
                .border_color(t.border)
                .rounded_lg()
                .px_4()
                .py_2()
                .text_sm()
                .text_color(t.text_muted)
                .child("说明：故障转移模式按优先级选择最高的在线接口；负载均衡模式通过上述算法在多个接口间分配新建连接。可在「接口监控」中调整各接口的优先级与权重。"),
        );
        s
    }

    fn render_statistics(
        &self,
        t: Theme,
        candidates: Vec<netmux_core::CandidateIface>,
        max_speed: f64,
        narrow: bool,
    ) -> impl IntoElement {
        let mut rows = div().flex().flex_col().gap_2();
        let total_tx: f64 = candidates.iter().map(|c| c.tx_bps).sum();
        let total_rx: f64 = candidates.iter().map(|c| c.rx_bps).sum();
        rows = rows.child(entrance(
            card(&t)
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(div().text_sm().text_color(t.text_muted).child("总计"))
                .child(div().flex_1())
                .child(div().text_sm().text_color(t.bar_tx).child(format!("↑ TX {}", netmux_core::stats::fmt_bps(total_tx))))
                .child(div().text_sm().text_color(t.bar_rx).child(format!("↓ RX {}", netmux_core::stats::fmt_bps(total_rx)))),
            "stat-total",
        ));
        for c in candidates {
            let load = (c.tx_bps + c.rx_bps) / max_speed.max(1.0);
            let name_w = if narrow { px(90.0) } else { px(150.0) };
            let row_el = card(&t)
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(div().w(name_w).font_weight(FontWeight::SEMIBOLD).child(c.name.clone()))
                .child(div().text_xs().text_color(t.bar_tx).child(netmux_core::stats::fmt_bps(c.tx_bps)))
                .child(div().text_xs().text_color(t.bar_rx).child(netmux_core::stats::fmt_bps(c.rx_bps)))
                .child(bar_fill(&t, &format!("stat-{}", c.name), load, t.bar_neutral));
            rows = rows.child(entrance(row_el, &format!("statrow-{}", c.name)));
        }
        rows.child(entrance(
            card(&t)
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(div().text_sm().child(format!(
                    "当前活跃流记录: {} 条",
                    self.aggregator.lock().expect("aggregator lock").flow_table.len()
                ))),
            "stat-flows",
        ))
    }
}

fn strategy_card(
    t: &Theme,
    label: &str,
    desc: &str,
    value: Strategy,
    current: Strategy,
    cx: &mut Context<NetMuxApp>,
) -> impl IntoElement {
    let active = value == current;
    div()
        .id(format!("strategy-{label}"))
        .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| app.set_strategy(value)))
        .flex()
        .flex_col()
        .gap_1()
        .p_4()
        .rounded_lg()
        .flex_grow_1()
        .flex_basis(px(240.0))
        .border_1()
        .border_color(if active { t.accent_bright } else { t.border })
        .bg(if active { t.panel_active } else { t.panel })
        .hover(|s| {
            if active {
                s
            } else {
                s.bg(t.panel_hover)
            }
        })
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(if active { "●" } else { "○" }.to_string())
                .child(div().font_weight(FontWeight::SEMIBOLD).child(label.to_string())),
        )
        .child(div().text_xs().text_color(t.text_muted).child(desc.to_string()))
}

fn algo_card(
    t: &Theme,
    label: &str,
    desc: &str,
    value: BalanceAlgorithm,
    current: BalanceAlgorithm,
    cx: &mut Context<NetMuxApp>,
) -> impl IntoElement {
    let active = value == current;
    div()
        .id(format!("algo-{label}"))
        .on_click(cx.listener(move |app, _e: &ClickEvent, _w, _cx| app.set_algorithm(value)))
        .flex()
        .flex_col()
        .gap_1()
        .p_4()
        .rounded_lg()
        .flex_grow_1()
        .flex_basis(px(220.0))
        .border_1()
        .border_color(if active { t.accent_bright } else { t.border })
        .bg(if active { t.panel_active } else { t.panel })
        .hover(|s| {
            if active {
                s
            } else {
                s.bg(t.panel_hover)
            }
        })
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(if active { "●" } else { "○" }.to_string())
                .child(div().font_weight(FontWeight::SEMIBOLD).child(label.to_string())),
        )
        .child(div().text_xs().text_color(t.text_muted).child(desc.to_string()))
}

/// Key performance indicator card; wraps responsively via flex-basis.
fn kpi(t: &Theme, label: &str, value: String) -> Div {
    card(t)
        .flex()
        .flex_col()
        .gap_1()
        .flex_grow_1()
        .flex_basis(px(200.0))
        .child(div().text_xs().text_color(t.text_muted).child(label.to_string()))
        .child(div().text_xl().font_weight(FontWeight::BOLD).child(value))
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

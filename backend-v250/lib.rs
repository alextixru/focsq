// Ported from amurcanov/csqtt v2.5.0; see PROVENANCE.md.

mod auth;
mod captcha;
mod captcha_slider;
mod cpu_task;
pub mod direct_relay;
mod dispatcher;
mod dns;
#[path = "shared/dtls.rs"]
pub mod dtls;
mod events;
mod logging;
mod namegen;
mod obfs;
mod packet;
mod profiles;
mod protocol;
mod repair;
mod session;
mod sni;
#[path = "shared/spsc_ring.rs"]
mod spsc_ring;
mod srtp_mode;
mod stats;
mod stun_codec;
mod tun;
mod turn;
mod turn_core;
mod turn_endpoint;
mod turn_ip_pool;
mod turn_stream;
mod vk_js_calls;
#[path = "shared/wire_protocol.rs"]
mod wire_protocol;
mod worker;
mod wrap;

use anyhow::{Context, Result, bail};
use auth::{VkAuth, VkHashCheck};
use captcha::CaptchaSolver;
use dispatcher::{Dispatcher, Termination};
use events::Events;
use obfs::ObfsMode;
use packet::{PacketPool, packet_pool_size};
use repair::RepairState;
use session::ShutdownCoordinator;
use srtp_mode::SrtpMode;
use stats::Stats;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use turn_endpoint::TurnTransportMode;
use turn_ip_pool::{TurnIpPool, parse_custom_turn_ips};
use worker::{
    GROUPS_PER_CREDENTIAL, GroupContext, PauseGate, RuntimeParams, WORKER_START_INTERVAL,
    WORKERS_PER_GROUP, WorkerStartPacer, parse_hashes, run_groups,
};
use wrap::derive_wrap_key;

#[cfg(target_os = "macos")]
pub mod tun_darwin;
const MAX_VK_HASHES: usize = 6;
pub const MAX_WORKERS: usize = 100;
type StdinLine = std::io::Result<String>;
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub custom_turn_ips: String,
    pub turn_transport: String,
    pub srtp_mode: String,
    pub exact_workers: bool,
    pub domain_routing: bool,
    pub exclude_ru_zones: bool,
    pub template_domains: bool,
    pub domain_whitelist: bool,
    pub direct_domains: String,
    pub domains_file: Vec<String>,
    pub ip_routing: bool,
    pub ip_whitelist: bool,
    pub direct_ips: String,

    pub turn: String,
    pub port: String,
    pub listen: String,
    pub vk: String,
    pub vk_hash_mode: String,
    pub peer: String,
    pub workers: usize,
    pub allow_hash_redistribution: bool,
    pub device_id: String,
    pub password: String,
    pub vk_auth_mode: String,
    pub captcha_mode: String,
    pub fingerprint: String,
    pub client_ids: String,
    pub obfs: String,
    pub generation: u64,
    pub salt: String,
    pub tun_uds: String,
    pub validate_vk_hashes: bool,
    pub vk_js_token: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            custom_turn_ips: String::new(),
            turn_transport: "udp".to_owned(),
            srtp_mode: "auto".to_owned(),
            exact_workers: false,
            domain_routing: false,
            exclude_ru_zones: false,
            template_domains: false,
            domain_whitelist: false,
            direct_domains: String::new(),
            domains_file: Vec::new(),
            ip_routing: false,
            ip_whitelist: false,
            direct_ips: String::new(),

            turn: "".to_string(),
            port: "".to_string(),
            listen: "127.0.0.1:9000".to_string(),
            vk: "".to_string(),
            vk_hash_mode: "manual".to_string(),
            peer: "".to_string(),
            workers: 18,
            allow_hash_redistribution: false,
            device_id: "unknown".to_string(),
            password: "".to_string(),
            vk_auth_mode: "vkcalls".to_string(),
            captcha_mode: "auto".to_string(),
            fingerprint: "chrome".to_string(),
            client_ids: "".to_string(),
            obfs: "unified".to_string(),
            generation: 0,
            salt: "".to_string(),
            tun_uds: "".to_string(),
            validate_vk_hashes: false,
            vk_js_token: "".to_string(),
        }
    }
}

pub fn set_log_callback(cb: Box<dyn Fn(String) + Send + Sync>) {
    logging::set_log_callback(cb);
}

/// Принудительное включение структурированных событий (__CSQTT_EVENT__|...)
/// для embedded-режима, когда ядро живёт в процессе host-приложения
/// и переменную окружения CSQTT_EVENTS задать нельзя.
static EVENTS_FORCED: AtomicBool = AtomicBool::new(false);

pub fn set_events_enabled(enabled: bool) {
    EVENTS_FORCED.store(enabled, Ordering::Release);
}

/// Канал управления активной сессией (замена stdin для встроенного режима)
static CONTROL_TX: Mutex<Option<tokio::sync::mpsc::Sender<StdinLine>>> = Mutex::new(None);

fn set_control_channel(tx: tokio::sync::mpsc::Sender<StdinLine>) {
    if let Ok(mut guard) = CONTROL_TX.lock() {
        *guard = Some(tx);
    }
}

fn clear_control_channel() {
    if let Ok(mut guard) = CONTROL_TX.lock() {
        *guard = None;
    }
}

/// Отправить команду управления активной сессии ("PAUSE", "RESUME", "STOP",
/// "PATH_VALIDATE:", "CAPTCHA_RESULT|..."). Возвращает false, если клиент не запущен.
pub fn submit_control_line(line: String) -> bool {
    let guard = match CONTROL_TX.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };
    match guard.as_ref() {
        Some(tx) => tx.try_send(Ok(line)).is_ok(),
        None => false,
    }
}

/// Активный решатель капчи текущей сессии (получатель CAPTCHA_RESULT)
static ACTIVE_CAPTCHA: Mutex<Option<Arc<CaptchaSolver>>> = Mutex::new(None);

fn set_active_captcha(solver: Arc<CaptchaSolver>) {
    if let Ok(mut guard) = ACTIVE_CAPTCHA.lock() {
        *guard = Some(solver);
    }
}

fn clear_active_captcha() {
    if let Ok(mut guard) = ACTIVE_CAPTCHA.lock() {
        *guard = None;
    }
}

/// Передать результат решения капчи из host-приложения.
/// Возвращает false, если клиент не запущен или ответ устарел (канал занят).
pub fn submit_captcha_result(result: String) -> bool {
    let guard = match ACTIVE_CAPTCHA.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };
    match guard.as_ref() {
        Some(solver) => solver.submit_result(result),
        None => false,
    }
}

static RUNNING: AtomicBool = AtomicBool::new(false);

struct SessionCleanup(CancellationToken);
impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.0.cancel();
        clear_control_channel();
        clear_active_captcha();
        #[cfg(target_os = "macos")]
        tun_darwin::teardown();
        RUNNING.store(false, Ordering::Release);
    }
}

pub async fn run_client(
    arguments: ClientConfig,
    external_cancel: Option<CancellationToken>,
) -> Result<()> {
    if RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        bail!("Клиент уже запущен");
    }
    let cancel = external_cancel.unwrap_or_default();
    let _cleanup = SessionCleanup(cancel.clone());
    run(arguments, cancel).await
}
async fn run(arguments: ClientConfig, cancel: CancellationToken) -> Result<()> {
    if arguments.validate_vk_hashes {
        run_vk_hash_validation(&arguments).await?;
        return Ok(());
    }
    let js_hash_mode = arguments.vk_hash_mode == "auto_js";
    let mut vk_auth_mode = arguments.vk_auth_mode.clone();
    let js_auth_mode = if vk_auth_mode == "auto_js" && !js_hash_mode {
        crate::log_error!(
            "[КЛИЕНТ] Предупреждение: режим Auto JS неприменим без хешей Auto JS, переключаем на vkcalls"
        );
        vk_auth_mode = "vkcalls".to_owned();
        false
    } else {
        vk_auth_mode == "auto_js"
    };
    if arguments.peer.is_empty() || (!js_hash_mode && arguments.vk.is_empty()) {
        bail!("[КЛИЕНТ] Нужны -peer и хеши VK");
    }
    let password = arguments.password.clone();
    if password.is_empty() {
        bail!("[КЛИЕНТ] Укажите пароль подключения");
    }
    let (control_tx, stdin) = tokio::sync::mpsc::channel(64);
    set_control_channel(control_tx);
    let peer = resolve_peer(&arguments.peer).await?;
    let mode = ObfsMode::parse(&arguments.obfs)?;
    let turn_transport = TurnTransportMode::parse(&arguments.turn_transport)?;
    let srtp_mode = SrtpMode::parse(&arguments.srtp_mode)?;
    let wrap_key = derive_wrap_key(&password)?;
    let client_wrap_key = wrap_key;
    let session_profile = profiles::random_profile(&arguments.fingerprint);
    let mut js_calls = None;
    let mut js_credential_broker = None;
    let hash_source = if js_hash_mode {
        let bootstrap = vk_js_calls::Bootstrap {
            token: arguments.vk_js_token.clone(),
        };
        let started = vk_js_calls::start(bootstrap, js_auth_mode, &session_profile).await?;
        let hashes = started.hashes.join(",");
        js_calls = Some(started.active);
        js_credential_broker = Some(started.credential_broker);
        hashes
    } else {
        arguments.vk.clone()
    };
    let hashes: Vec<_> = parse_hashes(&hash_source)
        .into_iter()
        .take(MAX_VK_HASHES)
        .collect();
    if hashes.is_empty() {
        bail!("[КЛИЕНТ] Нет хешей VK");
    }
    let workers = if arguments.exact_workers {
        arguments.workers.clamp(3, MAX_WORKERS)
    } else {
        normalize_worker_count(arguments.workers)
    };
    let groups = workers.div_ceil(WORKERS_PER_GROUP);
    let captcha = CaptchaSolver::new(&arguments.captcha_mode, cancel.clone());
    set_active_captcha(captcha.clone());
    let events = Events::new(EVENTS_FORCED.load(Ordering::Acquire));
    let client_ids: Vec<_> = arguments
        .client_ids
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    let auth = Arc::new(VkAuth::new(
        &vk_auth_mode,
        session_profile,
        &client_ids,
        captcha.clone(),
        js_credential_broker,
    ));
    let stats = Arc::new(Stats::default());
    let paused = Arc::new(PauseGate::new());
    let finish_js_calls = Arc::new(AtomicBool::new(false));
    #[cfg(target_os = "macos")]
    if !arguments.tun_uds.is_empty() {
        schedule_vk_endpoint_excludes(cancel.clone());
    }
    events.process(std::process::id());
    let pool = PacketPool::new(packet_pool_size(MAX_WORKERS));
    let tun_uds = (!arguments.tun_uds.is_empty()).then_some(arguments.tun_uds.clone());
    #[cfg(target_os = "macos")]
    let native_tun = tun_uds.is_some();
    #[cfg(target_os = "macos")]
    let peer_ip = peer.ip().to_string();
    let mut direct_domains = crate::sni::parse_direct_domains(&arguments.direct_domains);
    for file_path in &arguments.domains_file {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            let file_domains = crate::sni::parse_direct_domains(&content);
            for domain in file_domains {
                if !direct_domains.contains(&domain) {
                    direct_domains.push(domain);
                }
            }
        }
    }
    direct_domains.truncate(1024);
    let ip_rules = crate::sni::parse_ip_rules(&arguments.direct_ips);
    let domain_routing = dispatcher::DomainRoutingConfig {
        enabled: arguments.domain_routing,
        exclude_ru_zones: arguments.exclude_ru_zones,
        template_domains: arguments.template_domains,
        direct_domains: Arc::new(direct_domains),
        is_whitelist: arguments.domain_whitelist,
        ip_routing_enabled: arguments.ip_routing,
        ip_is_whitelist: arguments.ip_whitelist,
        ip_rules: Arc::new(ip_rules),
    };
    let dispatcher_result = Dispatcher::start_with_domain_routing(
        &arguments.listen,
        tun_uds,
        pool.clone(),
        stats.clone(),
        cancel.clone(),
        domain_routing,
        workers,
    )
    .await;
    let (dispatcher, local_port) = match dispatcher_result {
        Ok(value) => value,
        Err(error) => {
            if let Some(active) = js_calls.take() {
                active.leave_creator().await;
            }
            return Err(error);
        }
    };
    let control_task = start_control_input(
        cancel.clone(),
        paused.clone(),
        captcha,
        events.clone(),
        finish_js_calls.clone(),
        dispatcher.clone(),
        stdin,
    );
    let local_port: Arc<str> = Arc::from(local_port);
    let raw_turn_ips = if !arguments.custom_turn_ips.is_empty() {
        &arguments.custom_turn_ips
    } else {
        &arguments.turn
    };
    let turn_ip_pool = Arc::new(TurnIpPool::new(
        parse_custom_turn_ips(raw_turn_ips),
        MAX_WORKERS,
    ));
    let initial_workers = workers;
    let scale_notify = Arc::new(tokio::sync::Notify::new());
    let params_workers = Arc::new(AtomicUsize::new(initial_workers));
    let params = Arc::new(RuntimeParams {
        peer,
        turn_host: (!arguments.turn.is_empty()).then(|| Arc::from(arguments.turn.as_str())),
        turn_port: (!arguments.port.is_empty()).then(|| Arc::from(arguments.port.as_str())),
        turn_ip_pool,
        turn_transport,
        srtp_mode,
        hashes: hashes.into(),
        wrap_key,
        client_wrap_key,
        mode,
        generation: arguments.generation,
        salt: Arc::from(arguments.salt.as_str()),
        local_port: local_port.clone(),
        password: Arc::from(password.as_str()),
        workers: params_workers,
        configured_workers: workers,
    });
    print_configuration(
        &arguments,
        auth.client_ids(),
        workers,
        groups,
        &params,
        &local_port,
    );
    let repair = RepairState::new(MAX_WORKERS);
    let stats_task = tokio::spawn(stats.clone().run(events.clone(), cancel.clone()));
    let (config_tx, mut config_rx) = tokio::sync::mpsc::channel::<String>(32);
    let config_events = events.clone();
    #[cfg(target_os = "macos")]
    let config_cancel = cancel.clone();
    let config_task = tokio::spawn(async move {
        let mut last_config = None;
        while let Some(config) = config_rx.recv().await {
            if last_config.as_deref() == Some(config.as_str()) {
                continue;
            }
            if let Some(value) = config.strip_prefix("TUNCONF:") {
                dns::mark_tunnel_active();
                let mut fields = value.splitn(3, ':');
                let ip = fields.next().unwrap_or_default();
                let dns = fields.next().unwrap_or_default();
                crate::log_error!("[КЛИЕНТ] Tunnel IP: {ip}/32 | DNS: {dns}");
                #[cfg(target_os = "macos")]
                if native_tun {
                    if let Err(error) = tun_darwin::apply_tunconf(ip, dns, &peer_ip).await {
                        config_events.error(
                            "tun_config",
                            &format!("Настройка сети: {error:#}"),
                            true,
                        );
                        config_cancel.cancel();
                        return;
                    }
                }
            }
            config_events.config(&config);
            last_config = Some(config);
        }
    });
    let (ready_credential_tx, ready_credential_rx) =
        if should_leave_js_creator(js_hash_mode, js_auth_mode) {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
    let context = Arc::new(GroupContext {
        params,
        auth,
        dispatcher: dispatcher.clone(),
        pool,
        stats,
        events: events.clone(),
        paused,
        config_tx,
        start_pacer: Arc::new(WorkerStartPacer::new(WORKER_START_INTERVAL)),
        credential_pacer: Arc::new(tokio::sync::Mutex::new(())),
        ready_credential_tx,
        config_sent: Arc::new(AtomicBool::new(false)),
        config_in_flight: Arc::new(AtomicBool::new(false)),
        server_stream_repair: Arc::new(AtomicBool::new(false)),
        repair,
        shutdown: Arc::new(ShutdownCoordinator::new()),
        cancel: cancel.clone(),
        scale_notify,
    });
    let required_ready_bots = required_js_ready_bots(groups);
    if js_auth_mode {
        crate::log_error!("[VK JS] Создатель удерживает звонок");
    }
    let creator_leave_task = match (js_calls.as_ref(), ready_credential_rx) {
        (Some(active), Some(receiver)) => Some(tokio::spawn(leave_js_creator_after_ready_workers(
            active.clone(),
            receiver,
            required_ready_bots,
            cancel.clone(),
        ))),
        _ => None,
    };
    let shutdown_events = events.clone();
    let tun_lost_events = events.clone();
    let tun_io_lost = dispatcher.tun_io_lost.clone();
    let lost_cancel = cancel.clone();
    let tun_monitor = tokio::spawn(async move {
        tokio::select! {
            _ = lost_cancel.cancelled() => {},
            _ = tun_io_lost.notified() => {
                tun_lost_events.error("tun_lost", "Сетевой интерфейс закрыт", true);
                lost_cancel.cancel();
            }
        }
    });
    let groups_future = run_groups(context);
    tokio::pin!(groups_future);
    let groups_completed = tokio::select! {
        _ = &mut groups_future => true,

        _ = cancel.cancelled() => false,
    };
    cancel.cancel();
    if !groups_completed {
        groups_future.await;
    }
    dispatcher.shutdown().await;
    stats_task.abort();
    config_task.abort();
    control_task.abort();
    tun_monitor.abort();
    let _ = stats_task.await;
    let _ = config_task.await;
    let _ = control_task.await;
    let _ = tun_monitor.await;
    if let Some(mut task) = creator_leave_task
        && tokio::time::timeout(Duration::from_secs(9), &mut task)
            .await
            .is_err()
    {
        task.abort();
        let _ = task.await;
    }
    if let Some(active) = js_calls.take() {
        if finish_js_calls.load(Ordering::Acquire) {
            active.finish().await;
        } else {
            active.leave_creator().await;
        }
    }
    let termination = dispatcher.termination();
    shutdown_events.stopped();
    crate::log_error!("[КЛИЕНТ] Все воркеры завершены");
    match termination {
        None => Ok(()),
        Some(Termination::TunLost) => bail!("Сетевой интерфейс закрыт"),
        Some(Termination::Fatal) => bail!("аварийное завершение TUN или UDP задачи"),
    }
}

async fn leave_js_creator_after_ready_workers(
    active: vk_js_calls::ActiveCalls,
    receiver: tokio::sync::mpsc::UnboundedReceiver<usize>,
    required_ready_bots: usize,
    cancel: CancellationToken,
) {
    let all_ready = wait_for_js_credential_readiness(receiver, required_ready_bots, cancel).await;
    if all_ready {
        crate::log_error!("[VK JS] TURN-боты готовы, создатель выходит из звонка");
    }
    let _ = tokio::time::timeout(Duration::from_secs(8), active.leave_creator()).await;
}

async fn wait_for_js_credential_readiness(
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<usize>,
    expected_credentials: usize,
    cancel: CancellationToken,
) -> bool {
    let mut ready = HashSet::with_capacity(expected_credentials);
    while ready.len() < expected_credentials {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            credential = receiver.recv() => match credential {
                Some(credential) => {
                    ready.insert(credential);
                }
                None => break,
            },
        }
    }
    ready.len() == expected_credentials
}

fn required_js_ready_bots(groups: usize) -> usize {
    groups.div_ceil(GROUPS_PER_CREDENTIAL).clamp(1, 2)
}

fn normalize_worker_count(requested: usize) -> usize {
    if requested <= 5 {
        return 5;
    }
    requested.clamp(WORKERS_PER_GROUP, MAX_WORKERS) / WORKERS_PER_GROUP * WORKERS_PER_GROUP
}

fn should_leave_js_creator(js_hash_mode: bool, js_auth_mode: bool) -> bool {
    js_hash_mode && js_auth_mode
}

async fn run_vk_hash_validation(arguments: &ClientConfig) -> Result<()> {
    let hashes: Vec<_> = parse_hashes(&arguments.vk)
        .into_iter()
        .take(MAX_VK_HASHES)
        .collect();
    if hashes.is_empty() {
        bail!("[КЛИЕНТ] Нет хешей VK для проверки");
    }
    let client_ids: Vec<_> = arguments
        .client_ids
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    for (hash, result) in auth::check_vk_hashes(&arguments.fingerprint, &client_ids, &hashes).await
    {
        let payload = match result {
            VkHashCheck::Valid => serde_json::json!({
                "hash": hash,
                "status": "valid"
            }),
            VkHashCheck::Invalid { code, message } => serde_json::json!({
                "hash": hash,
                "status": "invalid",
                "code": code,
                "message": message
            }),
            VkHashCheck::Unavailable { message } => serde_json::json!({
                "hash": hash,
                "status": "unavailable",
                "message": message
            }),
        };
        println!("HASH_CHECK:{payload}");
    }
    Ok(())
}

async fn resolve_peer(peer: &str) -> Result<SocketAddr> {
    let mut last_error = None;
    for _ in 0..15 {
        match dns::resolve_socket(peer).await {
            Ok(address) => return Ok(address),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("пустой DNS-ответ для пира")))
        .context("ошибка разбора пира")
}

fn start_control_input(
    cancel: CancellationToken,
    paused: Arc<PauseGate>,
    captcha: Arc<CaptchaSolver>,
    events: Events,
    finish_js_calls: Arc<AtomicBool>,
    dispatcher: Arc<Dispatcher>,
    mut stdin: tokio::sync::mpsc::Receiver<StdinLine>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let control_required = events.enabled();
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => return,
                next = stdin.recv() => next,
            };
            let line = match next {
                Some(Ok(line)) => line,
                Some(Err(error)) => {
                    crate::log_error!("[КЛИЕНТ] Ошибка канала управления: {error}");
                    if control_required {
                        cancel.cancel();
                    }
                    return;
                }
                None => {
                    if control_required {
                        crate::log_error!("[КЛИЕНТ] Канал управления закрыт");
                        cancel.cancel();
                    }
                    return;
                }
            };
            let line = line.trim();
            if !line.contains("error:tunnel stopped") && line != "FINISH_VK_CALLS" {
                crate::log_error!("[STDIN] {}", loggable_stdin_line(line));
            }
            match line {
                "PAUSE" => paused.set_paused(true),
                "RESUME" => paused.set_paused(false),
                "FINISH_VK_CALLS" => finish_js_calls.store(true, Ordering::Release),
                "STOP" => {
                    crate::log_error!("[КЛИЕНТ] Получена команда STOP");
                    cancel.cancel();
                    return;
                }
                _ => {
                    if let Some(result) = line.strip_prefix("CAPTCHA_RESULT|") {
                        if captcha.submit_result(result.to_owned()) {
                            crate::log_error!("[КАПЧА] Результат от Kotlin записан в канал");
                        } else {
                            crate::log_error!(
                                "[КАПЧА] Канал результата уже заполнен, устаревший ответ отклонён"
                            );
                        }
                    } else if let Some(payload) = line.strip_prefix("UPDATE_DOMAINS|") {
                        dispatcher.update_domain_routing(payload);
                    }
                }
            }
        }
    })
}

fn loggable_stdin_line(line: &str) -> &str {
    if line.starts_with("CAPTCHA_RESULT|") {
        "CAPTCHA_RESULT|<скрыто>"
    } else if line.starts_with("VK_JS_BOOTSTRAP:") {
        "VK_JS_BOOTSTRAP:<скрыто>"
    } else {
        line
    }
}

fn print_configuration(
    arguments: &ClientConfig,
    client_ids: String,
    workers: usize,
    groups: usize,
    params: &RuntimeParams,
    local_port: &str,
) {
    let hashes = params.hashes.len();
    let turn_transport = params.turn_transport;
    let srtp_mode = params.srtp_mode;
    let captcha = match arguments.captcha_mode.as_str() {
        "wv" => "WBV selected in Android",
        "rjs" => "RJS Rust v2 with WBV Auto fallback",
        _ => "AUTO: Rust v2 x2 -> WBV Auto x2 -> Rust v2 x1 -> Manual WBV",
    };
    crate::log_error!("[КЛИЕНТ] ═══════════════════════════════════════");
    crate::log_error!("[КЛИЕНТ] VK Creds: Client IDs: {client_ids}");
    crate::log_error!("[КЛИЕНТ] VK Auth: {}", arguments.vk_auth_mode);
    crate::log_error!("[КЛИЕНТ] TLS: {} fingerprint", arguments.fingerprint);
    crate::log_error!("[КЛИЕНТ] Воркеров: {workers} (групп: {groups}, по {WORKERS_PER_GROUP})");
    crate::log_error!("[КЛИЕНТ] Хешей: {hashes}");
    crate::log_error!(
        "[КЛИЕНТ] Слушаю: {} (порт {local_port}) | Пир: {}",
        arguments.listen,
        arguments.peer
    );
    crate::log_error!(
        "[КЛИЕНТ] TURN: {} | SRTP: {} | DTLS: 1.2 (ECDSA P-256) | WRAP: ON | obfs={}",
        turn_transport.as_str(),
        srtp_mode.as_str(),
        arguments.obfs,
    );
    crate::log_error!("[WRAP] WRAP Ключ вычислен ✓");
    crate::log_error!("[КЛИЕНТ] Captcha: {captcha}");
    if arguments.domain_routing {
        crate::log_error!(
            "[КЛИЕНТ] Доменная маршрутизация: ВКЛ (RU/SU/РФ: {}, кастомных доменов: {})",
            if arguments.exclude_ru_zones {
                "ДА"
            } else {
                "НЕТ"
            },
            arguments
                .direct_domains
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .count()
        );
    }
    crate::log_error!("[КЛИЕНТ] ═══════════════════════════════════════");
}

#[cfg(target_os = "macos")]
fn schedule_vk_endpoint_excludes(cancel: tokio_util::sync::CancellationToken) {
    const HOSTS: &[&str] = &[
        "api.vk.me",
        "api.vk.com",
        "login.vk.ru",
        "login.vk.com",
        "id.vk.ru",
        "id.vk.com",
        "oauth.vk.ru",
        "oauth.vk.com",
        "vk.com",
    ];
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(15));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    for host in HOSTS {
                        let Ok(addrs) =
                            tokio::net::lookup_host((host.to_string(), 443u16)).await
                        else {
                            crate::log_error!(
                                "[TUN] VK-хост {host} не резолвится — исключение пропущено"
                            );
                            continue;
                        };
                        for addr in addrs {
                            #[cfg(windows)]
                            crate::tun_win::exclude_host_ip(addr.ip());
                            #[cfg(target_os = "linux")]
                            crate::tun_linux::exclude_host_ip(addr.ip());
                            #[cfg(target_os = "macos")]
                            crate::tun_darwin::exclude_host_ip(addr.ip());
                        }
                    }
                }
            }
        }
    });
}

#[cfg(all(test, target_os = "macos"))]
mod macos_port_tests;

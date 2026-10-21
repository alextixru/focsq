// SPDX-FileCopyrightText: 2026 alextixru
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [FOCSQ] Нативный macOS TUN: utun + root-помощник (модель PWDTT, wg_darwin.go).
//!
//! Создать utun и править таблицу маршрутов может только root, а ядро живёт
//! в процессе приложения без прав. Поэтому работа делится на два процесса:
//!   1. Ядро слушает unix-сокет и запускает `csqtt-tun-helper` от root:
//!      напрямую, если само уже root (CLI под sudo), иначе через osascript
//!      «with administrator privileges» — системный диалог пароля.
//!   2. Помощник создаёт utun и передаёт fd ядру (SCM_RIGHTS), после чего
//!      висит на сокете и выполняет команды: conf (адрес/маршруты/DNS по
//!      TUNCONF), exclude (TURN/VK-хосты мимо туннеля), down.
//!   3. Обрыв сокета (краш ядра) = down: помощник снимает аплинк-маршруты,
//!      возвращает DNS и выходит. Half-маршруты 0/1+128/1 исчезают сами
//!      вместе с utun, когда закрывается последний fd.
//! Сетевая модель — как в tun_linux.rs: исходный шлюз запоминается до
//! перехвата, VK-подсети и TURN /32 идут через него, пир не исключается.
//! Пакеты utun несут 4-байтовый заголовок семейства адресов — его снимает
//! и добавляет диспетчер (read_tun_packet/write_tun_packet).

use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::File,
    io::{BufRead, BufReader, IoSlice, IoSliceMut, Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            fs::DirBuilderExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// MTU как в tun_linux.rs (Constants.Vpn.DEFAULT_MTU оригинала)
const MTU: usize = 1300;

/// Подсети VK/TURN целиком через исходный шлюз. Совпадает с tun_linux.rs.
const VK_EXCLUDE_CIDRS: [&str; 13] = [
    "87.240.128.0/18",
    "87.240.192.0/19",
    "90.156.0.0/16",
    "93.186.224.0/21",
    "95.142.192.0/21",
    "95.163.0.0/16",
    "95.213.0.0/18",
    "155.212.192.0/20",
    "185.16.28.0/22",
    "194.67.64.0/18",
    "195.82.146.0/23",
    "213.180.193.0/24",
    "77.88.0.0/18",
];

/// Бинарник помощника ищется рядом с исполняемым файлом приложения
/// (Contents/MacOS в .app, target/release у csqtt-cli).
const HELPER_NAME: &str = "csqtt-tun-helper";

/// Ожидание помощника: пользователь вводит пароль в системном диалоге.
const HELPER_TIMEOUT: Duration = Duration::from_secs(120);

/// Ожидание применения TUNCONF помощником (ifconfig/route/DNS).
const CONF_TIMEOUT: Duration = Duration::from_secs(30);

// ===========================================================================
// Протокол ядро ↔ помощник: JSON-строки в обе стороны
// ===========================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Conf {
        ip: Ipv4Addr,
        mtu: usize,
        dns: Vec<IpAddr>,
        routes: Vec<String>,
        excludes: Vec<String>,
        set_dns: bool,
    },
    Exclude {
        ip: Ipv4Addr,
    },
    Down,
}

/// Сообщение с `name` несёт fd интерфейса в SCM_RIGHTS; `applied` — ответ на conf.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Reply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    applied: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ===========================================================================
// Сторона ядра
// ===========================================================================

/// Связь с помощником активной сессии.
struct Link {
    writer: Mutex<UnixStream>,
    applied: Mutex<mpsc::Receiver<Result<(), String>>>,
    closed: Mutex<mpsc::Receiver<()>>,
    /// Процесс помощника, если ядро запустило его само (уже root)
    child: Mutex<Option<Child>>,
}

impl Link {
    fn send(&self, request: &Request) -> Result<()> {
        let mut line = serde_json::to_vec(request)?;
        line.push(b'\n');
        self.writer
            .lock()
            .unwrap()
            .write_all(&line)
            .context("помощник TUN недоступен")
    }
}

static LINK: Mutex<Option<Arc<Link>>> = Mutex::new(None);
/// TURN/VK-IP, исключённые динамически: дедуп от всех воркеров
static DYNAMIC_EXCLUDES: OnceLock<Mutex<HashSet<Ipv4Addr>>> = OnceLock::new();
/// Явный путь к помощнику (хост-приложение), иначе — рядом с исполняемым файлом
static HELPER_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

fn dynamic_excludes() -> &'static Mutex<HashSet<Ipv4Addr>> {
    DYNAMIC_EXCLUDES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn current_link() -> Option<Arc<Link>> {
    LINK.lock().unwrap().clone()
}

/// Задать путь к `csqtt-tun-helper`, если он лежит не рядом с исполняемым файлом.
pub fn set_helper_path(path: impl Into<PathBuf>) {
    *HELPER_PATH.lock().unwrap() = Some(path.into());
}

fn helper_path() -> Result<PathBuf> {
    if let Some(path) = HELPER_PATH.lock().unwrap().clone() {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os("CSQTT_TUN_HELPER") {
        return Ok(path.into());
    }
    let executable = std::env::current_exe().context("путь к исполняемому файлу")?;
    let path = executable.with_file_name(HELPER_NAME);
    if !path.exists() {
        bail!("{HELPER_NAME} не найден рядом с {}", executable.display());
    }
    Ok(path)
}

/// Запустить помощника, получить от него utun и вернуть fd в формате
/// диспетчера — неблокирующий File, как TunDevice::nonblocking_file в Linux.
pub async fn open() -> Result<File> {
    tokio::task::spawn_blocking(open_blocking)
        .await
        .context("запуск помощника TUN прерван")?
}

fn open_blocking() -> Result<File> {
    close_link();
    let helper = helper_path()?;
    let directory = private_socket_dir()?;
    let connected = (|| -> Result<(UnixStream, Option<Child>)> {
        let socket = directory.join("h.sock");
        let listener = UnixListener::bind(&socket).context("unix-сокет для помощника TUN")?;
        listener.set_nonblocking(true)?;
        let mut child = launch_helper(&helper, &socket)?;
        let stream = accept_helper(&listener, child.as_mut())?;
        Ok((stream, child))
    })();
    let _ = std::fs::remove_dir_all(&directory);
    let (stream, child) = connected?;
    stream.set_nonblocking(false)?;

    let (name, descriptor, leftover) = receive_interface(&stream)?;
    set_nonblocking(&descriptor)?;

    let (applied_tx, applied_rx) = mpsc::channel();
    let (closed_tx, closed_rx) = mpsc::channel();
    spawn_reader(stream.try_clone()?, leftover, applied_tx, closed_tx)?;
    let link = Arc::new(Link {
        writer: Mutex::new(stream),
        applied: Mutex::new(applied_rx),
        closed: Mutex::new(closed_rx),
        child: Mutex::new(child),
    });
    *LINK.lock().unwrap() = Some(link.clone());

    // TURN/VK-хосты, увиденные до запуска помощника
    let pending: Vec<Ipv4Addr> = dynamic_excludes().lock().unwrap().iter().copied().collect();
    for ip in pending {
        if let Err(error) = link.send(&Request::Exclude { ip }) {
            crate::log_error!("[TUN] Отложенный exclude TURN {ip}: {error:#}");
        }
    }
    crate::log_error!("[КЛИЕНТ] TUN-интерфейс создан: {name}");
    Ok(File::from(descriptor))
}

/// Каталог 0700 для сокета: путь unix-сокета ограничен 104 байтами,
/// поэтому при длинном $TMPDIR уходим в /tmp.
fn private_socket_dir() -> Result<PathBuf> {
    let suffix = format!("csqtt-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let mut directory = std::env::temp_dir().join(&suffix);
    if directory.as_os_str().len() > 80 {
        directory = Path::new("/tmp").join(&suffix);
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .with_context(|| format!("каталог сокета {}", directory.display()))?;
    Ok(directory)
}

fn launch_helper(helper: &Path, socket: &Path) -> Result<Option<Child>> {
    if unsafe { libc::geteuid() } == 0 {
        let child = Command::new(helper)
            .arg("--sock")
            .arg(socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("запуск {}", helper.display()))?;
        return Ok(Some(child));
    }
    crate::log_error!("[TUN] Запрос прав администратора для настройки туннеля…");
    let command = format!(
        "{} --sock {} >/dev/null 2>&1 &",
        shell_quote(helper.as_os_str()),
        shell_quote(socket.as_os_str())
    );
    let script = format!(
        "do shell script {} with administrator privileges",
        applescript_string(&command)
    );
    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .output()
        .context("osascript")?;
    if !output.status.success() {
        bail!(
            "права администратора не получены: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(None)
}

fn accept_helper(listener: &UnixListener, mut child: Option<&mut Child>) -> Result<UnixStream> {
    let deadline = Instant::now() + HELPER_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error).context("accept помощника TUN"),
        }
        if let Some(child) = child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            bail!("помощник TUN завершился до подключения: {status}");
        }
        if Instant::now() >= deadline {
            bail!("помощник TUN не вышел на связь за {} с", HELPER_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Читать сообщения помощника до получения fd интерфейса. Возвращает имя,
/// fd и прочитанный сверх того хвост (его дочитает поток-читатель).
fn receive_interface(stream: &UnixStream) -> Result<(String, OwnedFd, Vec<u8>)> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, UnixAddr, recvmsg};

    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut pending: Vec<u8> = Vec::new();
    let mut descriptor: Option<OwnedFd> = None;
    let mut buffer = [0u8; 4096];
    loop {
        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let Ok(reply) = serde_json::from_slice::<Reply>(&line) else {
                continue;
            };
            if let Some(log) = reply.log {
                crate::log_error!("[TUN] {log}");
            }
            if let Some(error) = reply.error {
                bail!("помощник TUN: {error}");
            }
            if let Some(name) = reply.name {
                let descriptor = descriptor
                    .take()
                    .with_context(|| format!("fd интерфейса {name} не получен"))?;
                stream.set_read_timeout(None)?;
                return Ok((name, descriptor, pending));
            }
        }

        let (bytes, received) = {
            let mut slices = [IoSliceMut::new(&mut buffer)];
            let mut ancillary = nix::cmsg_space!([RawFd; 2]);
            let message = recvmsg::<UnixAddr>(
                stream.as_raw_fd(),
                &mut slices,
                Some(&mut ancillary),
                MsgFlags::empty(),
            )
            .context("чтение от помощника TUN")?;
            let mut received = Vec::new();
            for control in message.cmsgs().context("управляющие сообщения помощника")? {
                if let ControlMessageOwned::ScmRights(descriptors) = control {
                    for raw in descriptors.into_iter().filter(|raw| *raw >= 0) {
                        // SAFETY: fd только что получен через SCM_RIGHTS и ещё ничей
                        received.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
            }
            (message.bytes, received)
        };
        if bytes == 0 {
            bail!("помощник TUN закрыл соединение до передачи интерфейса");
        }
        if descriptor.is_none() {
            descriptor = received.into_iter().next();
        }
        pending.extend_from_slice(&buffer[..bytes]);
    }
}

fn set_nonblocking(descriptor: &OwnedFd) -> Result<()> {
    let raw = descriptor.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error()).context("O_NONBLOCK на utun");
    }
    // macOS не умеет MSG_CMSG_CLOEXEC — ставим FD_CLOEXEC вручную
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("FD_CLOEXEC на utun");
    }
    Ok(())
}

fn spawn_reader(
    stream: UnixStream,
    leftover: Vec<u8>,
    applied: mpsc::Sender<Result<(), String>>,
    closed: mpsc::Sender<()>,
) -> Result<()> {
    std::thread::Builder::new()
        .name("csqtt-tun-helper".to_owned())
        .spawn(move || {
            let reader = BufReader::new(std::io::Cursor::new(leftover).chain(stream));
            for line in reader.split(b'\n') {
                let Ok(line) = line else { break };
                let Ok(reply) = serde_json::from_slice::<Reply>(&line) else {
                    continue;
                };
                if let Some(log) = reply.log {
                    crate::log_error!("[TUN] {log}");
                }
                match (reply.applied, reply.error) {
                    (Some(true), _) => {
                        let _ = applied.send(Ok(()));
                    }
                    (Some(false), error) => {
                        let _ = applied.send(Err(error.unwrap_or_default()));
                    }
                    (None, Some(error)) => crate::log_error!("[ОШИБКА] Помощник TUN: {error}"),
                    (None, None) => {}
                }
            }
            let _ = closed.send(());
        })
        .context("поток чтения помощника TUN")?;
    Ok(())
}

/// Маршруты перехвата. CSQTT_TUN_ROUTES — для отладки рядом с другим VPN:
/// CIDR через запятую или «none» (без перехвата: трафик пускается в
/// туннель вручную, например `curl --interface utunN`).
fn capture_routes() -> Vec<String> {
    match std::env::var("CSQTT_TUN_ROUTES") {
        Ok(value) if value.trim().eq_ignore_ascii_case("none") => Vec::new(),
        Ok(value) if !value.trim().is_empty() => value
            .split(',')
            .map(str::trim)
            .filter(|cidr| !cidr.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => vec!["0.0.0.0/1".to_owned(), "128.0.0.0/1".to_owned()],
    }
}

/// Применить TUNCONF: адрес + исключения + перехват half-маршрутами + DNS.
/// Модель — tun_linux.rs::apply_tunconf, исполняет помощник.
pub async fn apply_tunconf(ip: &str, dns: &str, peer_ip: &str) -> Result<()> {
    let address: Ipv4Addr = ip.parse().with_context(|| format!("некорректный IP: {ip}"))?;
    let peer: Ipv4Addr = peer_ip
        .parse()
        .with_context(|| format!("некорректный IP пира: {peer_ip}"))?;
    let dns_servers = dns
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpAddr>()
                .with_context(|| format!("некорректный DNS: {value}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if dns_servers.is_empty() {
        bail!("TUNCONF не содержит DNS");
    }
    let link = current_link().context("TUN-устройство не создано — адрес выставить некому")?;
    let routes = capture_routes();
    let set_dns = std::env::var("CSQTT_TUN_DNS").map_or(true, |value| value != "0");

    link.send(&Request::Conf {
        ip: address,
        mtu: MTU,
        dns: dns_servers,
        routes: routes.clone(),
        excludes: VK_EXCLUDE_CIDRS.iter().map(|cidr| (*cidr).to_owned()).collect(),
        set_dns,
    })?;
    let waiter = link.clone();
    let result = tokio::task::spawn_blocking(move || {
        waiter.applied.lock().unwrap().recv_timeout(CONF_TIMEOUT)
    })
    .await
    .context("ожидание помощника TUN прервано")?;
    match result {
        Ok(Ok(())) => {
            crate::log_error!(
                "[TUN] Настроен: ip={address}/24 перехват={routes:?} dns={dns} (системный: {set_dns}) | пир {peer} — через туннель"
            );
            Ok(())
        }
        Ok(Err(error)) => bail!("помощник TUN: {error}"),
        Err(_) => bail!("помощник TUN не ответил на TUNCONF за {} с", CONF_TIMEOUT.as_secs()),
    }
}

/// Динамический exclude-маршрут для TURN/VK-хостов (мимо туннеля). До
/// запуска помощника IP запоминается и уходит ему сразу после подключения.
pub fn exclude_host_ip(ip: IpAddr) {
    let IpAddr::V4(address) = ip else { return };
    if address.is_loopback() || address.is_unspecified() {
        return;
    }
    if !dynamic_excludes().lock().unwrap().insert(address) {
        return;
    }
    match current_link() {
        Some(link) => {
            if let Err(error) = link.send(&Request::Exclude { ip: address }) {
                crate::log_error!("[TUN] Exclude-маршрут TURN {address}: {error:#}");
            }
        }
        None => crate::log_error!("[TUN] TURN {address}: помощника ещё нет, исключим при запуске"),
    }
}

/// Отпустить помощника: он снимает аплинк-маршруты, возвращает DNS и выходит.
fn close_link() {
    let Some(link) = LINK.lock().unwrap().take() else {
        return;
    };
    let _ = link.send(&Request::Down);
    let finished = link
        .closed
        .lock()
        .unwrap()
        .recv_timeout(Duration::from_secs(5))
        .is_ok();
    if let Some(mut child) = link.child.lock().unwrap().take() {
        let deadline = Instant::now() + Duration::from_secs(2);
        while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    if finished {
        crate::log_error!("[TUN] Помощник снял маршруты и завершился");
    } else {
        crate::log_error!("[TUN] Помощник не подтвердил завершение за 5 с");
    }
}

/// Teardown: помощник снимает аплинк-маршруты и DNS; utun и half-маршруты
/// исчезают, когда диспетчер закроет fd.
pub fn teardown() {
    close_link();
    dynamic_excludes().lock().unwrap().clear();
}

/// Мгновенное опускание при закрытии — как в tun_linux.rs, это teardown.
pub fn drop_interface_now() {
    teardown();
}

fn shell_quote(value: &OsStr) -> String {
    format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
}

fn applescript_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

// ===========================================================================
// Сторона помощника (root): `csqtt-tun-helper --sock PATH`
// ===========================================================================

/// Шлюз, через который уходят исключения: исходный default-маршрут.
#[derive(Clone)]
enum Uplink {
    Gateway(Ipv4Addr),
    Interface(String),
}

impl std::fmt::Display for Uplink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Uplink::Gateway(gateway) => write!(formatter, "шлюз {gateway}"),
            Uplink::Interface(interface) => write!(formatter, "интерфейс {interface}"),
        }
    }
}

struct Helper {
    stream: UnixStream,
    name: String,
    uplink: Option<Uplink>,
    address: Option<Ipv4Addr>,
    /// Маршруты через аплинк, добавленные нами (снимаются при выходе)
    uplink_routes: Vec<String>,
    /// Маршруты перехвата на utun (исчезают вместе с интерфейсом)
    capture_routes: Vec<String>,
    /// Подмена DNS служб (откатывается при выходе)
    dns_override: Option<DnsOverride>,
}

/// Точка входа помощника. Возвращает код выхода процесса.
pub fn helper_main(args: &[String]) -> i32 {
    let mut socket = None;
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--sock" {
            socket = arguments.next().cloned();
        }
    }
    let Some(socket) = socket else {
        eprintln!("использование: {HELPER_NAME} --sock ПУТЬ");
        return 2;
    };
    let stream = match UnixStream::connect(&socket) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("{HELPER_NAME}: подключение к {socket}: {error}");
            return 1;
        }
    };
    let mut helper = Helper {
        stream,
        name: String::new(),
        uplink: None,
        address: None,
        uplink_routes: Vec::new(),
        capture_routes: Vec::new(),
        dns_override: None,
    };
    let result = helper.serve();
    helper.cleanup();
    match result {
        Ok(()) => 0,
        Err(error) => {
            helper.reply(&Reply {
                error: Some(format!("{error:#}")),
                ..Reply::default()
            });
            1
        }
    }
}

impl Helper {
    fn reply(&self, reply: &Reply) {
        let Ok(mut line) = serde_json::to_vec(reply) else {
            return;
        };
        line.push(b'\n');
        let _ = (&self.stream).write_all(&line);
    }

    fn log(&self, text: impl Into<String>) {
        self.reply(&Reply {
            log: Some(text.into()),
            ..Reply::default()
        });
    }

    fn serve(&mut self) -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            bail!("помощник запущен не от root (uid={})", unsafe { libc::getuid() });
        }
        // Исходный шлюз — ДО перехвата: дальше default-маршрут перекрыт utun
        let uplink = default_uplink()?;
        let (descriptor, name) = create_utun()?;
        self.name = name;
        self.log(format!("Создан интерфейс {} | исходный {uplink}", self.name));
        self.uplink = Some(uplink);
        self.send_interface(&descriptor)?;
        // Свою копию fd держим до выхода: закрытие, пока fd ещё в полёте
        // (ядро не успело принять сообщение), отключает utun-сокет — ядро
        // получает уже мёртвый интерфейс (EOF на первом чтении).
        let _utun = descriptor;

        let reader = BufReader::new(self.stream.try_clone()?);
        for line in reader.split(b'\n') {
            let Ok(line) = line else { break };
            let request: Request = match serde_json::from_slice(&line) {
                Ok(request) => request,
                Err(error) => {
                    self.log(format!("непонятная команда: {error}"));
                    continue;
                }
            };
            match request {
                Request::Conf {
                    ip,
                    mtu,
                    dns,
                    routes,
                    excludes,
                    set_dns,
                } => {
                    let result = self.configure(ip, mtu, &dns, &routes, &excludes, set_dns);
                    self.reply(&Reply {
                        applied: Some(result.is_ok()),
                        error: result.err().map(|error| format!("{error:#}")),
                        ..Reply::default()
                    });
                }
                Request::Exclude { ip } => {
                    if self.add_uplink_route(&format!("{ip}/32")) {
                        self.log(format!("Exclude-маршрут TURN {ip} добавлен"));
                    }
                }
                Request::Down => break,
            }
        }
        Ok(())
    }

    fn send_interface(&self, descriptor: &OwnedFd) -> Result<()> {
        use nix::sys::socket::{ControlMessage, MsgFlags, UnixAddr, sendmsg};

        let mut payload = serde_json::to_vec(&Reply {
            name: Some(self.name.clone()),
            ..Reply::default()
        })?;
        payload.push(b'\n');
        let slices = [IoSlice::new(&payload)];
        let descriptors = [descriptor.as_raw_fd()];
        let controls = [ControlMessage::ScmRights(&descriptors)];
        let sent = sendmsg::<UnixAddr>(
            self.stream.as_raw_fd(),
            &slices,
            &controls,
            MsgFlags::empty(),
            None,
        )
        .context("передача fd интерфейса")?;
        if sent < payload.len() {
            (&self.stream).write_all(&payload[sent..])?;
        }
        Ok(())
    }

    fn configure(
        &mut self,
        ip: Ipv4Addr,
        mtu: usize,
        dns: &[IpAddr],
        routes: &[String],
        excludes: &[String],
        set_dns: bool,
    ) -> Result<()> {
        // 1. Адрес/маска/MTU. Повторный TUNCONF с новым IP — меняем алиас.
        if self.address != Some(ip) {
            if let Some(previous) = self.address.take() {
                let _ = run("/sbin/ifconfig", [self.name.as_str(), "inet", &previous.to_string(), "-alias"]);
            }
            run(
                "/sbin/ifconfig",
                [self.name.as_str(), "inet", &format!("{ip}/24"), &ip.to_string(), "alias"],
            )?;
            self.address = Some(ip);
        }
        run("/sbin/ifconfig", [self.name.as_str(), "mtu", &mtu.to_string(), "up"])?;

        // 2. Исключения через исходный шлюз — ДО перехвата, чтобы трафик
        //    к TURN/VK ни на миг не ушёл в туннель (петля)
        let mut added = 0;
        for cidr in excludes {
            if self.add_uplink_route(cidr) {
                added += 1;
            }
        }
        self.log(format!("Exclude-подсетей VK добавлено: {added}/{}", excludes.len()));

        // 3. Перехват. Пир не исключаем — см. tun_linux.rs::apply_tunconf.
        //    Без ensure (как в Linux): занятый маршрут — чужой VPN, переписать
        //    его значит молча забрать и потерять при отключении.
        for cidr in routes {
            if self.capture_routes.contains(cidr) {
                continue;
            }
            parse_cidr(cidr)?;
            run(
                "/sbin/route",
                ["-q", "-n", "add", "-net", cidr.as_str(), "-interface", self.name.as_str()],
            )
            .with_context(|| format!("маршрут перехвата {cidr} (занят другим VPN?)"))?;
            self.capture_routes.push(cidr.clone());
        }

        // 4. DNS системы — на туннельные серверы. Их /32 — в туннель явно:
        //    Яндекс-DNS (77.88.8.8) попадает в исключение VK 77.88.0.0/18 и
        //    ушёл бы мимо туннеля, а в сетях с заблокированным внешним DNS
        //    (белые списки, гостевой Wi-Fi) резолв умирает целиком.
        if set_dns && self.dns_override.is_none() {
            for server in dns {
                let IpAddr::V4(server) = server else { continue };
                let host = format!("{server}/32");
                if self.capture_routes.contains(&host) {
                    continue;
                }
                let server = server.to_string();
                match run(
                    "/sbin/route",
                    ["-q", "-n", "add", "-host", server.as_str(), "-interface", self.name.as_str()],
                ) {
                    Ok(_) => self.capture_routes.push(host),
                    Err(error) => self.log(format!("DNS {server} в туннель: {error:#}")),
                }
            }
            let dns_override = DnsOverride::apply(dns)?;
            flush_dns_cache();
            self.log(format!(
                "DNS направлен в {} (служб: {})",
                dns.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", "),
                dns_override.backup.len()
            ));
            self.dns_override = Some(dns_override);
        }
        Ok(())
    }

    /// Маршрут через исходный шлюз (ensure: существующий — переписать).
    /// Возвращает true, если маршрут добавлен сейчас.
    fn add_uplink_route(&mut self, cidr: &str) -> bool {
        if self.uplink_routes.iter().any(|route| route == cidr) {
            return false;
        }
        let Some(uplink) = self.uplink.clone() else {
            return false;
        };
        let (address, prefix) = match parse_cidr(cidr) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.log(format!("exclude {cidr}: {error:#}"));
                return false;
            }
        };
        let destination = if prefix == 32 {
            vec!["-host".to_owned(), address.to_string()]
        } else {
            vec!["-net".to_owned(), cidr.to_owned()]
        };
        let target = match &uplink {
            Uplink::Gateway(gateway) => vec![gateway.to_string()],
            Uplink::Interface(interface) => vec!["-interface".to_owned(), interface.clone()],
        };
        let arguments: Vec<&str> = destination.iter().chain(&target).map(String::as_str).collect();
        match ensure_route(&arguments) {
            Ok(()) => {
                self.uplink_routes.push(cidr.to_owned());
                true
            }
            Err(error) => {
                self.log(format!("exclude {cidr}: {error:#}"));
                false
            }
        }
    }

    /// Уборка: DNS назад, аплинк-маршруты снять. Маршруты перехвата
    /// уйдут вместе с utun, когда закроются fd помощника и ядра.
    fn cleanup(&mut self) {
        if let Some(dns_override) = self.dns_override.take() {
            dns_override.restore();
            flush_dns_cache();
        }
        for cidr in self.uplink_routes.drain(..) {
            let destination = match parse_cidr(&cidr) {
                Ok((address, 32)) => vec!["-host".to_owned(), address.to_string()],
                _ => vec!["-net".to_owned(), cidr.clone()],
            };
            let mut arguments = vec!["-q", "-n", "delete"];
            arguments.extend(destination.iter().map(String::as_str));
            let _ = run("/sbin/route", arguments);
        }
    }
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let (address, prefix) = cidr.split_once('/').context("CIDR без префикса")?;
    let address: Ipv4Addr = address
        .parse()
        .with_context(|| format!("некорректный IP: {address}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("некорректный префикс: {prefix}"))?;
    if prefix == 0 || prefix > 32 {
        bail!("префикс /{prefix} вне 1..=32 — используйте half-маршруты 0/1 + 128/1");
    }
    Ok((address, prefix))
}

/// Запустить системную утилиту без shell; ошибка — с её stderr.
fn run<I, S>(program: &str, arguments: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("запуск {program}"))?;
    if !output.status.success() {
        bail!(
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// route add, а если маршрут уже есть (хвост прошлой сессии) — route change.
fn ensure_route(arguments: &[&str]) -> Result<()> {
    let mut add = vec!["-q", "-n", "add"];
    add.extend_from_slice(arguments);
    match run("/sbin/route", &add) {
        Ok(_) => Ok(()),
        Err(error) if format!("{error:#}").contains("File exists") => {
            let mut change = vec!["-q", "-n", "change"];
            change.extend_from_slice(arguments);
            run("/sbin/route", &change).map(|_| ())
        }
        Err(error) => Err(error),
    }
}

/// Исходный default-маршрут из `route -n get default`.
fn default_uplink() -> Result<Uplink> {
    let output = run("/sbin/route", ["-n", "get", "default"])
        .context("default-маршрут не найден — нет сети?")?;
    let mut gateway = None;
    let mut interface = None;
    for line in output.lines() {
        match line.trim().split_once(':') {
            Some(("gateway", value)) => gateway = value.trim().parse::<Ipv4Addr>().ok(),
            Some(("interface", value)) => interface = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    match (gateway, interface) {
        (Some(gateway), _) => Ok(Uplink::Gateway(gateway)),
        (None, Some(interface)) => Ok(Uplink::Interface(interface)),
        (None, None) => bail!("default-маршрут без шлюза и интерфейса"),
    }
}

/// Создать utun: сокет PF_SYSTEM к com.apple.net.utun_control, номер
/// интерфейса (sc_unit=0) выбирает ядро ОС. Требует root.
fn create_utun() -> Result<(OwnedFd, String)> {
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
    const UTUN_OPT_IFNAME: libc::c_int = 2;

    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(PF_SYSTEM)");
    }
    // SAFETY: дескриптор только что создан и ещё ничей
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (target, source) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *target = *source as libc::c_char;
    }
    if unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut info) } < 0 {
        return Err(std::io::Error::last_os_error()).context("CTLIOCGINFO utun_control");
    }

    let address = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
        sc_family: libc::AF_SYSTEM as libc::c_uchar,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    if unsafe {
        libc::connect(
            raw,
            (&address as *const libc::sockaddr_ctl).cast(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("создание utun (нужен root)");
    }

    let mut name = [0u8; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            raw,
            libc::SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("UTUN_OPT_IFNAME");
    }
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(length as usize);
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("FD_CLOEXEC на utun");
    }
    Ok((descriptor, String::from_utf8_lossy(&name[..end]).into_owned()))
}

/// Подмена DNS активных служб через SCDynamicStore — как у Amnezia/Mozilla
/// VPN: ключ Setup:/Network/Service/<id>/DNS в динамическом хранилище
/// (ручной DNS поверх DHCP). networksetup не годится: он пишет в
/// preferences.plist, configd пересинхронизирует Setup-ключи и стирает
/// чужие оверрайды (DNS другого VPN), а откат «Empty» их не возвращает.
/// Прежние значения хранятся как есть (CFPropertyList) и возвращаются точно.
struct DnsOverride {
    store: dynamic_store::Store,
    backup: Vec<(String, Option<core_foundation::propertylist::CFPropertyList>)>,
}

impl DnsOverride {
    fn apply(servers: &[IpAddr]) -> Result<Self> {
        let store = dynamic_store::Store::open(HELPER_NAME).context("SCDynamicStore")?;
        // Активные службы — те, у которых configd опубликовал IPv4
        let mut services: Vec<String> = store
            .keys("State:/Network/Service/[^/]+/IPv4")
            .iter()
            .filter_map(|key| key.split('/').nth(3).map(str::to_owned))
            .collect();
        services.sort();
        services.dedup();
        if services.is_empty() {
            bail!("нет активных сетевых служб для DNS");
        }
        let servers: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
        let dictionary = dynamic_store::dns_dictionary(&servers);
        let mut dns_override = Self {
            store,
            backup: Vec::new(),
        };
        for service in services {
            let key = format!("Setup:/Network/Service/{service}/DNS");
            let previous = dns_override.store.get(&key);
            if !dns_override.store.set(&key, &dictionary) {
                dns_override.restore();
                bail!("DNS службы {service} не записан");
            }
            dns_override.backup.push((key, previous));
        }
        Ok(dns_override)
    }

    fn restore(self) {
        for (key, previous) in &self.backup {
            match previous {
                Some(value) => self.store.set(key, value),
                None => self.store.remove(key),
            };
        }
    }
}

/// [FOCSQ] Минимальная обёртка SCDynamicStore (SystemConfiguration.framework).
mod dynamic_store {
    use core_foundation::{
        array::{CFArray, CFArrayRef},
        base::TCFType,
        dictionary::CFDictionary,
        propertylist::{CFPropertyList, CFPropertyListRef, CFPropertyListSubClass},
        string::{CFString, CFStringRef},
    };
    use std::ffi::c_void;

    type SCDynamicStoreRef = *const c_void;

    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCDynamicStoreCreate(
            allocator: *const c_void,
            name: CFStringRef,
            callout: *const c_void,
            context: *mut c_void,
        ) -> SCDynamicStoreRef;
        fn SCDynamicStoreCopyKeyList(store: SCDynamicStoreRef, pattern: CFStringRef) -> CFArrayRef;
        fn SCDynamicStoreCopyValue(store: SCDynamicStoreRef, key: CFStringRef) -> CFPropertyListRef;
        fn SCDynamicStoreSetValue(
            store: SCDynamicStoreRef,
            key: CFStringRef,
            value: CFPropertyListRef,
        ) -> u8;
        fn SCDynamicStoreRemoveValue(store: SCDynamicStoreRef, key: CFStringRef) -> u8;
    }

    pub struct Store(SCDynamicStoreRef);

    impl Drop for Store {
        fn drop(&mut self) {
            unsafe { core_foundation::base::CFRelease(self.0) };
        }
    }

    impl Store {
        pub fn open(name: &str) -> Option<Self> {
            let name = CFString::new(name);
            let store = unsafe {
                SCDynamicStoreCreate(
                    std::ptr::null(),
                    name.as_concrete_TypeRef(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            };
            (!store.is_null()).then_some(Self(store))
        }

        /// Ключи по регулярному выражению (синтаксис SCDynamicStore).
        pub fn keys(&self, pattern: &str) -> Vec<String> {
            let pattern = CFString::new(pattern);
            let list = unsafe { SCDynamicStoreCopyKeyList(self.0, pattern.as_concrete_TypeRef()) };
            if list.is_null() {
                return Vec::new();
            }
            // SAFETY: Copy-функция — владение по create rule
            let list: CFArray<CFString> = unsafe { CFArray::wrap_under_create_rule(list) };
            list.iter().map(|key| key.to_string()).collect()
        }

        pub fn get(&self, key: &str) -> Option<CFPropertyList> {
            let key = CFString::new(key);
            let value = unsafe { SCDynamicStoreCopyValue(self.0, key.as_concrete_TypeRef()) };
            // SAFETY: Copy-функция — владение по create rule
            (!value.is_null()).then(|| unsafe { CFPropertyList::wrap_under_create_rule(value) })
        }

        pub fn set(&self, key: &str, value: &CFPropertyList) -> bool {
            let key = CFString::new(key);
            unsafe {
                SCDynamicStoreSetValue(self.0, key.as_concrete_TypeRef(), value.as_concrete_TypeRef())
                    != 0
            }
        }

        pub fn remove(&self, key: &str) -> bool {
            let key = CFString::new(key);
            unsafe { SCDynamicStoreRemoveValue(self.0, key.as_concrete_TypeRef()) != 0 }
        }
    }

    /// {ServerAddresses: [...]} — словарь DNS службы.
    pub fn dns_dictionary(servers: &[String]) -> CFPropertyList {
        let addresses: Vec<CFString> = servers.iter().map(|server| CFString::new(server)).collect();
        let addresses = CFArray::from_CFTypes(&addresses);
        let dictionary = CFDictionary::from_CFType_pairs(&[(
            CFString::new("ServerAddresses").as_CFType(),
            addresses.as_CFType(),
        )]);
        dictionary.to_untyped().to_CFPropertyList()
    }
}

fn flush_dns_cache() {
    let _ = run("/usr/bin/dscacheutil", ["-flushcache"]);
    let _ = run("/usr/bin/killall", ["-HUP", "mDNSResponder"]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_rejects_default_route_and_garbage() {
        assert_eq!(parse_cidr("87.240.128.0/18").unwrap(), (Ipv4Addr::new(87, 240, 128, 0), 18));
        assert_eq!(parse_cidr("1.2.3.4/32").unwrap().1, 32);
        assert!(parse_cidr("0.0.0.0/0").is_err());
        assert!(parse_cidr("1.2.3.4/33").is_err());
        assert!(parse_cidr("1.2.3.4").is_err());
        assert!(parse_cidr("1.2.3.4/8; rm -rf /").is_err());
    }

    #[test]
    fn helper_command_survives_shell_and_applescript_quoting() {
        let path = OsStr::new("/Applications/FOCSQ's \"dev\".app/csqtt-tun-helper");
        assert_eq!(
            shell_quote(path),
            r#"'/Applications/FOCSQ'\''s "dev".app/csqtt-tun-helper'"#
        );
        assert_eq!(applescript_string(r#"a "b" \c"#), r#""a \"b\" \\c""#);
    }

    #[test]
    fn protocol_lines_round_trip() {
        let conf = Request::Conf {
            ip: Ipv4Addr::new(10, 66, 67, 4),
            mtu: MTU,
            dns: vec!["77.88.8.8".parse().unwrap()],
            routes: vec!["0.0.0.0/1".to_owned()],
            excludes: vec![VK_EXCLUDE_CIDRS[0].to_owned()],
            set_dns: true,
        };
        let line = serde_json::to_string(&conf).unwrap();
        assert!(line.starts_with(r#"{"cmd":"conf","ip":"10.66.67.4""#));
        assert!(matches!(
            serde_json::from_str::<Request>(&line).unwrap(),
            Request::Conf { mtu: MTU, set_dns: true, .. }
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"exclude","ip":"1.2.3.4"}"#).unwrap(),
            Request::Exclude { .. }
        ));
        // Неверный IP отбрасывается ещё при разборе — до route/ifconfig
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"exclude","ip":"1.2.3.4 -x"}"#).is_err());
        let reply: Reply = serde_json::from_str(r#"{"applied":false,"error":"boom"}"#).unwrap();
        assert_eq!((reply.applied, reply.error.as_deref()), (Some(false), Some("boom")));
    }

    #[test]
    fn capture_routes_default_to_half_routes() {
        // SAFETY: тест однопоточный по этой переменной
        unsafe { std::env::remove_var("CSQTT_TUN_ROUTES") };
        assert_eq!(capture_routes(), ["0.0.0.0/1", "128.0.0.0/1"]);
    }
}

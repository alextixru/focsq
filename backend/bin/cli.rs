// SPDX-FileCopyrightText: 2026 alextixru
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [FOCSQ] Консольный клиент: ядро без GUI — отладка и проверка на новых ОС.
//! Значения по умолчанию — как у фронтенда (connect.dart).
//!
//! macOS: sudo CSQTT_PASSWORD=… csqtt-cli --peer IP:ПОРТ --vk ССЫЛКИ --tun utun
//! Без sudo ядро попросит пароль администратора системным диалогом.

use std::process::exit;

const USAGE: &str = "\
csqtt-cli — клиент CSQTT без GUI

  --peer ХОСТ:ПОРТ      сервер CSQTT (обязательно)
  --password ПАРОЛЬ     пароль подключения (или CSQTT_PASSWORD)
  --vk ССЫЛКИ           ссылки vk.com/call/join/… или хеши через запятую (или CSQTT_VK)
  --hashes РЕЖИМ        manual | auto_js (хеши из звонков аккаунта по токену)
  --auth РЕЖИМ          vkcalls | legacy (капча) | auto_js (аккаунт ВК)
  --vk-token ТОКЕН      токен ВК для auto_js (или CSQTT_VK_TOKEN)
  --workers N           число потоков (по умолчанию 9)
  --device-id ID        идентификатор устройства (или CSQTT_DEVICE_ID)
  --tun ИМЯ             нативный TUN (по умолчанию utun/tun/wintun); off — UDP на --listen
  --listen АДРЕС        локальный UDP в режиме --tun off (127.0.0.1:9000)
  --fingerprint ИМЯ     TLS-отпечаток (chrome)
  --obfs РЕЖИМ          обфускация (audio)
  --check-hashes        только проверить хеши VK и выйти
";

fn usage(problem: &str) -> ! {
    if problem.is_empty() {
        print!("{USAGE}");
        exit(0);
    }
    eprintln!("csqtt-cli: {problem}\n\n{USAGE}");
    exit(2);
}

fn main() {
    let mut config = csqtt_core::ClientConfig {
        workers: 9,
        client_ids: "8202606,6287487".to_owned(),
        tun_uds: if cfg!(windows) { "wintun" } else { "tun" }.to_owned(),
        password: std::env::var("CSQTT_PASSWORD").unwrap_or_default(),
        vk: std::env::var("CSQTT_VK").unwrap_or_default(),
        vk_js_token: std::env::var("CSQTT_VK_TOKEN").unwrap_or_default(),
        device_id: std::env::var("CSQTT_DEVICE_ID").unwrap_or_default(),
        ..csqtt_core::ClientConfig::default()
    };

    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .unwrap_or_else(|| usage(&format!("{flag}: нет значения")))
        };
        match flag.as_str() {
            "--peer" => config.peer = value(),
            "--password" => config.password = value(),
            "--vk" => config.vk = value(),
            "--hashes" => config.vk_hash_mode = value(),
            "--auth" => config.vk_auth_mode = value(),
            "--vk-token" => config.vk_js_token = value(),
            "--workers" => {
                config.workers = value()
                    .parse()
                    .unwrap_or_else(|_| usage("--workers: нужно число"))
            }
            "--device-id" => config.device_id = value(),
            "--tun" => {
                let tun = value();
                config.tun_uds = if tun == "off" { String::new() } else { tun };
            }
            "--listen" => config.listen = value(),
            "--fingerprint" => config.fingerprint = value(),
            "--obfs" => config.obfs = value(),
            "--check-hashes" => config.validate_vk_hashes = true,
            "-h" | "--help" => usage(""),
            other => usage(&format!("неизвестный флаг {other}")),
        }
    }

    if config.device_id.is_empty() {
        config.device_id = uuid::Uuid::new_v4().to_string();
        eprintln!(
            "csqtt-cli: --device-id не задан, сгенерирован {} — сервер привязывает пароль к устройству, передавайте его и дальше",
            config.device_id
        );
    }
    config.generation = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    config.salt = uuid::Uuid::new_v4().simple().to_string()[..16].to_owned();

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("csqtt-cli: tokio: {error}");
            exit(1);
        }
    };
    if let Err(error) = runtime.block_on(csqtt_core::run_client(config, None)) {
        eprintln!("csqtt-cli: {error:#}");
        exit(1);
    }
}

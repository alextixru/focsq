// SPDX-FileCopyrightText: 2026 alextixru
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [FOCSQ] Root-помощник macOS TUN: создаёт utun, передаёт fd ядру и
//! правит маршруты/DNS по его командам (tun_darwin.rs). Кладётся рядом
//! с исполняемым файлом приложения; ядро запускает его само.

fn main() {
    #[cfg(target_os = "macos")]
    {
        let arguments: Vec<String> = std::env::args().skip(1).collect();
        std::process::exit(csqtt_core::tun_darwin::helper_main(&arguments));
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("csqtt-tun-helper нужен только на macOS");
        std::process::exit(2);
    }
}

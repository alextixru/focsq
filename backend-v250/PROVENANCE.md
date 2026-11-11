# CSQTT 2.5.0 macOS engine

Source: https://github.com/amurcanov/csqtt/tree/v2.5.0
Commit: fd936ef087c34cc46f26111dc2361f43b8b03c07 (20 October 2026).
Client sources and shared protocol only. No server code is built or deployed.

macOS adaptations: library API for the existing Flutter bridge; host log/control
callbacks; utun and routing/DNS helper from this fork's ci/macos-intel branch
(98ce6ac12fa322c95b6d829d26e6041abb9ed1c7); utun packet framing; TURN/VK bypass
routes; explicit failure if network configuration fails; cleanup on session exit.
The original main.rs is retained for comparison, but is not a Cargo binary target.
Windows/Linux retain backend/ (2.1.9). macOS uses this 2.5.0 engine.

Upstream LICENSE is preserved in this directory. Copyright 2026 amurcanov;
desktop integration copyright 2026 luminescq and alextixru.

The v2.5.0 tag omitted domains.txt required by sni.rs. It is restored from
upstream main, blob d52d29657e34ffa13544323087ed7f20b344737a.

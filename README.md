# chronicle-pulse-secops-workbench

Real-Time Threat Intelligence & Google SecOps (Chronicle) UDM / YARA-L 2.0 Detection Workbench

## Repository Structure

- `src/` & `server.ts` — Full-stack React 19 + Express + TypeScript Real-Time Threat Intelligence Workbench
- `secops-rules/` — Production YARA-L 2.0 detection rules for Google SecOps (Chronicle)
- `secops-queries/` — Unified Data Model (UDM) IoC Sweep & Behavioral Threat Hunting queries
- `threat-intel/stix21-bundle.json` — STIX 2.1 structured threat intelligence bundle
- `threat-intel/ADVISORIES.md` — Full Threat Intelligence & MITRE ATT&CK Kill Chain reports


## Active Threat Intelligence Summary (8 Advisories)

| ID | Threat / Advisory Title | Severity | Actor | Malware | YARA-L 2.0 Rule |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ti-2026-001` | Volt Typhoon KV-Botnet Edge Router Zero-Day & Living-off-the-Land Campaign (CVE-2026-21409) | **Critical** | Volt Typhoon | KV-Botnet | `volt_typhoon_kv_botnet_edge_router_zero_day__ti2026.yaral` |
| `ti-2026-002` | LockBit 4.0 & RansomHub Dual-Extortion Wave Targeting BFSI & Healthcare VMware ESXi Hypervisors | **Critical** | RansomHub & LockBit Affiliates | LockBit | `lockbit_4_0_ransomhub_dual_extortion_wave_ta_ti2026.yaral` |
| `ti-2026-003` | Lumma Stealer & RedLine MaaS Campaign Abusing Fake CAPTCHA & ClickFix PowerShell Lures | **High** | Storm-1607 MaaS Affiliates | Lumma Stealer | `lumma_stealer_redline_maas_campaign_abusing__ti2026.yaral` |
| `ti-2026-004` | APT29 (Midnight Blizzard) OAuth Token & Entra ID Cross-Tenant Cloud Identity Intrusion | **Critical** | APT29 | GraphAPI-Backdoor | `apt29_midnight_blizzard_oauth_token_entra_id_ti2026.yaral` |
| `ti-2026-005` | Lazarus Group & APT41 Polyglot Supply Chain Attack on PyPI / NPM CI/CD Pipelines | **Critical** | Lazarus | InvisibleFerret | `lazarus_group_apt41_polyglot_supply_chain_at_ti2026.yaral` |
| `ti-2026-006` | Akira & BlackCat Linux/Windows Ransomware Campaign Targeting Manufacturing & Retail OT Gateways | **High** | Akira Syndicate | Akira | `akira_blackcat_linux_windows_ransomware_camp_ti2026.yaral` |
| `ti-2025-007` | AcidPour & Industroyer-Variant OT Wiper Campaign Against Energy & Telecom Substations | **Critical** | Sandworm / APT44 | AcidPour Wiper | `acidpour_industroyer_variant_ot_wiper_campai_ti2025.yaral` |
| `ti-2024-008` | AsyncRAT & Vidar Loader Campaign Abusing Signed Cloud Tunnel Binaries in Healthcare & Retail | **Medium** | TA577 / AsyncRAT Operators | AsyncRAT | `asyncrat_vidar_loader_campaign_abusing_signe_ti2024.yaral` |

## Quick Start (Local Development)

```bash
npm install
npm run dev
```

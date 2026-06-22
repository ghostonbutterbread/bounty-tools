#!/usr/bin/env python3
"""
Credential Store — Shared authentication layer for bug bounty tools.
Each program has its own credentials directory with chmod 600 protection.

Usage:
    from credential_store import CredentialStore
    
    store = CredentialStore("acme")
    creds = store.get()
    if store.validate(creds):
        # use credentials
"""

import os
import re
import json
import stat
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

DEFAULT_CORE_FAMILY = "web_bounty"
DEFAULT_CORE_LANE = "web"
BOUNTY_CORE_PATH = Path(os.environ.get("BOUNTY_CORE_PATH", str(Path.home() / "projects" / "bounty-core")))


def _load_resolve_storage():
    try:
        from bounty_core import resolve_storage
        return resolve_storage
    except Exception:
        if BOUNTY_CORE_PATH.exists() and str(BOUNTY_CORE_PATH) not in sys.path:
            sys.path.insert(0, str(BOUNTY_CORE_PATH))
        try:
            from bounty_core import resolve_storage
            return resolve_storage
        except Exception:
            return None


def _safe_program(program: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", str(program or "").lower().replace(" ", "_")).strip("._-") or "unknown"


def _credential_dir(program: str, *, family: str, lane: str, base_dir: Optional[Path] = None) -> Path:
    safe = _safe_program(program)
    if base_dir is not None:
        return Path(base_dir) / safe / "credentials"
    resolve_storage = _load_resolve_storage()
    if resolve_storage is not None:
        layout = resolve_storage(safe, family=family, lane=lane, create=False)
        return layout.context_root / "credentials"
    return Path.home() / "Shared" / family / safe / lane / "context" / "credentials"


@dataclass
class Account:
    """Account metadata stored alongside credentials."""
    email: str
    username: Optional[str] = None
    platform: Optional[str] = None  # hackerone, bugcrowd, openbugbounty, etc.
    notes: Optional[str] = None


@dataclass
class Credentials:
    """Credentials for a program."""
    api_token: Optional[str] = None
    session_token: Optional[str] = None
    oauth_token: Optional[str] = None
    api_key: Optional[str] = None
    password: Optional[str] = None
    headers: Optional[dict] = None  # custom headers as JSON string


class CredentialStore:
    """
    Manages per-program credentials with secure file permissions.
    
    Directory structure:
        ~/Shared/{family}/{program}/{lane}/context/credentials/
        ├── credentials.env    # chmod 600
        └── account.json       # chmod 600
    """
    
    def __init__(
        self,
        program: str,
        base_dir: Optional[Path] = None,
        *,
        family: str = DEFAULT_CORE_FAMILY,
        lane: str = DEFAULT_CORE_LANE,
    ):
        self.program = _safe_program(program)
        self.family = family
        self.lane = lane
        self.base_dir = Path(base_dir) if base_dir is not None else None
        self.cred_dir = _credential_dir(self.program, family=family, lane=lane, base_dir=self.base_dir)
        self.cred_file = self.cred_dir / "credentials.env"
        self.account_file = self.cred_dir / "account.json"
    
    # ─── Directory Management ───────────────────────────────────────────────
    
    def init(self) -> bool:
        """Create credentials directory with secure permissions. Returns True if created."""
        if self.cred_dir.exists():
            return False
        # Set umask BEFORE creating to avoid TOCTOU race
        old_umask = os.umask(0o077)
        try:
            self.cred_dir.mkdir(parents=True, exist_ok=True)
        finally:
            os.umask(old_umask)
        return True
    
    # ─── Store / Retrieve ───────────────────────────────────────────────────
    
    def store(self, credentials: Credentials, account: Optional[Account] = None) -> None:
        """Store credentials and account info with secure permissions."""
        self.init()
        
        # Build .env content
        lines = []
        for key, value in asdict(credentials).items():
            if value is not None:
                if isinstance(value, dict):
                    value = json.dumps(value)
                lines.append(f"{key}={value}")
        
        cred_content = "\n".join(lines) + "\n"
        self.cred_file.write_text(cred_content)
        self._secure_perms(self.cred_file)
        
        # Store account metadata
        if account:
            self.account_file.write_text(json.dumps(asdict(account), indent=2) + "\n")
            self._secure_perms(self.account_file)
    
    def get(self) -> Optional[Credentials]:
        """Load credentials from file. Returns None if not found."""
        if not self.cred_file.exists():
            return None
        
        creds = Credentials()
        for line in self.cred_file.read_text().strip().split("\n"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                value = value.strip().strip('"').strip("'")
                if hasattr(creds, key) and value:
                    setattr(creds, key, value)
        
        return creds
    
    def get_account(self) -> Optional[Account]:
        """Load account metadata. Returns None if not found."""
        if not self.account_file.exists():
            return None
        data = json.loads(self.account_file.read_text())
        return Account(**data)
    
    def get_env(self) -> dict:
        """Load credentials as a dict for passing to subprocesses."""
        creds = self.get()
        if not creds:
            return {}
        
        env = {}
        for key, value in asdict(creds).items():
            if value is not None:
                env[f"BBOUNTY_{key.upper()}"] = value
        
        account = self.get_account()
        if account:
            if account.email:
                env["BBOUNTY_EMAIL"] = account.email
            if account.platform:
                env["BBOUNTY_PLATFORM"] = account.platform
        
        return env
    
    # ─── Validation ────────────────────────────────────────────────────────
    
    def validate(self, credentials: Optional[Credentials] = None) -> bool:
        """Check if credentials appear to be present and non-empty."""
        if credentials is None:
            credentials = self.get()
        if credentials is None:
            return False
        
        # At least one auth field must be set
        return any([
            credentials.api_token,
            credentials.session_token,
            credentials.oauth_token,
            credentials.api_key,
            credentials.password,
        ])
    
    def validate_api_token(self, token: str, platform: str = "hackerone") -> bool:
        """
        Test if an API token is valid by making a lightweight API call.
        Returns True if the token works.
        """
        import requests
        
        if not token:
            return False
        
        try:
            if platform.lower() == "hackerone":
                r = requests.get(
                    "https://api.hackerone.com/v1/users/me",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10
                )
                return r.status_code == 200
            elif platform.lower() == "bugcrowd":
                r = requests.get(
                    "https://bugcrowd.com/api/v1/user",
                    headers={"Authorization": f"Token token={token}"},
                    timeout=10
                )
                return r.status_code == 200
            elif platform.lower() == "intigriti":
                r = requests.get(
                    "https://api.intigriti.com/user",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10
                )
                return r.status_code == 200
            else:
                # Generic test — try the token as-is
                return len(token) > 10
        except Exception:
            return False
    
    # ─── Security ──────────────────────────────────────────────────────────
    
    @staticmethod
    def _secure_perms(path: Path) -> None:
        """Set permissions: 0o700 for dirs (owner rwx), 0o600 for files (owner rw)."""
        if path.is_dir():
            os.chmod(path, stat.S_IRWXU)  # 0o700 — dirs need +x to traverse
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600


def list_programs(*, family: str = DEFAULT_CORE_FAMILY, lane: str | None = None) -> list[str]:
    """List all programs that have credential stores."""
    base = Path.home() / "Shared" / family
    if not base.exists():
        return []
    pattern = f"*/{lane or '*'}/context/credentials/credentials.env"
    return sorted({path.parents[3].name for path in base.glob(pattern)})


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Credential Store CLI")
    sub = parser.add_subparsers(dest="cmd")
    
    # init
    p_init = sub.add_parser("init", help="Initialize credential store for a program")
    p_init.add_argument("program", help="Program name")
    p_init.add_argument("--core-program", "--name", dest="core_program", default=None, help="bounty-core program/target identity/name")
    p_init.add_argument("--family", default=DEFAULT_CORE_FAMILY, help=f"bounty-core storage family (default: {DEFAULT_CORE_FAMILY})")
    p_init.add_argument("--lane", default=DEFAULT_CORE_LANE, help=f"bounty-core storage lane (default: {DEFAULT_CORE_LANE})")
    
    # store
    p_store = sub.add_parser("store", help="Store credentials")
    p_store.add_argument("program", help="Program name")
    p_store.add_argument("--token", help="API token")
    p_store.add_argument("--session", help="Session token")
    p_store.add_argument("--email", help="Account email")
    p_store.add_argument("--platform", help="Platform (hackerone, bugcrowd, etc.)")
    p_store.add_argument("--core-program", "--name", dest="core_program", default=None, help="bounty-core program/target identity/name")
    p_store.add_argument("--family", default=DEFAULT_CORE_FAMILY, help=f"bounty-core storage family (default: {DEFAULT_CORE_FAMILY})")
    p_store.add_argument("--lane", default=DEFAULT_CORE_LANE, help=f"bounty-core storage lane (default: {DEFAULT_CORE_LANE})")
    
    # list
    p_list = sub.add_parser("list", help="List programs with credentials")
    p_list.add_argument("--family", default=DEFAULT_CORE_FAMILY, help=f"bounty-core storage family (default: {DEFAULT_CORE_FAMILY})")
    p_list.add_argument("--lane", default=None, help="Optional bounty-core lane filter")
    
    # validate
    p_validate = sub.add_parser("validate", help="Validate credentials for a program")
    p_validate.add_argument("program", help="Program name")
    p_validate.add_argument("--core-program", "--name", dest="core_program", default=None, help="bounty-core program/target identity/name")
    p_validate.add_argument("--family", default=DEFAULT_CORE_FAMILY, help=f"bounty-core storage family (default: {DEFAULT_CORE_FAMILY})")
    p_validate.add_argument("--lane", default=DEFAULT_CORE_LANE, help=f"bounty-core storage lane (default: {DEFAULT_CORE_LANE})")
    
    args = parser.parse_args()
    
    if args.cmd == "init":
        store = CredentialStore(args.core_program or args.program, family=args.family, lane=args.lane)
        if store.init():
            print(f"✅ Created credential store for '{store.program}'")
        else:
            print(f"ℹ️  Credential store for '{store.program}' already exists")
    
    elif args.cmd == "store":
        store = CredentialStore(args.core_program or args.program, family=args.family, lane=args.lane)
        creds = Credentials(api_token=args.token, session_token=args.session)
        account = Account(email=args.email or "", platform=args.platform) if args.email else None
        store.store(creds, account)
        print(f"✅ Stored credentials for '{store.program}'")
    
    elif args.cmd == "list":
        programs = list_programs(family=args.family, lane=args.lane)
        if programs:
            print("Programs with credentials:")
            for p in programs:
                print(f"  • {p}")
        else:
            print("No credential stores found.")
    
    elif args.cmd == "validate":
        store = CredentialStore(args.core_program or args.program, family=args.family, lane=args.lane)
        creds = store.get()
        valid = store.validate(creds)
        account = store.get_account()
        platform = account.platform if account else "unknown"
        
        if valid:
            print(f"✅ Credentials found for '{store.program}'")
            if creds and creds.api_token:
                is_api_valid = store.validate_api_token(creds.api_token, platform)
                print(f"   API token: {'✅ valid' if is_api_valid else '⚠️  could not verify'}")
        else:
            print(f"❌ No credentials found for '{store.program}'")
    
    else:
        parser.print_help()

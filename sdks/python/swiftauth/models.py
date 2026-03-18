from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AppInfo:
    name: str = ""
    version: str = ""
    anti_debug: bool = False
    anti_vm: bool = False
    lock_hwid: bool = False
    lock_ip: bool = False
    lock_pc_name: bool = False


@dataclass
class UserData:
    key: str = ""
    username: str = ""
    email: str = ""
    level: int = 0
    expires_at: Optional[str] = None
    metadata: Optional[dict] = None


@dataclass
class VariableData:
    key: str = ""
    value: str = ""
    type: str = "STRING"


@dataclass
class UserVariableData:
    key: str = ""
    value: str = ""


@dataclass
class UpdateCheckResult:
    update_available: bool = False
    latest_version: str = ""
    current_version: str = ""
    file: Optional[dict] = None

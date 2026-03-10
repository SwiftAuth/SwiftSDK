from swiftauth.client import SwiftAuthClient, SwiftAuthError
from swiftauth.models import (
    AppInfo,
    UserData,
    VariableData,
    UserVariableData,
    UpdateCheckResult,
)

__version__ = "1.0.0"
__all__ = [
    "SwiftAuthClient",
    "SwiftAuthError",
    "AppInfo",
    "UserData",
    "VariableData",
    "UserVariableData",
    "UpdateCheckResult",
]

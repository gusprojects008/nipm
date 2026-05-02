import os
import pwd
from pathlib import Path
from logging import getLogger

from core.app import ProfilesManager, WPAProcessManager, DHCPCDProcessManager

logger = getLogger(__name__)


class AppContext:
    def __init__(self):
        self.real_user = os.environ.get("SUDO_USER") or os.getlogin()
        pw = pwd.getpwnam(self.real_user)
        home_dir = Path(pw.pw_dir)

        self.config_dir: Path = home_dir / ".config" / "nipm"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.chmod(0o740)

        self.config_file_path: Path = self.config_dir / "nipm-config.json"

        self.profiles_manager = ProfilesManager(self.config_dir, self.config_file_path)
        self.wpa_manager = WPAProcessManager()
        self.dhcpcd_manager = DHCPCDProcessManager()

        logger.debug(
            f"AppContext initialized — user={self.real_user} "
            f"config_dir={self.config_dir}"
        )

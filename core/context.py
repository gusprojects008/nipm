import os
import pwd
from pathlib import Path
from logging import getLogger

logger = getLogger(__name__)

class AppContext:
    def __init__(self, config: dict):
        self.config = config

        self.real_user = os.environ.get("SUDO_USER") or os.getlogin()
        pw = pwd.getpwnam(self.real_user)
        home_dir = Path(pw.pw_dir)

        self.config_dir: Path = home_dir / ".config" / "nipm"

        self.config_file_path: Path = self.config_dir / "nipm-config.json"

        logger.debug(
            f"AppContext initialized — user={self.real_user} "
        )

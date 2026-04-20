#!/usr/bin/env python3

import os
import socket
import sys
import shutil
import subprocess
import time
import json
from pathlib import Path
import re
import getpass
import pwd
import argparse
import hashlib
import logging
from logging import FileHandler, Formatter
from typing import Dict, List, Any, Tuple, Optional
import readline
import atexit

from rich.logging import RichHandler

# ─── Logging setup ────────────────────────────────────────────────────────────

def new_file_path(fullpath: str = None, fullpath_fallback: str = "nipm",
                  base: str = None, ext: str = None, filename: str = None) -> Path:
    """
    Unified new_file_path.

    Simple form (from framesniff pattern):
        new_file_path("nipm.log")        -> nipm-2025-01-01_12-00-00.log
        new_file_path(fullpath_fallback="nipm") -> nipm-<ts>

    Legacy keyword form (original nipm pattern):
        new_file_path(base="scan", ext=".txt")
        new_file_path(base="scan", filename="myfile.txt")
    """
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")

    # Simple / framesniff-style usage
    if fullpath or (not base and not ext and not filename):
        p = Path(fullpath if fullpath else fullpath_fallback)
        suffix = p.suffix
        stem = p.with_suffix("")
        return Path(f"{stem}-{timestamp}{suffix}")

    # Legacy keyword usage
    if filename:
        return Path(f"{timestamp}-{filename}")
    if base and ext:
        return Path(f"{base}-{timestamp}{ext}")
    if base:
        return Path(f"{base}-{timestamp}")
    return Path(timestamp)


def setup_logging(verbose: bool = False) -> Optional[Path]:
    """
    Configure root logger:
      - Always: RichHandler → INFO to console (coloured, pretty).
      - If verbose: FileHandler → DEBUG to a timestamped log file.

    Returns the log file path when verbose=True, otherwise None.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=False,
        show_path=False,
        markup=True,
    )
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(Formatter("%(message)s"))
    logger.addHandler(console_handler)

    log_file_path: Optional[Path] = None
    if verbose:
        log_file_path = new_file_path("nipm.log")
        file_handler = FileHandler(str(log_file_path))
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)

    return log_file_path


# Bootstrap logging early (no verbose flag yet – will be reconfigured in main)
setup_logging(verbose=False)
logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

DEPENDENCIES = ['wpa_supplicant', 'dhcpcd', 'iw', 'ip']
SERVICE_TIMEOUT = 30
PROCESS_TIMEOUT = 5

# ─── Privilege / dependency checks ────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        raise PermissionError(
            f"This program requires root permissions to run.\n"
            f"Run: sudo {' '.join(sys.argv)}"
        )


def check_dependencies(deps: List[str]):
    for dep in deps:
        if not shutil.which(dep):
            raise FileNotFoundError(f"{dep} not found. Install it and try again...")


# ─── Interface helpers ────────────────────────────────────────────────────────

def check_interface_mode(ifname: str, mode: str) -> bool:
    """
    Verify that *ifname* is currently in the given *mode* (e.g. 'managed',
    'monitor').  Raises RuntimeError / Exception on any problem.
    """
    try:
        result = subprocess.run(
            ['iw', 'dev', ifname, 'info'],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Interface {ifname} not found or iw command failed")
        match = re.search(r'type\s+(\w+)', result.stdout)
        if match:
            if match.group(1).lower() == mode:
                return True
            raise Exception(
                f"Error: set the interface to {mode}:\n"
                f"  RUN: sudo nipm.py set-{mode} -i {ifname}"
            )
        raise RuntimeError(f"Could not determine interface type for {ifname}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("iw command timed out")
    except FileNotFoundError:
        raise RuntimeError("iw command not found")
    except Exception as error:
        raise RuntimeError(f"Error checking interface mode: {error}")


def check_interface_exists(ifname: str) -> bool:
    logger.debug(f"Checking if {ifname} exists...")
    return Path(f"/sys/class/net/{ifname}").exists()


def check_active_interface(ifname: str) -> bool:
    logger.debug(f"Checking if {ifname} is active...")
    try:
        state_path = Path(f"/sys/class/net/{ifname}/operstate")
        return state_path.read_text().strip() == "up"
    except Exception:
        return False


def check_interface_ipv4(ifname: str) -> bool:
    logger.debug(f"Checking IPv4 configuration for {ifname}...")
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", ifname],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, text=True
        )
        return "inet " in result.stdout
    except Exception:
        return False


def check_default_gateway(ifname: str) -> bool:
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                fields = line.strip().split()
                iface, dest, mask = fields[0], fields[1], fields[7]
                if iface == ifname and dest == "00000000" and mask == "00000000":
                    return True
    except Exception:
        pass
    return False


def interface_working(ifname: str) -> bool:
    logger.debug(f"Checking if {ifname} is working...")
    return all([
        check_interface_exists(ifname),
        check_active_interface(ifname),
        check_interface_ipv4(ifname),
        check_default_gateway(ifname),
    ])


def set_interface_down(ifname: str) -> bool:
    logger.info(f"Bringing interface [bold]{ifname}[/bold] down...")
    try:
        subprocess.run(["ip", "link", "set", ifname, "down"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as error:
        logger.error(f"Failed to set interface {ifname} down: {error}")
        return False


def set_interface_up(ifname: str) -> bool:
    logger.info(f"Bringing interface [bold]{ifname}[/bold] up...")
    try:
        subprocess.run(["ip", "link", "set", ifname, "up"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as error:
        logger.error(f"Failed to set interface {ifname} up: {error}")
        return False


def restart_interface(ifname: str) -> bool:
    logger.info(f"Restarting [bold]{ifname}[/bold]...")
    try:
        return set_interface_down(ifname) and set_interface_up(ifname)
    except Exception as error:
        logger.error(f"Error restarting interface {ifname}: {error}")
        return False


def get_mac_address(ifname: str) -> Optional[str]:
    try:
        return Path(f"/sys/class/net/{ifname}/address").read_text().strip()
    except Exception:
        logger.warning(f"Could not read MAC address for {ifname}")
        return None


def is_wireless(ifname: str) -> bool:
    logger.debug(f"Checking if {ifname} is wireless...")
    try:
        return Path(f"/sys/class/net/{ifname}/wireless").exists()
    except Exception:
        return False


# ─── PSK / profile validation ─────────────────────────────────────────────────

def _generate_hex_psk(ssid: str, psk: str) -> str:
    logger.debug(f"Generating hex PSK for SSID '{ssid}'...")
    return hashlib.pbkdf2_hmac(
        'sha1', psk.encode('utf-8'), ssid.encode('utf-8'), 4096, 32
    ).hex()


def validate_interface_profile_data(
    CONFIG_DIR: Path, ifname: str, profile_data: Dict[str, Any]
) -> Dict[str, Any]:
    logger.debug(f"Validating profile for {ifname}...")

    hwaddr = get_mac_address(ifname) if (ifname and check_interface_exists(ifname)) else None

    metric = profile_data.get("metric", 100)
    if not isinstance(metric, int) or metric <= 0:
        raise ValueError(f"Invalid metric for {ifname}: {metric}")

    is_wifi = ("ssid" in profile_data and profile_data["ssid"].strip()) or is_wireless(ifname)

    if is_wifi:
        ssid = profile_data.get("ssid", "").strip()
        if not ssid or len(ssid) > 32:
            raise ValueError(f"SSID for {ifname} must be 1–32 characters.")
        psk = profile_data.get("psk", "").strip()
        if not (8 <= len(psk) <= 63):
            raise ValueError(f"PSK for {ifname} must be 8–63 characters.")
        psk_hex = _generate_hex_psk(ssid, psk)
        return {
            "hwaddr": hwaddr,
            "type": "wireless",
            "metric": metric,
            "ssid": ssid,
            "psk": psk,
            "psk_hex": psk_hex,
            "wpa_supplicant_conf_path": str(CONFIG_DIR / f"wpa-supplicant-{ifname}.conf"),
            "dhcpcd_conf_path": str(CONFIG_DIR / f"dhcpcd-{ifname}.conf"),
        }
    else:
        return {
            "hwaddr": hwaddr,
            "type": "ethernet",
            "metric": metric,
            "dhcpcd_conf_path": str(CONFIG_DIR / f"dhcpcd-{ifname}.conf"),
        }


# ─── Config parsing ───────────────────────────────────────────────────────────

def parse_config(
    CONFIG_DIR: Path, config_file_path: Path
) -> List[Tuple[str, Dict[str, Any]]]:
    logger.debug(f"Parsing config file {config_file_path}...")

    if not config_file_path or not config_file_path.is_file():
        logger.error(f"Configuration file not found at {config_file_path}")
        sys.exit(1)
    try:
        with config_file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as error:
        logger.error(f"Error reading JSON config: {error}")
        sys.exit(1)

    profiles = []
    for ifname, profile_data in data.items():
        try:
            valid = validate_interface_profile_data(CONFIG_DIR, ifname, profile_data)
            profiles.append((ifname, valid))
        except Exception as error:
            logger.error(f"Skipping profile for {ifname}: {error}")
    if not profiles:
        logger.error("No valid profiles found in configuration.")
    return profiles


# ─── ProfilesManager ─────────────────────────────────────────────────────────

class ProfilesManager:
    def __init__(self, CONFIG_DIR: Path, config_file_path: Path):
        self.config_dir = CONFIG_DIR
        self.config_file_path = config_file_path

    def create_profile(self, ifname: str, valid_profile: Dict[str, Any]) -> bool:
        logger.info(f"Creating/updating profile for [bold]{ifname}[/bold]...")
        if valid_profile["type"] == "wireless":
            wpa_path = Path(valid_profile['wpa_supplicant_conf_path'])
            wpa_conf = (
                f"ctrl_interface=/var/run/wpa_supplicant\n"
                f"network={{\n"
                f"    ssid=\"{valid_profile['ssid']}\"\n"
                f"    psk={valid_profile['psk_hex']}\n"
                f"}}"
            )
            wpa_path.write_text(wpa_conf.strip() + "\n")
            wpa_path.chmod(0o740)

        dhcp_path = Path(valid_profile['dhcpcd_conf_path'])
        dhcp_conf = f"interface {ifname}\nmetric {valid_profile['metric']}"
        dhcp_path.write_text(dhcp_conf.strip() + "\n")
        dhcp_path.chmod(0o740)

        all_profiles = self._read_profiles()
        all_profiles[ifname] = valid_profile
        self._write_profiles(all_profiles)
        logger.info(f"Profile for [bold]{ifname}[/bold] saved successfully.")
        return True

    def list_profiles(self):
        data = self._read_profiles()
        if not data:
            logger.info("No network profiles found.")
            return
        for ifname, profile in data.items():
            logger.info(f"[bold cyan]{ifname}[/bold cyan] → {profile}")

    def remove_profile(self, ifname: str) -> bool:
        all_profiles = self._read_profiles()
        if ifname not in all_profiles:
            logger.error(f"Profile for {ifname} not found.")
            return False
        try:
            p = validate_interface_profile_data(
                self.config_dir, ifname, all_profiles[ifname]
            )
            if p["type"] == "wireless":
                Path(p['wpa_supplicant_conf_path']).unlink(missing_ok=True)
            Path(p['dhcpcd_conf_path']).unlink(missing_ok=True)
        except ValueError as error:
            logger.warning(f"Could not resolve file paths for {ifname}: {error}")
        except Exception as error:
            logger.error(f"File cleanup error for {ifname}: {error}")
            return False

        del all_profiles[ifname]
        self._write_profiles(all_profiles)
        logger.info(f"Profile for [bold]{ifname}[/bold] removed.")
        return True

    def remove_all_profiles(self) -> bool:
        if not self.config_file_path.exists():
            logger.info("No profiles to remove.")
            return True
        try:
            for ifname, profile_data in parse_config(self.config_dir, self.config_file_path):
                if profile_data["type"] == "wireless":
                    Path(profile_data['wpa_supplicant_conf_path']).unlink(missing_ok=True)
                Path(profile_data['dhcpcd_conf_path']).unlink(missing_ok=True)
            self.config_file_path.unlink()
            logger.info("All profiles removed.")
            return True
        except SystemExit:
            logger.warning("Failed to parse config. Running manual cleanup...")
            if self.config_dir.exists():
                shutil.rmtree(self.config_dir)
            return True
        except Exception as error:
            logger.error(f"Failed to remove all profiles: {error}")
            return False

    def _read_profiles(self) -> Dict[str, Any]:
        if not self.config_file_path.exists():
            return {}
        try:
            with self.config_file_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as error:
            logger.warning(f"Could not read {self.config_file_path}: {error}. Starting fresh.")
            return {}

    def _write_profiles(self, data: Dict[str, Any]):
        try:
            with self.config_file_path.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.config_file_path.chmod(0o740)
        except Exception as error:
            logger.error(f"Failed to write profiles: {error}")


# ─── WPA / DHCPCD process managers ───────────────────────────────────────────

class WPAProcessManager:
    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}

    def start(self, ifname: str, config_path: str) -> bool:
        self.stop(ifname)
        socket_path = Path(f"/var/run/wpa_supplicant/{ifname}")
        if socket_path.exists():
            try:
                os.remove(socket_path)
            except OSError:
                pass
        try:
            proc = subprocess.Popen(
                ["wpa_supplicant", "-i", ifname, "-c", config_path, "-D", "nl80211"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.processes[ifname] = proc
            return True
        except Exception:
            return False

    def stop(self, ifname: str):
        proc = self.processes.pop(ifname, None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=PROCESS_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def stop_all(self):
        for ifname in list(self.processes):
            self.stop(ifname)

    def wait_for_connected(self, ifname: str) -> bool:
        return self._wait_for_wpa_event(ifname, "CTRL-EVENT-CONNECTED")

    def _wait_for_wpa_event(self, ifname: str, event: str) -> bool:
        logger.info(
            f"Waiting for wpa_supplicant [{event}] on {ifname} "
            f"(timeout {SERVICE_TIMEOUT}s)..."
        )
        ctrl_path = f"/var/run/wpa_supplicant/{ifname}"
        local_path = f"/tmp/wpa_ctrl_{ifname}_{os.getpid()}"

        if os.path.exists(local_path):
            try:
                os.unlink(local_path)
            except Exception:
                pass

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            start = time.time()
            while not os.path.exists(ctrl_path):
                if time.time() - start > SERVICE_TIMEOUT:
                    return False
                time.sleep(1)

            sock.bind(local_path)
            sock.connect(ctrl_path)
            sock.send(b"ATTACH")
            data = sock.recv(4096).decode('utf-8', errors='ignore')
            if "OK" not in data:
                logger.error("wpa_supplicant ATTACH failed")
                return False
            sock.settimeout(SERVICE_TIMEOUT)
            while True:
                data = sock.recv(4096).decode('utf-8', errors='ignore')
                if event in data:
                    logger.info(f"wpa_supplicant event received: {event}")
                    return True
        except socket.timeout:
            logger.error("Timeout waiting for wpa_supplicant event")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in wpa_supplicant wait: {e}")
            return False
        finally:
            sock.close()
            if os.path.exists(local_path):
                try:
                    os.unlink(local_path)
                except Exception:
                    pass


class DHCPCDProcessManager:
    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}

    def start(self, ifname: str, config_path: str) -> bool:
        logger.info(f"Starting dhcpcd for [bold]{ifname}[/bold]...")
        self.stop(ifname)
        try:
            proc = subprocess.Popen(
                ["dhcpcd", "-n", ifname, "-f", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.processes[ifname] = proc
            start_time = time.time()
            while True:
                if check_interface_ipv4(ifname) and check_default_gateway(ifname):
                    logger.info(f"dhcpcd configured [bold]{ifname}[/bold] successfully.")
                    return True
                if time.time() - start_time > SERVICE_TIMEOUT:
                    logger.error(f"Timeout waiting for DHCP lease on {ifname}")
                    self.stop(ifname)
                    return False
                time.sleep(1)
        except Exception as e:
            logger.error(f"Failed to start dhcpcd for {ifname}: {e}")
            self.stop(ifname)
            return False

    def stop(self, ifname: str):
        proc = self.processes.pop(ifname, None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=PROCESS_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def stop_all(self):
        for ifname in list(self.processes):
            self.stop(ifname)


# ─── Connection logic ─────────────────────────────────────────────────────────

def cleanup_network_processes(real_user: str, wpa_manager, dhcpcd_manager):
    logger.info("Cleaning up network processes...")
    dhcpcd_manager.stop_all()
    wpa_manager.stop_all()
    for proc_name in ("wpa_supplicant", "dhcpcd"):
        try:
            subprocess.run(
                ["pkill", "-u", real_user, proc_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception as e:
            logger.warning(f"Process cleanup failed for {proc_name}: {e}")


def connection(
    profile: Tuple[str, Dict[str, Any]], wpa_manager, dhcpcd_manager
) -> bool:
    ifname, p = profile
    if p["type"] == "wireless":
        success = (
            wpa_manager.start(ifname, p["wpa_supplicant_conf_path"])
            and wpa_manager.wait_for_connected(ifname)
            and dhcpcd_manager.start(ifname, p["dhcpcd_conf_path"])
        )
    else:
        success = dhcpcd_manager.start(ifname, p["dhcpcd_conf_path"])

    if success:
        logger.info(f"[bold green]Connection successful[/bold green] on {ifname}.")
    else:
        logger.error(f"Connection failed on {ifname}.")
    return success


def start(
    profiles: List[Tuple[str, Dict[str, Any]]],
    background: bool,
    sleep_time: int,
    real_user: str,
    wpa_manager,
    dhcpcd_manager,
):
    if not profiles:
        logger.error("No valid profiles found.")
        return

    profiles.sort(key=lambda p: p[1]["metric"])
    cleanup_network_processes(real_user, wpa_manager, dhcpcd_manager)
    ifname, profile_data = profiles[0]

    if not background:
        if connection((ifname, profile_data), wpa_manager, dhcpcd_manager):
            logger.info("Connection established. Exiting.")
        else:
            logger.error("Could not establish a connection using any available profile.")
        return

    logger.info("Monitoring mode activated [dim](Ctrl+C to exit)[/dim]")
    active_ifname = None
    try:
        while True:
            best = next(
                (n for n, _ in profiles if check_interface_exists(n)), None
            )
            if best != active_ifname:
                if active_ifname:
                    logger.info(f"Switching from {active_ifname} to {best}...")
                    wpa_manager.stop(active_ifname)
                    dhcpcd_manager.stop(active_ifname)
                if best:
                    current_profile = next(p for n, p in profiles if n == best)
                    if connection((best, current_profile), wpa_manager, dhcpcd_manager):
                        active_ifname = best
                    else:
                        logger.error(f"Failed to connect to {best}. Retrying in {sleep_time}s.")
                        active_ifname = None
                else:
                    active_ifname = None
            elif active_ifname and not interface_working(active_ifname):
                logger.warning(f"Connection on {active_ifname} dropped. Reconnecting...")
                current_profile = next(p for n, p in profiles if n == active_ifname)
                if not connection((active_ifname, current_profile), wpa_manager, dhcpcd_manager):
                    active_ifname = None
            time.sleep(sleep_time)
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user.")
    except Exception as error:
        logger.error(f"Monitoring stopped by error: {error}")
    finally:
        cleanup_network_processes(real_user, wpa_manager, dhcpcd_manager)
        if active_ifname:
            restart_interface(active_ifname)
        logger.info("All connections cleaned up.")


# ─── Scan ─────────────────────────────────────────────────────────────────────

def scan(ifname: str, output_filename: str = None):
    print("In development, see https://github.com/gusprojects008/wnlpy\n")
    print(f"Scanning Wi-Fi networks on {ifname}...\n")

    if not Path(f"/sys/class/net/{ifname}").exists():
        logger.error(f"Interface {ifname} not found.")
        return
    try:
        set_interface_up(ifname)
        result = subprocess.run(
            ["iw", "dev", ifname, "scan"],
            capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        logger.error("'iw' command not found.")
        return
    except subprocess.CalledProcessError as e:
        logger.error(f"Scan failed: {e}")
        return

    if not result.stdout.strip():
        print("No networks found.")
        return

    def extract(pattern, text, default="N/A"):
        m = re.search(pattern, text)
        return m.group(1).strip() if m else default

    def security_type(block):
        if "WPA3" in block or "SAE" in block:
            return "WPA3"
        if "WPA2" in block or "RSN:" in block:
            return "WPA2"
        if "WPA:" in block:
            return "WPA"
        if "privacy" in block:
            return "WEP"
        return "OPEN"

    def wps_status(block):
        if "WPS:" not in block:
            return "Disabled"
        state = extract(r"Wi-Fi Protected Setup State:\s*\d+\s*\((\w+)\)", block, "")
        methods = extract(r"Config methods:\s*(.+)", block, "")
        locked = "[LOCKED]" if "AP setup locked: 0x01" in block else ""
        details = (f" ({state})" if state else "") + (f" - {methods}" if methods else "")
        return f"Enabled{details} {locked}".strip()

    def encryption_modes(block):
        enc = []
        if "CCMP" in block:
            enc.append("AES")
        if "TKIP" in block:
            enc.append("TKIP")
        return ", ".join(enc) if enc else "None"

    def security_flags(block):
        flags = []
        if "WPA3" in block or "SAE" in block:
            flags.append("WPA3")
        if "Management frame protection: required" in block:
            flags.append("PMF-Required")
        elif "Management frame protection: capable" in block:
            flags.append("PMF-Capable")
        return ", ".join(flags) if flags else "None"

    def print_network(num, block):
        print(
            f"┌─── NETWORK #{num} {'─' * 50}\n"
            f"│ SSID: {extract(r'SSID:\\s*(.+)', block, 'Hidden')}\n"
            f"│ BSSID: {extract(r'^([0-9a-f:]{17})', block)}\n"
            f"│ Signal: {extract(r'signal:\\s*([-\\d.]+)\\s*dBm', block)} dBm | "
            f"Channel: {extract(r'DS Parameter set:\\s*channel\\s*(\\d+)', block)} | "
            f"Freq: {extract(r'freq:\\s*([\\d.]+)', block)} MHz\n"
            f"│ Security: {security_type(block)}\n"
            f"│ Encryption: {encryption_modes(block)}\n"
            f"│ Vendor: {extract(r'Manufacturer:\\s*(.+)', block, 'Unknown')}\n"
            f"│ WPS: {wps_status(block)}\n"
            f"│ Security Flags: {security_flags(block)}\n"
            f"└{'─' * 60}"
        )

    blocks = result.stdout.strip().split("\nBSS ")[1:]
    if not blocks:
        print("No networks found.")
        return

    output_path = new_file_path(
        fullpath_fallback=f"station-scan-result",
        base="station-scan-result", ext=".txt", filename=output_filename
    )
    output_path.write_text(result.stdout)
    for i, block in enumerate(blocks, 1):
        print_network(i, block)
    print(f"\nTotal networks found: {len(blocks)}")


# ─── List interfaces ──────────────────────────────────────────────────────────

def list_interfaces() -> List[str]:
    try:
        interfaces = [
            iface.name for iface in Path("/sys/class/net").iterdir() if iface.is_dir()
        ]
        if not interfaces:
            logger.warning("No network interfaces found.")
            return []
        print("Available interfaces:")
        for ifname in interfaces:
            print(f"  [bold]{ifname}[/bold]  {get_mac_address(ifname) or ''}")
        return interfaces
    except Exception as error:
        logger.error(f"Failed to list interfaces: {error}")
        return []


# ─── History / readline helpers ──────────────────────────────────────────────

# Commands eligible for tab-completion
NIPM_COMMANDS = [
    "create-profile",
    "list-profiles",
    "remove-profile",
    "remove-profiles",
    "start",
    "scan",
    "list-interfaces",
]


class HistoryManager:
    """
    Wraps readline to provide:
      - Persistent per-namespace history (~/.config/nipm/.history_<ns>)
      - Tab-completion of network interfaces *and* nipm subcommands
    """

    def __init__(self, namespace: str = "global"):
        self.namespace = namespace
        self.histfile = Path.home() / ".config" / "nipm" / f".history_{namespace}"
        self.histfile.parent.mkdir(parents=True, exist_ok=True)
        self._setup_readline()

    def _setup_readline(self):
        try:
            readline.read_history_file(self.histfile)
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)
        readline.set_completer(self._completer)
        readline.parse_and_bind("tab: complete")
        atexit.register(readline.write_history_file, self.histfile)

    def _completer(self, text: str, state: int) -> Optional[str]:
        """Complete network interfaces and nipm subcommands."""
        candidates: List[str] = []

        # Network interfaces
        try:
            candidates += [
                iface.name
                for iface in Path("/sys/class/net").iterdir()
                if iface.is_dir()
            ]
        except Exception:
            pass

        # Subcommands
        candidates += NIPM_COMMANDS

        matches = [c for c in candidates if c.startswith(text)]
        return matches[state] if state < len(matches) else None

    def input(self, prompt_text: str) -> str:
        return input(prompt_text).strip()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    # Pre-parse verbose flag so logging is configured before anything else runs
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("-v", "--verbose", action="store_true")
    pre_args, _ = pre_parser.parse_known_args()
    log_file = setup_logging(verbose=pre_args.verbose)
    if log_file:
        logger.info(f"Verbose mode enabled. Writing debug log to {log_file}")

    check_root()
    check_dependencies(DEPENDENCIES)

    real_user = os.environ.get("SUDO_USER") or os.getlogin()
    pw = pwd.getpwnam(real_user)
    home_dir = Path(pw.pw_dir)
    CONFIG_DIR = home_dir / ".config" / "nipm"
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.chmod(0o740)
    config_file_path = CONFIG_DIR / "nipm-config.json"

    profiles_manager = ProfilesManager(CONFIG_DIR, config_file_path)
    wpa_manager = WPAProcessManager()
    dhcpcd_manager = DHCPCDProcessManager()

    parser = argparse.ArgumentParser(
        description="Network Interface Profile Manager (NIPM)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging to a timestamped log file."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    subparsers.add_parser("create-profile",    help="Create or update a network profile.")
    subparsers.add_parser("list-profiles",     help="List all saved network profiles.")
    subparsers.add_parser("remove-profile",    help="Remove a specific network profile.")
    subparsers.add_parser("remove-profiles",   help="Remove all network profiles.")
    subparsers.add_parser("list-interfaces",   help="List network interfaces.")

    start_p = subparsers.add_parser("start", help="Connect to a network.")
    start_p.add_argument("-b", "--background", action="store_true",
                         help="Run in monitoring mode with failover and failback.")
    start_p.add_argument("-s", "--sleep", type=int, default=8,
                         help="Seconds between interface checks (default: 8)")

    scan_p = subparsers.add_parser("scan", help="Scan for wireless networks.")
    scan_p.add_argument("ifname", type=str, help="Wireless interface to use.")
    scan_p.add_argument("--output", "-o", type=str, default=None,
                        help="Output filename for scan results.")

    args = parser.parse_args()

    if args.command == "start":
        profiles = parse_config(CONFIG_DIR, config_file_path)
        start(profiles, args.background, args.sleep, real_user, wpa_manager, dhcpcd_manager)

    elif args.command == "scan":
        scan(args.ifname, args.output)

    elif args.command == "create-profile":
        list_interfaces()
        hist_iface  = HistoryManager("iface")
        hist_metric = HistoryManager("metric")
        hist_ssid   = HistoryManager("ssid")

        ifname = hist_iface.input("Network Interface Name (e.g. wlan0, enp0s3): ")
        if not ifname:
            raise ValueError("Interface name cannot be empty.")

        metric_val = hist_metric.input("Metric (default: 100): ")
        metric = int(metric_val) if metric_val else 100

        if is_wireless(ifname):
            ssid = hist_ssid.input("Network SSID: ")
            if not ssid:
                raise ValueError("SSID cannot be empty.")
            psk = getpass.getpass("Network Password (8–63 chars): ")
            if not psk:
                raise ValueError("Password cannot be empty.")
            temp = {"metric": metric, "ssid": ssid, "psk": psk}
        else:
            temp = {"metric": metric}

        valid = validate_interface_profile_data(CONFIG_DIR, ifname, temp)
        profiles_manager.create_profile(ifname, valid)

    elif args.command == "remove-profile":
        list_interfaces()
        hist_iface = HistoryManager("iface")
        ifname = hist_iface.input("Network Interface Name (e.g. wlan0, enp0s3): ")
        if not ifname:
            raise ValueError("Interface name cannot be empty.")
        profiles_manager.remove_profile(ifname)

    elif args.command == "remove-profiles":
        profiles_manager.remove_all_profiles()

    elif args.command == "list-profiles":
        profiles_manager.list_profiles()

    elif args.command == "list-interfaces":
        list_interfaces()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

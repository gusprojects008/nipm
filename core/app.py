import os
import re
import time
import json
import socket
import shutil
import hashlib
import getpass
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from logging import getLogger
from core.common.cli import HistoryManager

logger = getLogger(__name__)

WPA_SUPPLICANT_TIMEOUT = 20
DHCPCD_TIMEOUT = 15
PROCESS_TIMEOUT = 10

def check_interface_exists(ifname: str) -> bool:
    logger.info(f"Checking if {ifname} exists...")
    return Path(f"/sys/class/net/{ifname}").exists()

def check_active_interface(ifname: str) -> bool:
    logger.info(f"Checking if {ifname} is active...")
    try:
        state_path = Path(f"/sys/class/net/{ifname}/operstate")
        return state_path.read_text().strip() in ("up", "unknown")
    except Exception:
        return False

def check_interface_ipv4(ifname: str) -> bool:
    logger.info(f"Checking the IPv4 configuration for {ifname}...")
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", ifname],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=True, text=True
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
                if (fields[0] == ifname
                        and fields[1] == "00000000"
                        and fields[7] == "00000000"):
                    return True
    except Exception:
        pass
    return False

def interface_working(ifname: str) -> bool:
    logger.info(f"Checking if {ifname} is working...")
    return all([
        check_interface_exists(ifname),
        check_active_interface(ifname),
        check_interface_ipv4(ifname),
        check_default_gateway(ifname),
    ])

def _set_interface_state(mode: str, ifname: str) -> bool:
    logger.info(f"Bringing interface {ifname} {mode}...")
    try:
        subprocess.run(
            ["ip", "link", "set", ifname, mode],
            check=True, capture_output=True, text=True
        )
        logger.info(f"Interface {ifname} is {mode}.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(
            f"{e.stderr.strip() if e.stderr else 'Unknown error'}"
        )
    except Exception as e:
        logger.error(f"error configure {ifname} to {mode} mode: {e}")

    return False

def set_interface_down(ifname: str) -> bool:
    _set_interface_state("down", ifname)

def set_interface_up(ifname: str) -> bool:
    _set_interface_state("up", ifname)

def restart_interface(ifname: str) -> bool:
    logger.info(f"Restarting {ifname}...")
    return set_interface_down(ifname) and set_interface_up(ifname)

def get_mac_address(ifname: str) -> Optional[str]:
    try:
        return Path(f"/sys/class/net/{ifname}/address").read_text().strip()
    except Exception:
        logger.warning(f"Could not read MAC address for {ifname}")
        return None

def is_wireless(ifname: str) -> bool:
    logger.info(f"Checking if {ifname} is wireless...")
    return Path(f"/sys/class/net/{ifname}/wireless").exists()

def _generate_hex_psk(ssid: str, psk: str) -> str:
    logger.info(f"Generating hexadecimal PSK for {ssid}...")
    return hashlib.pbkdf2_hmac(
        "sha1", psk.encode("utf-8"), ssid.encode("utf-8"), 4096, 32
    ).hex()


def validate_interface_profile_data(
    config_dir: Path, ifname: str, profile_data: dict
) -> dict:
    logger.info(f"Validating profile for {ifname}...")

    hwaddr = get_mac_address(ifname) if ifname and check_interface_exists(ifname) else None

    metric = profile_data.get("metric", 100)
    if not isinstance(metric, int) or metric <= 0:
        raise ValueError(f"Invalid metric for {ifname}: {metric}")

    is_wifi = ("ssid" in profile_data and profile_data["ssid"].strip()) or is_wireless(ifname)

    if is_wifi:
        ssid = profile_data.get("ssid", "").strip()
        if not ssid or len(ssid) > 32:
            raise ValueError(f"SSID for {ifname} must be between 1 and 32 characters.")

        psk = profile_data.get("psk", "").strip()
        if not (8 <= len(psk) <= 63):
            raise ValueError(f"PSK for {ifname} must be between 8 and 63 characters.")

        return {
            "hwaddr": hwaddr,
            "type": "wireless",
            "metric": metric,
            "ssid": ssid,
            "psk": psk,
            "psk_hex": _generate_hex_psk(ssid, psk),
            "wpa_supplicant_conf_path": str(config_dir / f"wpa-supplicant-{ifname}.conf"),
            "dhcpcd_conf_path": str(config_dir / f"dhcpcd-{ifname}.conf"),
        }
    else:
        return {
            "hwaddr": hwaddr,
            "type": "ethernet",
            "metric": metric,
            "dhcpcd_conf_path": str(config_dir / f"dhcpcd-{ifname}.conf"),
        }


def parse_config(config_dir: Path, config_file_path: Path) -> List[Tuple[str, dict]]:
    logger.info(f"Parsing config file {config_file_path}...")

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
            valid = validate_interface_profile_data(config_dir, ifname, profile_data)
            profiles.append((ifname, valid))
        except Exception as error:
            logger.error(f"Unexpected error adding profile for {ifname}:\n{error}")
            continue

    if not profiles:
        logger.error("No valid profiles found in configuration.")

    return profiles

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
            f"Waiting for wpa_supplicant {event} for {ifname} "
            f"(timeout {WPA_SUPPLICANT_TIMEOUT}s)"
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
                if time.time() - start > WPA_SUPPLICANT_TIMEOUT:
                    return False
                time.sleep(1)

            sock.bind(local_path)
            sock.connect(ctrl_path)
            logger.info("Sending ATTACH message to wpa_supplicant")
            sock.send(b"ATTACH")
            data = sock.recv(4096).decode("utf-8", errors="ignore")
            if "OK" not in data:
                logger.error("wpa_supplicant service is not working")
                return False

            logger.info("wpa_supplicant service working")
            sock.settimeout(WPA_SUPPLICANT_TIMEOUT)
            while True:
                data = sock.recv(4096).decode("utf-8", errors="ignore")
                if event in data:
                    logger.info(f"wpa_supplicant response: {event}")
                    return True
        except socket.timeout as e:
            logger.error(f"Timeout waiting for wpa_supplicant: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error with wpa_supplicant: {e}")
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
        logger.info(f"Starting dhcpcd for {ifname}")
        self.stop(ifname)
        try:
            proc = subprocess.Popen(
                ["dhcpcd", ifname, "-f", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.processes[ifname] = proc
            start_time = time.time()
            while True:
                if check_interface_ipv4(ifname) and check_default_gateway(ifname):
                    logger.info(f"dhcpcd successfully configured {ifname}")
                    return True
                if time.time() - start_time > DHCPCD_TIMEOUT:
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


class ProfilesManager:
    def __init__(self, config_dir: Path, config_file_path: Path):
        self.config_dir = config_dir
        self.config_file_path = config_file_path

    def create_profile(self, ifname: str, valid_profile: dict) -> bool:
        logger.info(f"Attempting to create profile for {ifname}...")

        if valid_profile["type"] == "wireless":
            wpa_path = Path(valid_profile["wpa_supplicant_conf_path"])
            wpa_conf = (
                f"ctrl_interface=/var/run/wpa_supplicant\n"
                f"network={{\n"
                f"    ssid=\"{valid_profile['ssid']}\"\n"
                f"    psk={valid_profile['psk_hex']}\n"
                f"}}"
            )
            wpa_path.write_text(wpa_conf.strip() + "\n")
            wpa_path.chmod(0o740)

        dhcpcd_path = Path(valid_profile["dhcpcd_conf_path"])
        dhcpcd_conf = f"interface {ifname}\nmetric {valid_profile['metric']}"
        dhcpcd_path.write_text(dhcpcd_conf.strip() + "\n")
        dhcpcd_path.chmod(0o740)

        all_profiles = self._read_profiles()
        all_profiles[ifname] = valid_profile
        self._write_profiles(all_profiles)

        logger.info(f"Profile for {ifname} created/updated successfully!")
        return True

    def list_profiles(self):
        data = self._read_profiles()
        if not data:
            logger.info("No network profiles found.")
            return
        logger.info("Existing network profiles:")
        for ifname, profile in data.items():
            logger.info(f"\n{ifname} => {profile}\n")

    def remove_profile(self, ifname: str) -> bool:
        all_profiles = self._read_profiles()
        if ifname not in all_profiles:
            logger.error(f"Profile for {ifname} not found.")
            return False
        try:
            profile_to_remove = all_profiles[ifname]
            valid = validate_interface_profile_data(
                self.config_dir, ifname, profile_to_remove
            )
            if valid["type"] == "wireless":
                Path(profile_to_remove["wpa_supplicant_conf_path"]).unlink(missing_ok=True)
            Path(valid["dhcpcd_conf_path"]).unlink(missing_ok=True)
            logger.info(f"Cleaned up config files for {ifname}.")
        except ValueError as error:
            logger.warning(
                f"Could not get file paths for {ifname}, proceeding with removal: {error}"
            )
        except Exception as error:
            logger.error(f"Error during file cleanup for {ifname}: {error}")
            return False

        del all_profiles[ifname]
        self._write_profiles(all_profiles)
        logger.info(f"Profile for {ifname} removed successfully!")
        return True

    def remove_all_profiles(self) -> bool:
        if not self.config_file_path.exists():
            logger.info("No profiles to remove.")
            return True
        try:
            profiles_to_delete = parse_config(self.config_dir, self.config_file_path)
            for ifname, profile_data in profiles_to_delete:
                if profile_data["type"] == "wireless":
                    Path(profile_data["wpa_supplicant_conf_path"]).unlink(missing_ok=True)
                Path(profile_data["dhcpcd_conf_path"]).unlink(missing_ok=True)
                logger.info(f"Removed config files for {ifname}.")
            self.config_file_path.unlink()
            logger.info("All network profiles have been removed.")
            return True
        except SystemExit:
            logger.info("Failed to parse config for cleanup. Doing manual cleanup...")
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
            logger.warning(f"Could not read {self.config_file_path}: {error}.")
            return {}
        except Exception as error:
            logger.error(f"Could not read {self.config_file_path}: {error}.")
            raise

    def _write_profiles(self, data: Dict[str, Any]):
        try:
            with self.config_file_path.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.config_file_path.chmod(0o740)
        except Exception as error:
            logger.error(f"Failed to write to {self.config_file_path}: {error}.")


class Operations:
    def __init__(self, context):
        self.ctx = context

        self._dispatch = {
            "start": lambda args: self.start(
                background=args.background,
                sleep_time=args.sleep,
            ),
            "scan": lambda args: self.scan(
                ifname=args.ifname,
                output_filename=args.output,
            ),
            "create-profile": lambda args: self.create_profile(),
            "remove-profile": lambda args: self.ctx.profiles_manager.remove_profile(args.ifname),
            "remove-profiles": lambda args: self.ctx.profiles_manager.remove_all_profiles(),
            "list-profiles": lambda args: self.ctx.profiles_manager.list_profiles(),
            "list-interfaces": lambda args: self.list_interfaces(),
        }

    def dispatch(self, args):
        handler = self._dispatch.get(args.command)
        if not handler:
            raise ValueError(f"Unknown command: {args.command}")
        return handler(args)

    def _cleanup_network_processes(self):
        logger.info("Cleaning up network processes")
        self.ctx.dhcpcd_manager.stop_all()
        self.ctx.wpa_manager.stop_all()
        try:
            subprocess.run(
                ["pkill", "-u", self.ctx.real_user, "wpa_supplicant"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["pkill", "-u", self.ctx.real_user, "dhcpcd"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception as e:
            logger.warning(f"Process cleanup failed: {e}")

    def _connect(self, profile: Tuple[str, dict]) -> bool:
        ifname, p = profile
        wireless = p["type"] == "wireless"

        if wireless:
            success = (
                self.ctx.wpa_manager.start(ifname, p["wpa_supplicant_conf_path"])
                and self.ctx.wpa_manager.wait_for_connected(ifname)
                and self.ctx.dhcpcd_manager.start(ifname, p["dhcpcd_conf_path"])
            )
        else:
            success = self.ctx.dhcpcd_manager.start(ifname, p["dhcpcd_conf_path"])

        if success:
            logger.info(f"Connection successful on {ifname}!")
        else:
            logger.error(f"Connection failed on {ifname}.")
        return success

    def start(self, background: bool = False, sleep_time: int = 8):
        profiles = parse_config(self.ctx.config_dir, self.ctx.config_file_path)
        if not profiles:
            logger.error("No valid profiles found.")
            return

        profiles.sort(key=lambda p: p[1]["metric"])
        self._cleanup_network_processes()

        if not background:
            ifname, profile_data = profiles[0]
            if self._connect((ifname, profile_data)):
                logger.info("Connection established. The script will now exit.")
            else:
                logger.error("Could not establish a connection using any available profile.")
            return

        logger.info("Monitoring mode activated (Ctrl+C to exit)")
        active_ifname = None
        try:
            while True:
                best = next(
                    (ifname for ifname, _ in profiles if check_interface_exists(ifname)),
                    None
                )
                if best != active_ifname:
                    if active_ifname:
                        logger.info(f"Switching from {active_ifname} to {best}...")
                        self.ctx.wpa_manager.stop(active_ifname)
                        self.ctx.dhcpcd_manager.stop(active_ifname)
                    if best:
                        current = next(p for i, p in profiles if i == best)
                        if self._connect((best, current)):
                            active_ifname = best
                        else:
                            logger.error(
                                f"Failed to connect to {best}. Retrying in {sleep_time}s."
                            )
                            active_ifname = None
                    else:
                        active_ifname = None
                elif active_ifname and not interface_working(active_ifname):
                    logger.warning(
                        f"Connection on {active_ifname} seems down, reconnecting..."
                    )
                    current = next(p for i, p in profiles if i == active_ifname)
                    if not self._connect((active_ifname, current)):
                        active_ifname = None

                time.sleep(sleep_time)
        except KeyboardInterrupt:
            logger.info("\nMonitoring stopped by user.")
        except Exception as error:
            logger.error(f"\nMonitoring stopped by error: {error}")
        finally:
            self._cleanup_network_processes()
            if active_ifname:
                restart_interface(active_ifname)
            logger.info("Cleaned up all connections.")

    def create_profile(self):
        self.list_interfaces()
        hist_iface = HistoryManager("iface")
        hist_metric = HistoryManager("metric")
        hist_ssid = HistoryManager("ssid")
        
        ifname = hist_iface.input("Network Interface Name (e.g. wlan0, enp0s3): ")

        if not ifname: 
            raise ValueError("Interface name cannot be empty.")
    
        metric_val = hist_metric.input("Metric (default: 100): ")
        metric = int(metric_val) if metric_val else 100
        
        temp_profile = {"metric": metric}
        
        if is_wireless(ifname):
            ssid = hist_ssid.input("Network SSID: ")
            if not ssid: 
                raise ValueError("SSID cannot be empty.")
            
            psk = getpass.getpass("Network Password (8-63 chars): ")

            if not psk: 
                raise ValueError("Password cannot be empty.")
            
            temp_profile.update({"ssid": ssid, "psk": psk})
    
        valid_profile = validate_interface_profile_data(
            self.ctx.config_dir, ifname, temp_profile
        )

        self.ctx.profiles_manager.create_profile(ifname, valid_profile)

    def scan(self, ifname: str, output_filename: Optional[str] = None):
        logger.info("In development, see https://github.com/gusprojects008/wnlpy\n")
        logger.info(f"Scanning Wi-Fi networks on {ifname}...\n")

        if not check_interface_exists(ifname):
            logger.error(f"Interface {ifname} not found.")
            return

        try:
            set_interface_up(ifname)
            result = subprocess.run(
                ["iw", "dev", ifname, "scan"],
                capture_output=True, text=True, check=True
            )
        except FileNotFoundError:
            logger.error("'iw' command not found. Please install wireless tools.")
            return
        except subprocess.CalledProcessError as e:
            logger.error(f"Scan failed: {e}")
            return

        if not result.stdout.strip():
            logger.info("No networks found.")
            return

        def extract(pattern: str, text: str, default: str = "N/A") -> str:
            match = re.search(pattern, text)
            return match.group(1).strip() if match else default

        def security_type(block: str) -> str:
            if "WPA3" in block or "SAE" in block:
                return "WPA3"
            if "WPA2" in block or "RSN:" in block:
                return "WPA2"
            if "WPA:" in block:
                return "WPA"
            if "privacy" in block:
                return "WEP"
            return "OPEN"

        def wps_status(block: str) -> str:
            if "WPS:" not in block:
                return "Disabled"
            status  = "Enabled"
            state   = extract(r"Wi-Fi Protected Setup State:\s*\d+\s*\((\w+)\)", block, "")
            methods = extract(r"Config methods:\s*(.+)", block, "")
            locked  = "[LOCKED]" if "AP setup locked: 0x01" in block else ""
            details = f" ({state})" if state else ""
            details += f" - {methods}" if methods else ""
            return f"{status}{details} {locked}".strip()

        def encryption_modes(block: str) -> str:
            enc = []
            if "CCMP" in block:
                enc.append("AES")
            if "TKIP" in block:
                enc.append("TKIP")
            return ", ".join(enc) if enc else "None"

        def security_flags(block: str) -> str:
            flags = []
            if "WPA3" in block or "SAE" in block:
                flags.append("WPA3")
            if "Management frame protection: required" in block:
                flags.append("PMF-Required")
            elif "Management frame protection: capable" in block:
                flags.append("PMF-Capable")
            return ", ".join(flags) if flags else "None"

        def print_network(num: int, block: str):
            logger.info(
                f"┌─── NETWORK #{num} {'─' * 50}\n"
                f"│ SSID     : {extract(r'SSID: (.+)', block, 'Hidden')}\n"
                f"│ BSSID    : {extract(r'^([0-9a-f:]{17})', block)}\n"
                f"│ Signal   : {extract(r'signal: ([-0-9.]+) dBm', block)} dBm | "
                f"Channel: {extract(r'DS Parameter set: channel ([0-9]+)', block)} | "
                f"Freq: {extract(r'freq: ([0-9.]+)', block)} MHz\n"
                f"│ Security : {security_type(block)}\n"
                f"│ Encrypt  : {encryption_modes(block)}\n"
                f"│ Vendor   : {extract(r'Manufacturer: (.+)', block, 'Unknown')}\n"
                f"│ WPS      : {wps_status(block)}\n"
                f"│ Flags    : {security_flags(block)}\n"
                f"└{'─' * 60}"
            )

        blocks = result.stdout.strip().split("\nBSS ")[1:]
        if not blocks:
            logger.info("No networks found.")
            return

        output_path = Path(output_filename) if output_filename else Path("station-scan-result.txt")
        output_path.write_text(result.stdout)

        for i, block in enumerate(blocks, 1):
            print_network(i, block)

        logger.info(f"\nTotal networks found: {len(blocks)}")

    def list_interfaces(self) -> List[str]:
        try:
            interfaces = [
                iface.name for iface in Path("/sys/class/net").iterdir() if iface.is_dir()
            ]
            if not interfaces:
                logger.warning("No network interfaces found.")
                return []
            logger.info("Available interfaces:")
            for ifname in interfaces:
                logger.info(f" - {ifname}  {get_mac_address(ifname) or ''}")
            return interfaces
        except Exception as error:
            logger.error(f"Failed to list system interfaces: {error}")
            return []

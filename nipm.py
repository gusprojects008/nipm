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
from typing import Dict, List, Any, Tuple, Optional
import readline
import atexit

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
dependencies = ['wpa_supplicant', 'dhcpcd', 'iw', 'ip']
service_timeout = 30
process_timeout = 5

def check_root_privilegies():
    if os.getuid() != 0:
        error = f"This program requires administrator privileges! Run with sudo:\nsudo {sys.executable} {Path(__file__).resolve()} {' '.join(sys.argv[1:]) if len(sys.argv) > 1 else ''}"
        raise PermissionError(error)

def check_dependencies(dependencies):
    for dependency in dependencies:
        if not shutil.which(dependency):
            raise FileNotFoundError(f"{dependency} not found. Install it and try again...")

def new_file_path(base: str = None, ext: str = None, filename: str = None) -> Path:
    logger.info("Creating a new file path...")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    if not filename:
        if base and ext:
            return Path(f"{base}-{timestamp}{ext}")
        elif base:
            return Path(f"{base}-{timestamp}")
        else:
            return Path(f"{timestamp}")
    else:
        return Path(f"{timestamp}-{filename}")

def check_interface_exists(ifname: str) -> bool:
    logger.info(f"Checking if {ifname} exists...")
    return Path(f"/sys/class/net/{ifname}").exists()

def check_active_interface(ifname: str) -> bool:
    logger.info(f"Checking if {ifname} is active...")
    try:
       state_path = Path(f"/sys/class/net/{ifname}/operstate")
       return state_path.read_text().strip() == "up"
    except Exception:
       return False

def check_interface_ipv4(ifname: str) -> bool:
    logger.info(f"Checking the IPv4 configuration for {ifname} ...")
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
                iface = fields[0]
                dest = fields[1]
                gateway = fields[2]
                mask = fields[7]
                if iface == ifname and dest == "00000000" and mask == "00000000":
                    return True
    except Exception:
        pass
    return False

def interface_working(ifname: str) -> bool:
    logger.info(f"Checking if {ifname} is working ...")
    return all([
        check_interface_exists(ifname),
        check_active_interface(ifname),
        check_interface_ipv4(ifname),
        check_default_gateway(ifname)
    ])
    
def set_interface_down(ifname: str) -> bool:
    logger.info(f"Bringing interface {ifname} down...")
    try:
        subprocess.run(["ip", "link", "set", ifname, "down"], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info(f"Interface {ifname} is down.")
        return True
    except subprocess.CalledProcessError as error:
        logger.error(f"Failed to set interface {ifname} down: {error}")
        return False

def set_interface_up(ifname: str) -> bool:
    logger.info(f"Bringing interface {ifname} up...")
    try:
       subprocess.run(["ip", "link", "set", ifname, "up"], check=True, 
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
       logger.info(f"Interface {ifname} is up.")
       return True
    except subprocess.CalledProcessError as error:
       logger.error(f"Failed to set interface {ifname} up: {error}")
       return False

def restart_interface(ifname: str) -> bool:
    logger.info(f"Restarting {ifname} ...")
    try:
        return True if (set_interface_down(ifname) and set_interface_up(ifname)) else False
    except Exception as error:
        print(f"Error when trying to restart interface {ifname}")
        return False

def get_mac_address(ifname: str) -> str:
    try:
        path = Path(f"/sys/class/net/{ifname}/address")
        return path.read_text().strip()
    except Exception:
        logger.warning(f"Could not read MAC address for {ifname}")

def is_wireless(ifname: str) -> bool:
    logger.info(f"Checking if {ifname} is wireless...")
    try:
        return Path(f"/sys/class/net/{ifname}/wireless").exists()
    except Exception:
        return False

def _generate_hex_psk(ssid: str, psk: str) -> str:
    logger.info(f"Generating hexadecimal PSK for {ssid} ...")
    return hashlib.pbkdf2_hmac('sha1', psk.encode('utf-8'), ssid.encode('utf-8'), 4096, 32).hex()

def validate_interface_profile_data(CONFIG_DIR, ifname: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
    logger.info(f"Validating profile for {ifname}...")

    if not ifname or not check_interface_exists(ifname):
        logger.warning(f"Invalid or non-existent interface at startup: {ifname}")
        hwaddr = None
    else:
        hwaddr = get_mac_address(ifname)

    metric = profile_data.get("metric", 100)

    if not isinstance(metric, int) or metric <= 0:
        raise ValueError(f"Invalid metric for {ifname}: {metric}")

    is_wifi_config = ("ssid" in profile_data and profile_data["ssid"].strip()) or is_wireless(ifname)

    if is_wifi_config:
        ssid = profile_data.get("ssid", "").strip()
        if not ssid or len(ssid) > 32:
            raise ValueError(f"SSID for {ifname} must be between 1 and 32 characters.")

        psk = profile_data.get("psk", "").strip()
        if not (8 <= len(psk) <= 63):
            raise ValueError(f"PSK for {ifname} must be between 8 and 63 characters.")
        
        psk_hex = _generate_hex_psk(ssid, psk)

        wpa_supplicant_conf_path = CONFIG_DIR / f"wpa-supplicant-{ifname}.conf"
        dhcpcd_conf_path = CONFIG_DIR / f"dhcpcd-{ifname}.conf"

        return {
            "hwaddr": hwaddr,
            "type": "wireless",
            "metric": metric,
            "ssid": ssid,
            "psk": psk,
            "psk_hex": psk_hex,
            "wpa_supplicant_conf_path": str(wpa_supplicant_conf_path),
            "dhcpcd_conf_path": str(dhcpcd_conf_path),
        }
    else:
        dhcpcd_conf_path = CONFIG_DIR / f"dhcpcd-{ifname}.conf"
        return {
            "hwaddr": hwaddr,
            "type": "ethernet",
            "metric": metric,
            "dhcpcd_conf_path": str(dhcpcd_conf_path),
        }

def parse_config(CONFIG_DIR, config_file_path: Path) -> List[Tuple[str, Dict[str, Any]]]:
    logger.info(f"Parsing config file {config_file_path}...")

    if not config_file_path or not config_file_path.is_file():
        logger.error(f"Configuration file not found at {config_file_path}")
        sys.exit(1)
    try:
        with config_file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except Exception as error:
        logger.error(f"Error reading JSON config: {error}")
        sys.exit(1)

    profiles = []
    for ifname, profile_data in data.items():
         try:
             valid_profile = validate_interface_profile_data(CONFIG_DIR, ifname, profile_data)
             profiles.append((ifname, valid_profile))
         except Exception as error:
             logger.error(f"Unexpected error adding profile of {ifname} in profiles list:\n{error}")
             continue

    if not profiles:
       logger.error("No valid profiles found in configuration.")
       return []

    return profiles

class ProfilesManager:
    def __init__(self, CONFIG_DIR: Path, config_file_path: Path):
        self.config_dir = CONFIG_DIR
        self.config_file_path = config_file_path

    def create_profile(self, ifname: str, valid_profile: Dict[str, Any]) -> bool:
        logger.info(f"Attempting to create profile for {ifname}...")

        if valid_profile["type"] == "wireless":
            wpa_supplicant_conf_path = Path(valid_profile['wpa_supplicant_conf_path'])
            wpa_supplicant_conf = f"ctrl_interface=/var/run/wpa_supplicant\nnetwork={{\n    ssid=\"{valid_profile['ssid']}\"\n    psk={valid_profile['psk_hex']}\n}}"
            wpa_supplicant_conf_path.write_text(wpa_supplicant_conf.strip() + "\n")
            wpa_supplicant_conf_path.chmod(0o740)

        dhcpcd_conf_path = Path(valid_profile['dhcpcd_conf_path'])
        dhcpcd_conf = f"interface {ifname}\nmetric {valid_profile['metric']}"
        dhcpcd_conf_path.write_text(dhcpcd_conf.strip() + "\n")
        dhcpcd_conf_path.chmod(0o740)

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
            logger.info(f"\n\n{ifname} => {profile}\n")
                
    def remove_profile(self, ifname: str) -> bool:
        all_profiles = self._read_profiles()

        if ifname not in all_profiles:
            logger.error(f"Profile for {ifname} not found.")
            return False
        
        try:
            profile_to_remove = all_profiles[ifname]
            valid_profile = validate_interface_profile_data(self.config_dir, ifname, profile_to_remove)
            if valid_profile["type"] == "wireless":
                Path(profile_to_remove['wpa_supplicant_conf_path']).unlink(missing_ok=True)
            Path(valid_profile['dhcpcd_conf_path']).unlink(missing_ok=True)
            logger.info(f"Cleaned up config files for {ifname}.")

        except ValueError as error:
            logger.warning(f"Could not get associated file paths for {ifname}, but proceeding with removal from main config: {error}")
        except Exception as error:
            logger.error(f"An error occurred during file cleanup for {ifname}: {error}")
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
                    Path(profile_data['wpa_supplicant_conf_path']).unlink(missing_ok=True)
                Path(profile_data['dhcpcd_conf_path']).unlink(missing_ok=True)
                logger.info(f"Removed config files for {ifname}.")
            self.config_file_path.unlink()
            logger.info("All network profiles have been removed.")
            return True
        except SystemExit:
            logger.info("Failed to parse config file for cleanup. Doing Manual cleanup...")
            if self.config_dir.exists():
                shutil.rmtree(self.config_dir)
            return True
        except Exception as error:
            logger.error("Failed to parse config file for cleanup. Manual cleanup may be required.")
            return False

    def _read_profiles(self) -> Dict[str, Any]:
        if not self.config_file_path.exists():
            return {}
        try:
            with self.config_file_path.open("r", encoding="utf-8") as file:
                return json.load(file)
        except (json.JSONDecodeError, IOError) as error:
            logger.warning(f"Could not read {self.config_file_path}: {error}. A new file will be created.")
            return {}
        except Exception as error:
            logger.error(f"Could not read {self.config_file_path}: {error}.")
            raise

    def _write_profiles(self, data: Dict[str, Any]):
        try:
            with self.config_file_path.open("w", encoding="utf-8") as file:
                json.dump(data, file, indent=2, ensure_ascii=False)
            self.config_file_path.chmod(0o740)
        except Exception as error:
            logger.error(f"Failed to write to {self.config_file_path}: {error}.")
            return False

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
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
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
                proc.wait(timeout=process_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def stop_all(self):
        for ifname in list(self.processes):
            self.stop(ifname)

    def wait_for_connected(self, ifname: str) -> bool:
        return self._wait_for_wpa_event(ifname, "CTRL-EVENT-CONNECTED")
    
    def _wait_for_wpa_event(self, ifname: str, event: str) -> bool:
        logger.info(f"Waiting for wpa_supplicant {event} for {ifname} (timeout {service_timeout}s)")
        ctrl_path = f"/var/run/wpa_supplicant/{ifname}"
        local_path = f"/tmp/wpa_ctrl_{ifname}_{os.getpid()}"

        if os.path.exists(local_path):
            try: os.unlink(local_path)
            except: pass
    
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        
        try:
            start = time.time()
            while not os.path.exists(ctrl_path):
                if time.time() - start > service_timeout:
                    return False
                time.sleep(1)
        
            sock.bind(local_path)
            sock.connect(ctrl_path)
            logger.info("Sending ATTACH message to wpa_supplicant")
            sock.send(b"ATTACH")
            data = sock.recv(4096).decode('utf-8', errors='ignore')
            if "OK" not in data:
                logger.error("wpa_supplicant service is not working")
                return False
            logger.info("wpa_supplicant service working")
            sock.settimeout(service_timeout)

            while True:
               data = sock.recv(4096).decode('utf-8', errors='ignore')
               if event in data:
                   logger.info(f"wpa_suplicant response: {event}")
                   return True
        except socket.timeout as e:
            logger.error(f"Timeout to start wpa_supplicant service: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while starting the wpa_supplicant service: {e}")
            return False
        finally:
            sock.close()
            if os.path.exists(local_path):
                try: os.unlink(local_path)
                except: pass

class DHCPCDProcessManager:
    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}

    def start(self, ifname: str, config_path: str) -> bool:
        logger.info(f"Starting dhcpcd for {ifname}")
        self.stop(ifname)

        try:
            proc = subprocess.Popen(
                ["dhcpcd", "-n", ifname, "-f", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.processes[ifname] = proc

            start_time = time.time()

            while True:
                if check_interface_ipv4(ifname) and check_default_gateway(ifname):
                    logger.info(f"dhcpcd successfully configured {ifname}")
                    return True

                if time.time() - start_time > service_timeout:
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
                proc.wait(timeout=process_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def stop_all(self):
        for ifname in list(self.processes):
            self.stop(ifname)

def cleanup_network_processes(real_user: str, wpa_manager, dhcpcd_manager):
    logger.info("Cleaning up network processes")

    dhcpcd_manager.stop_all()
    wpa_manager.stop_all()

    try:
        subprocess.run(
            ["pkill", "-u", real_user, "wpa_supplicant"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["pkill", "-u", real_user, "dhcpcd"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception as e:
        logger.warning(f"Process cleanup failed: {e}")

def start_wpa_and_wait(manager: WPAProcessManager, ifname: str, profile_data: dict) -> bool:
    if not manager.start(ifname, profile_data["wpa_supplicant_conf_path"]):
        return False
    return manager.wait_for_connected(ifname)

def start_dhcpcd_and_wait(manager: DHCPCDProcessManager, ifname: str, profile_data: dict) -> bool:
    return manager.start(ifname, profile_data["dhcpcd_conf_path"])

def connection(profile: Tuple[str, Dict[str, Any]], wpa_manager, dhcpcd_manager) -> bool:
    ifname, p = profile
    is_wireless = p["type"] == "wireless"
    success = (
        start_wpa_and_wait(wpa_manager, ifname, p)
        and start_dhcpcd_and_wait(dhcpcd_manager, ifname, p)
    ) if is_wireless else start_dhcpcd_and_wait(dhcpcd_manager, ifname, p)
    logger.info(f"Connection successful on {ifname}!") if success else logger.error(f"Connection failed on {ifname}.")
    return success

def start(profiles: List[Tuple[str, Dict[str, Any]]], background: bool, sleep_time: int, real_user, wpa_manager, dhcpcd_manager):
    if not profiles:
        logger.error("No valid profiles found.")
        return

    profiles.sort(key=lambda p: p[1]["metric"])
    cleanup_network_processes(real_user, wpa_manager, dhcpcd_manager)
    ifname, profile_data = profiles[0]

    if not background:
       if connection((ifname, profile_data), wpa_manager, dhcpcd_manager):
          logger.info("Connection established. The script will now exit.")
          return
       logger.error("Could not establish a connection using any available profile.")
       return

    logger.info("Monitoring mode activated (Ctrl+C to exit)")

    active_ifname = None

    try:
        while True:
            best_candidate_ifname = next((ifname for ifname, _ in profiles if check_interface_exists(ifname)), None)
            
            if best_candidate_ifname != active_ifname:
                if active_ifname:
                    logger.info(f"Switching from {active_ifname} to a better interface...")
                    wpa_manager.stop(active_ifname)
                    dhcpcd_manager.stop(active_ifname)
                
                if best_candidate_ifname:
                    logger.info(f"New target interface is {best_candidate_ifname}. Attempting to connect.")
                    current_profile = next(p for i, p in profiles if i == best_candidate_ifname)
                    
                    if connection((best_candidate_ifname, current_profile), wpa_manager, dhcpcd_manager):
                        active_ifname = best_candidate_ifname
                    else:
                        logger.error(f"Failed to connect to {best_candidate_ifname}. Will retry in {sleep_time}s.")
                        active_ifname = None
                else:
                    active_ifname = None

            elif active_ifname:
                if not interface_working(active_ifname):
                    logger.warning(f"Connection on {active_ifname} seems down, reconnecting...")
                    current_profile = next(p for i, p in profiles if i == active_ifname)
                    if not connection((active_ifname, current_profile), wpa_manager, dhcpcd_manager):
                        active_ifname = None

            time.sleep(sleep_time)
    except KeyboardInterrupt:
       logger.info("\nMonitoring stopped by user.")
    except Exception as error:
       logger.error(f"\nMonitoring stopped by Error: {error}")
    finally:
       cleanup_network_processes(real_user, wpa_manager, dhcpcd_manager)
       if active_ifname:
           restart_interface(active_ifname)
       logger.info("Cleaned up all connections.")

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
            capture_output=True,
            text=True,
            check=True
        )
    except FileNotFoundError:
        logger.error("'iw' command not found. Please install wireless tools.")
        return
    except subprocess.CalledProcessError as e:
        logger.error(f"Scan failed: {e}")
        return

    if not result.stdout.strip():
        print("No networks found.")
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
        status = "Enabled"
        state = extract(r"Wi-Fi Protected Setup State:\s*\d+\s*\((\w+)\)", block, "")
        methods = extract(r"Config methods:\s*(.+)", block, "")
        locked = "[LOCKED]" if "AP setup locked: 0x01" in block else ""
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
        print(
            f"┌─── NETWORK #{num} {'─' * 50}\n"
            f"│ SSID: {extract(r'SSID:\s*(.+)', block, 'Hidden')}\n"
            f"│ BSSID: {extract(r'^([0-9a-f:]{17})', block)}\n"
            f"│ Signal: {extract(r'signal:\s*([-\d.]+)\s*dBm', block)} dBm | "
            f"Channel: {extract(r'DS Parameter set:\s*channel\s*(\d+)', block)} | "
            f"Freq: {extract(r'freq:\s*([\d.]+)', block)} MHz\n"
            f"│ Security: {security_type(block)}\n"
            f"│ Encryption: {encryption_modes(block)}\n"
            f"│ Vendor: {extract(r'Manufacturer:\s*(.+)', block, 'Unknown')}\n"
            f"│ WPS: {wps_status(block)}\n"
            f"│ Security Flags: {security_flags(block)}\n"
            f"└{'─' * 60}"
        )

    blocks = result.stdout.strip().split("\nBSS ")[1:]
    if not blocks:
        print("No networks found.")
        return

    output_path = new_file_path("station-scan-result", ".txt", filename=output_filename)
    output_path.write_text(result.stdout)
    for i, block in enumerate(blocks, 1):
        print_network(i, block)

    print(f"\nTotal networks found: {len(blocks)}")

def list_interfaces() -> List[str]:
    try:
        interfaces = [iface.name for iface in Path("/sys/class/net").iterdir() if iface.is_dir()]
        if not interfaces:
            logger.warning("No network interfaces found.")
        if interfaces:
            print("Available interfaces:")
            for ifname in interfaces:
                print(f" - {ifname} {get_mac_address(ifname)}")
    except Exception as error:
        logger.error(f"Failed to list system interfaces: {error}")
        return []

class HistoryManager:
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
        readline.set_completer(self.interface_completer)
        readline.parse_and_bind("tab: complete")
        atexit.register(readline.write_history_file, self.histfile)
        self.readline_available = True
    
    def input(self, prompt_text: str) -> str:
        return input(prompt_text).strip()

    def interface_completer(self, text, state):
        interfaces = [iface.name for iface in Path("/sys/class/net").iterdir() if iface.is_dir()]
        matches = [i for i in interfaces if i.startswith(text)]
        return matches[state] if state < len(matches) else None

def main():
    check_root_privilegies()
    check_dependencies(dependencies)
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

    parser = argparse.ArgumentParser(description="A Python script to manage network connections.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    create_profiles_parser = subparsers.add_parser("create-profile", help="Create or update a network profile.")

    list_profiles_parser = subparsers.add_parser('list-profiles', help='List all saved network profiles.')

    remove_profiles_parser = subparsers.add_parser('remove-profile', help='Remove a specific network profile.')
    remove_profiles_parser.add_argument('ifname', type=str, help='The interface name to remove.')

    remove_all_profiles_parser = subparsers.add_parser('remove-profiles', help='Remove all network profiles.')

    start_parser = subparsers.add_parser("start", help="Connect to a network.")
    start_parser.add_argument("-b", "--background", action="store_true", help="Run in monitoring mode with failover and failback.")
    start_parser.add_argument("-s", "--sleep", type=int, default=8, help="Time to next interface check (seconds, default = 6)")

    scan_parser = subparsers.add_parser("scan", help="Scan for wireless networks.")
    scan_parser.add_argument("ifname", type=str, help="The wireless interface to use for scanning.")
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Output filename to scan results.")

    list_interfaces_parser = subparsers.add_parser("list-interfaces", help="List Network Interfaces.")

    args = parser.parse_args()

    if args.command == "start":
        profiles = parse_config(CONFIG_DIR, config_file_path)
        start(profiles, args.background, args.sleep, real_user, wpa_manager, dhcpcd_manager)
    elif args.command == "scan":
        scan(args.ifname, args.output)
    elif args.command == "create-profile":
        list_interfaces()

        hist_iface = HistoryManager("iface")
        hist_metric = HistoryManager("metric")
        hist_ssid = HistoryManager("ssid")
        
        ifname = hist_iface.input("Network Interface Name (e.g. wlan0, enp0s3): ")
        if not ifname: 
            raise ValueError("Interface name cannot be empty.")
        
        metric_val = hist_metric.input("Metric (default: 100): ")
        metric = int(metric_val) if metric_val else 100
        
        if is_wireless(ifname):
            ssid = hist_ssid.input("Network SSID: ")
            if not ssid: 
                raise ValueError("SSID cannot be empty.")
            
            psk = getpass.getpass("Network Password (8-63 chars): ")
            if not psk: 
                raise ValueError("Password cannot be empty.")
            
            temp_profile = {"metric": metric, "ssid": ssid, "psk": psk}
            valid_profile = validate_interface_profile_data(CONFIG_DIR, ifname, temp_profile)
            profiles_manager.create_profile(ifname, valid_profile)
        else:
            temp_profile = {"metric": metric}
            valid_profile = validate_interface_profile_data(CONFIG_DIR, ifname, temp_profile)
            profiles_manager.create_profile(ifname, valid_profile)
    elif args.command == 'list-profiles':
        profiles_manager.list_profiles()
    elif args.command == 'remove-profile':
        profiles_manager.remove_profile(args.ifname)
    elif args.command == 'remove-profiles':
        profiles_manager.remove_all_profiles()
    elif args.command == 'list-interfaces':
        list_interfaces()
    else:
        parser.print_help()
    
if __name__ == "__main__":
   main()

# Network Interface Profile Manager (NIPM)

NIPM (Network Interface Profile Manager) is a CLI tool for Linux that allows you to manage network interfaces and their connections (Wi-Fi or Ethernet) through profiles.
It supports the creation, maintenance, and automatic switching between network profiles in a dynamic and secure way, without relying on a resident daemon, providing greater control and flexibility over interfaces.
A personal script developed with minimalist environments in mind, and for users who don't want to manually configure network service configuration files, such as: wpa_supplicant and dhcpcd.
And don't want daemons that forcibly control network interfaces that regularly change mode (managed -> monitor).
Low CPU and memory usage.

> [!IMPORTANT]
> Make sure no other network daemons or services are running (e.g., iwd or NetworkManager) before executing the program.

---

## Overview

**NIPM** works directly with standard Linux networking tools:

* dhcpcd
* wpa_supplicant
* iw
* ip

It automates the creation and updating of these configuration files, ensuring compliance with official syntax and reducing manual errors.

NIPM prioritizes network interfaces based on user-defined metrics and automatically reconnects in case of failure, ensuring a reliable connection experience.

---

## Main Features

* **Profile creation and updates**: with the `create-profile` command, you can define SSID, password (PSK), and priority (metric) for each interface. The lower the interface metric, the higher its priority.
* **Centralized management**: keeps all configurations organized in the user profile directory (`~/.config/nipm`), which is only accessible with root permissions for security reasons.
* **Multiple interface support**: dynamically switches between active interfaces, always maintaining the highest-priority connection.
* **Continuous monitoring**: background mode (`-b`) checks interface availability and automatically reconnects in case of failure. You can also define the interval for each check using the (`-s`) option followed by the value in seconds.
* **Easy profile removal**: remove individual profiles or all profiles at once.
* **Compatibility**: uses standard Linux tools (`dhcpcd`, `wpa_supplicant`) without complex external dependencies.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/gusprojects008/nipm.git
cd nipm
```

Make sure you have Python 3.13+, `dhcpcd`, and `wpa_supplicant` installed.

---

## Usage

```bash
# Show help
sudo python3 nipm.py --help

# Create or update a network profile
sudo python3 nipm.py create-profile

# List all saved profiles
sudo python3 nipm.py list-profiles

# Remove a specific profile
sudo python3 nipm.py remove-profile <interface>

# Remove all profiles
sudo python3 nipm.py remove-profiles

# Start connection with interface monitoring (background)
sudo python3 nipm.py start -b

# Start connection without monitoring (single-run mode)
sudo python3 nipm.py start
```

> During profile creation, you will be prompted for:
>
> * Interface name (e.g., `wlan0`)
> * Network SSID
> * Network password (PSK)
> * Metric (interface priority, default = 100)

---

## Configuration Structure

* User configuration directory: `~/.config/nipm/`
* Main profile file: `nipm-config.json`
* Generated configuration files for each interface:

  * `wpa-supplicant-<ifname>.conf`
  * `dhcpcd-<ifname>.conf`

All files and directories are created with restricted permissions (`740`) for enhanced security.

---

## Requirements

* Python 3.13+
* `dhcpcd`
* `wpa_supplicant`
* Administrator privileges (sudo)

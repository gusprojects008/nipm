#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import argcomplete
from pathlib import Path
from logging import getLogger
from core.common.cli import interfaces_completer
from core.bootstrap import init

config = {
    "module_dependencies": ["rich", "argcomplete"],
    "system_dependencies": ["wpa_supplicant", "dhcpcd", "iw", "ip"],
    "args": None
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Interface Profile Manager (NIPM) - Manage network connections easily.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging and save logs to file"
    )

    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output fullpath to save debug logs to file"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    subparsers.add_parser("create-profile", help="Create or update a network profile.")

    remove_parser = subparsers.add_parser("remove-profile", help="Remove a specific network profile.")
    remove_parser.add_argument(
        "--ifname", required=True, type=str, help="Network interface name"
    ).completer = interfaces_completer

    subparsers.add_parser("remove-profiles", help="Remove all saved network profiles.")

    subparsers.add_parser("list-profiles", help="List all saved network profiles.")

    scan_parser = subparsers.add_parser("scan", help="Scan for wireless networks.")
    scan_parser.add_argument(
        "--ifname", required=True, type=str, help="Network interface name"
    ).completer = interfaces_completer
    scan_parser.add_argument(
        "--output", "-o", type=str, default=None, help="Output filename to save scan results."
    )

    start_parser = subparsers.add_parser("start", help="Connect to a network using saved profiles.")
    start_parser.add_argument(
        "-b", "--background",
        action="store_true",
        help="Run in monitoring mode with failover and failback."
    )
    start_parser.add_argument(
        "-s", "--sleep",
        type=int,
        default=8,
        help="Time between interface checks in seconds (default: 8)"
    )

    subparsers.add_parser("list-interfaces", help="List available network interfaces.")

    argcomplete.autocomplete(parser)
    return parser, parser.parse_args()


def main():
    parser, args = parse_args()
    config["args"] = args
    result = init(config)
    operations = result.operations
    logger = getLogger(__name__)
    operations.dispatch(args)


if __name__ == "__main__":
    main()

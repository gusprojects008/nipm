#!/bin/bash

set -e

echo ">>> Checking required system packages..."

for pkg in python iw dhcpcd wpa_supplicant pkill ip; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        echo "Error: '$pkg' is not installed. Please install it before running this setup."
        exit 1
    fi

done

echo ">>> All required packages are present..."

echo ">>> Setup completed successfully!"

echo ">>>> If needed, you can check this script (setup.sh) for the manual commands to perform each step."

echo ">>>> RUN: sudo python nipm.py --help"

#!/usr/bin/env bash

RESET='\033[0m'

BOLD='\033[1m'
DIM='\033[2m'
UNDERLINE='\033[4m'
REVERSE='\033[7m'

RED='\033[31m'
YELLOW='\033[33m'
GREEN='\033[32m'
BLUE='\033[34m'

set -euo pipefail

PROJECT_NAME="nipm"
PROGRAM_EXTENSION=".py"
VENV_DIR=".venv"
VENV_PYTHON="$VENV_DIR/bin/python"

print_step() {
    echo
    echo "==> $1"
}

print_ok() {
    echo "✔ $1"
}

print_error() {
    echo "✖ $1"
    exit 1
}

print_header() {
    echo
    echo -e "${REVERSE} $1 ${RESET}"
    echo
}

print_section() {
    echo -e "${BOLD}$1:${RESET}"
}

print_info() {
    echo -e "  ${BLUE}$1${RESET}"
}

print_success() {
    echo -e "  ${GREEN}$1${RESET}"
}

print_warning() {
    echo -e "  ${YELLOW}$1${RESET}"
}

print_error() {
    echo -e "  ${RED}$1${RESET}"
}

print_command() {
    echo -e "  ${GREEN}$1${RESET}"
}

print_comment() {
    echo -e "  ${DIM}# $1${RESET}"
}

print_separator() {
   echo -e "$RED========================================$RESET"
}

print_step "Checking required system dependencies..."

for pkg in python iw dhcpcd wpa_supplicant pkill ip; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        print_error "Missing dependency: $pkg"
    fi
done

print_ok "All required system dependencies are available."

print_step "Setting up virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    print_ok "Virtual environment created."
else
    print_ok "Virtual environment already exists."
fi

source "$VENV_DIR/bin/activate"

print_step "Upgrading pip..."
python -m pip install --upgrade pip >/dev/null

print_step "Installing dependencies..."

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_ok "Dependencies installed."
else
    print_error "requirements.txt not found."
fi

print_step "Setup completed successfully!"

print_header "$RED IMPORTANT"

print_section "Interpreter"
print_info "$VENV_PYTHON"
echo

print_section "Usage"
print_comment "activate virtual environment"
print_command "source \"$VENV_DIR/bin/activate\""
echo
print_comment "run the program"
print_command "sudo \"$VENV_PYTHON\" \"$PROJECT_NAME.py\" --help"

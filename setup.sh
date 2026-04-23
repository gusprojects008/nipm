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
CYAN='\033[36m'

set -euo pipefail

PROJECT_NAME="nipm"
PROGRAM_EXTENSION=".py"
WRAPPER_NAME=$PROJECT_NAME$PROGRAM_EXTENSION
VENV_DIR=".venv"
VENV_PYTHON="$VENV_DIR/bin/python"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$PROJECT_NAME$PROGRAM_EXTENSION"
VENV_ARGCOMPLETE="$SCRIPT_DIR/$VENV_DIR/bin/register-python-argcomplete"

CURRENT_SHELL=$(basename "$SHELL")
case "$CURRENT_SHELL" in
    bash)
        RC_FILE="$HOME/.bashrc"
        ;;
    zsh)
        RC_FILE="$HOME/.zshrc"
        ;;
    *)
        RC_FILE=""
        ;;
esac

AUTOCOMPLETE_LINE="eval \"\$($VENV_ARGCOMPLETE $WRAPPER_NAME)\""

SYSTEM_DEPENDENCIES=("python3" "iw" "dhcpcd" "wpa_supplicant" "pkill" "ip")

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

print_error_msg() {
    echo -e "  ${RED}$1${RESET}"
}

print_command() {
    echo -e "  ${GREEN}$1${RESET}"
}

print_comment() {
    echo -e "  ${DIM}# $1${RESET}"
}

print_separator_smooth() {
    local cols
    cols=$(tput cols 2>/dev/null || echo 80)
    printf "%*s\n" "$cols" "" | tr ' ' '─'
}

print_separator_equals() {
    local cols
    cols=$(tput cols 2>/dev/null || echo 80)
    printf "%*s\n" "$cols" "" | tr ' ' '='
}

print_step "Checking required system dependencies..."

for pkg in "${SYSTEM_DEPENDENCIES[@]}"; do
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
python -m pip install --upgrade pip >/dev/null 2>&1

print_step "Installing dependencies..."

if ! pip install --no-cache-dir -r requirements.txt --no-input; then
    print_error "Failed to install dependencies"
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
print_command "\"$VENV_PYTHON\" \"$SCRIPT_PATH\" --help"
echo

print_header "$CYAN OPTIONAL: CREATE WRAPPER + AUTOCOMPLETE"

read -p "Do you want to make '$WRAPPER_NAME' a system command with autocomplete? (requires sudo) (y/n) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ ! -f /usr/share/bash-completion/bash_completion ]; then
        print_warning "bash-completion not found (optional)"
    fi

    if [ ! -f "$VENV_ARGCOMPLETE" ]; then
        print_error_msg "argcomplete not found in venv."
        print_command "Run: source \"$VENV_DIR/bin/activate\" && pip install argcomplete"
        exit 1
    fi

    print_step "Creating wrapper at /usr/local/bin/$WRAPPER_NAME..."

    WRAPPER_CONTENT="#!/bin/bash
exec \"$SCRIPT_DIR/$VENV_PYTHON\" \"$SCRIPT_PATH\" \"\$@\""

    if echo "$WRAPPER_CONTENT" | sudo tee /usr/local/bin/$WRAPPER_NAME > /dev/null; then
        sudo chmod +x /usr/local/bin/$WRAPPER_NAME
        print_ok "Wrapper created at /usr/local/bin/$WRAPPER_NAME"
    else
        print_error_msg "Failed to create wrapper. Try manually:"
        print_command "echo '$WRAPPER_CONTENT' | sudo tee /usr/local/bin/$WRAPPER_NAME && sudo chmod +x /usr/local/bin/$WRAPPER_NAME"
        exit 1
    fi

    print_step "Configuring autocomplete..."

    if [ -z "$RC_FILE" ]; then
        print_warning "Shell '$CURRENT_SHELL' not supported for automation."
        print_info "Manually add the following to your shell configuration file:"
        print_command "$AUTOCOMPLETE_LINE"
    else
        if grep -q "# $WRAPPER_NAME autocomplete" "$RC_FILE"; then
            print_warning "Autocomplete already configured in $RC_FILE"
        else
            {
                echo ""
                echo "# $WRAPPER_NAME autocomplete"
                if [[ "$CURRENT_SHELL" == "zsh" ]]; then
                    echo "autoload -U bashcompinit && bashcompinit"
                fi
                echo "$AUTOCOMPLETE_LINE"
            } >> "$RC_FILE"
            print_ok "Autocomplete added to $RC_FILE"
        fi
        print_header "$RED IMPORTANT"
        print_section "$RED To activate"
        print_command "source $RC_FILE"
        echo
    fi

    print_section "Usage"
    print_command "$WRAPPER_NAME --help"
    echo

else
    print_info "Skipped. You can run the script directly:"
    print_command "\"$SCRIPT_DIR/$VENV_PYTHON\" \"$SCRIPT_PATH\" --help"
fi

print_ok "Setup complete! Happy networking!"

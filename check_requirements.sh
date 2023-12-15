#!/bin/bash

# Function to install package using apt-get (for Ubuntu)
install_with_apt() {
    echo "Installing required package : $1"
    echo "This requires root permission :"
    echo "Installing $1..."
    sudo apt-get install -y $1
}

# Function to install package using brew (for macOS)
install_with_brew() {
    echo "Installing $1..."
    brew install $1
}

# Check OS and set package manager
OS=$(uname -s)
PKG_MANAGER=""

case $OS in
    "Linux") PKG_MANAGER="apt-get";;
    "Darwin") PKG_MANAGER="brew";;
    *)
        echo "Unsupported OS. Exiting."
        exit 1
        ;;
esac

# Check if Homebrew is installed on macOS
if [ "$OS" = "Darwin" ] && ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not installed. Please install Homebrew."
    echo "https://brew.sh/"
    echo "Exiting..."
    exit 1
fi

# Check and install pkg-config
if ! command -v pkg-config >/dev/null 2>&1; then
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        install_with_apt pkg-config
    else
        install_with_brew pkg-config
    fi
fi

# Check and install openssl
if ! command -v openssl >/dev/null 2>&1; then
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        install_with_apt openssl
    else
        install_with_brew openssl
    fi
fi

# Check and install gnupg
if ! command -v gpg >/dev/null 2>&1; then
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        install_with_apt gnupg
    else
        install_with_brew gnupg
    fi
fi

echo "All requirements are satisfied. Compiling.."
exit 0


#!/bin/bash

# Nimplant Build Script
# Builds the Nim-based implant for multiple targets

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NIMPLANT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${NIMPLANT_DIR}/build"
MAIN_FILE="${NIMPLANT_DIR}/main.nim"

# Create build directory
mkdir -p "${BUILD_DIR}"

echo -e "${GREEN}[+] Nimplant Build System${NC}"
echo -e "${GREEN}[+] Build directory: ${BUILD_DIR}${NC}"
echo ""

# Function to build for a specific target
build_target() {
    local target=$1
    local output_name=$2
    local extra_flags=$3

    echo -e "${YELLOW}[*] Building for ${target}...${NC}"

    if [ "$target" = "windows" ]; then
        nim c \
            --cpu:amd64 \
            --os:windows \
            --define:mingw \
            --define:release \
            --opt:speed \
            --deadCodeElim:on \
            --passL:"-static" \
            --app:console \
            --out:"${BUILD_DIR}/${output_name}.exe" \
            ${extra_flags} \
            "${MAIN_FILE}"
    elif [ "$target" = "linux" ]; then
        nim c \
            --cpu:amd64 \
            --os:linux \
            --define:release \
            --opt:speed \
            --deadCodeElim:on \
            --passL:"-static" \
            --out:"${BUILD_DIR}/${output_name}" \
            ${extra_flags} \
            "${MAIN_FILE}"
    elif [ "$target" = "macos" ]; then
        nim c \
            --cpu:amd64 \
            --os:macosx \
            --define:release \
            --opt:speed \
            --deadCodeElim:on \
            --out:"${BUILD_DIR}/${output_name}" \
            ${extra_flags} \
            "${MAIN_FILE}"
    else
        echo -e "${RED}[-] Unknown target: ${target}${NC}"
        return 1
    fi

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Successfully built ${output_name}${NC}"
        if [ -f "${BUILD_DIR}/${output_name}" ] || [ -f "${BUILD_DIR}/${output_name}.exe" ]; then
            local size=$(du -h "${BUILD_DIR}/${output_name}"* 2>/dev/null | cut -f1 | head -1)
            echo -e "${GREEN}[+] Binary size: ${size}${NC}"
        fi
    else
        echo -e "${RED}[-] Build failed for ${target}${NC}"
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [target] [options]"
    echo ""
    echo "Targets:"
    echo "  all       Build for all supported platforms"
    echo "  windows   Build for Windows x64"
    echo "  linux     Build for Linux x64"
    echo "  macos     Build for macOS x64"
    echo "  clean     Clean build directory"
    echo ""
    echo "Options:"
    echo "  --debug   Build with debug symbols"
    echo "  --help    Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./build.sh windows"
    echo "  ./build.sh all"
    echo "  ./build.sh linux --debug"
}

# Parse command line arguments
TARGET=""
DEBUG_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        windows|linux|macos|all|clean)
            TARGET="$1"
            shift
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}[-] Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Set debug flags if needed
DEBUG_FLAGS=""
if [ "$DEBUG_MODE" = true ]; then
    DEBUG_FLAGS="--define:debug --stackTrace:on --lineTrace:on"
    echo -e "${YELLOW}[*] Debug mode enabled${NC}"
fi

# Check if Nim is installed
if ! command -v nim &> /dev/null; then
    echo -e "${RED}[-] Nim compiler not found. Please install Nim first.${NC}"
    exit 1
fi

# Check if main.nim exists
if [ ! -f "$MAIN_FILE" ]; then
    echo -e "${RED}[-] Main file not found: $MAIN_FILE${NC}"
    exit 1
fi

# Clean build directory if requested
if [ "$TARGET" = "clean" ]; then
    echo -e "${YELLOW}[*] Cleaning build directory...${NC}"
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
    echo -e "${GREEN}[+] Build directory cleaned${NC}"
    exit 0
fi

# Set default target if none specified
if [ -z "$TARGET" ]; then
    echo -e "${YELLOW}[*] No target specified, building for current platform...${NC}"
    case "$OSTYPE" in
        linux*)   TARGET="linux" ;;
        darwin*)  TARGET="macos" ;;
        msys*|mingw*|cygwin*) TARGET="windows" ;;
        *)
            echo -e "${RED}[-] Unable to detect platform. Please specify a target.${NC}"
            show_usage
            exit 1
            ;;
    esac
fi

# Build targets
case "$TARGET" in
    all)
        echo -e "${YELLOW}[*] Building for all platforms...${NC}"
        echo ""

        build_target "windows" "nimplant_windows_x64" "$DEBUG_FLAGS" || true
        echo ""

        build_target "linux" "nimplant_linux_x64" "$DEBUG_FLAGS" || true
        echo ""

        build_target "macos" "nimplant_macos_x64" "$DEBUG_FLAGS" || true
        echo ""

        echo -e "${GREEN}[+] Build complete! Check the ${BUILD_DIR} directory.${NC}"
        ;;

    windows)
        build_target "windows" "nimplant_windows_x64" "$DEBUG_FLAGS"
        ;;

    linux)
        build_target "linux" "nimplant_linux_x64" "$DEBUG_FLAGS"
        ;;

    macos)
        build_target "macos" "nimplant_macos_x64" "$DEBUG_FLAGS"
        ;;

    *)
        echo -e "${RED}[-] Invalid target: $TARGET${NC}"
        show_usage
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}[+] Build process completed!${NC}"

# Show build artifacts
if [ -d "$BUILD_DIR" ] && [ "$(ls -A $BUILD_DIR 2>/dev/null)" ]; then
    echo ""
    echo -e "${GREEN}[+] Build artifacts:${NC}"
    ls -lah "${BUILD_DIR}"/
fi

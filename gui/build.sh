#!/bin/bash

# SCYTHE GUI Build Script
# Wrapper around Makefile for easy command-line usage
# Supports cross-platform development and production builds

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the correct directory
if [ ! -f "Makefile" ] || [ ! -f "package.json" ]; then
    print_error "Please run this script from the gui directory (where Makefile and package.json are located)"
    exit 1
fi

# Check if make is available
if ! command -v make &> /dev/null; then
    print_error "make is not installed. Please install GNU make first."
    exit 1
fi

# Function to show usage
show_usage() {
    echo "SCYTHE GUI Build Script"
    echo "======================="
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup          Setup development environment"
    echo "  dev            Start development server"
    echo "  build          Build for production"
    echo "  test           Run all tests"
    echo "  clean          Clean build artifacts"
    echo "  info           Show project information"
    echo "  help           Show this help message"
    echo ""
    echo "Advanced commands:"
    echo "  build-dev      Build for development"
    echo "  build-release  Build release version"
    echo "  build-linux    Build for Linux"
    echo "  build-windows  Build for Windows"
    echo "  build-macos    Build for macOS"
    echo "  lint           Run linting"
    echo "  format         Format code"
    echo "  docs           Generate documentation"
    echo ""
    echo "For more options, use 'make help'"
}

# Parse command line arguments
COMMAND="$1"

case "${COMMAND:-help}" in
    "setup")
        print_status "Setting up development environment..."
        make setup
        ;;
    "dev")
        print_status "Starting development server..."
        make dev
        ;;
    "build")
        print_status "Building for production..."
        make build
        ;;
    "build-dev")
        print_status "Building for development..."
        make build-dev
        ;;
    "build-release")
        print_status "Building release version..."
        make build-release
        ;;
    "build-linux")
        print_status "Building for Linux..."
        make build-linux
        ;;
    "build-windows")
        print_status "Building for Windows..."
        make build-windows
        ;;
    "build-macos")
        print_status "Building for macOS..."
        make build-macos
        ;;
    "test")
        print_status "Running tests..."
        make test
        ;;
    "lint")
        print_status "Running linting..."
        make lint
        ;;
    "format")
        print_status "Formatting code..."
        make format
        ;;
    "clean")
        print_status "Cleaning build artifacts..."
        make clean
        ;;
    "docs")
        print_status "Generating documentation..."
        make docs
        ;;
    "info")
        make info
        ;;
    "check")
        print_status "Running all checks..."
        make check
        ;;
    "doctor")
        print_status "Running diagnostics..."
        make doctor
        ;;
    "help"|"-h"|"--help"|"")
        show_usage
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        echo ""
        show_usage
        exit 1
        ;;
esac

print_success "Command completed successfully!"

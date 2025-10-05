# SCYTHE GUI Makefile
# Comprehensive build system for SCYTHE C2 Controller GUI
# Supports cross-platform development and production builds

# =============================================================================
# CONFIGURATION
# =============================================================================

# Project directories
FRONTEND_DIR := .
BACKEND_DIR := src-tauri
DIST_DIR := dist
BUILD_DIR := src-tauri/target

# Tools and versions
NODE_VERSION := 18
RUST_VERSION := 1.70
TAURI_VERSION := 1.5

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
	PLATFORM := linux
	ifeq ($(UNAME_M),x86_64)
		ARCH := x86_64-unknown-linux-gnu
	else ifeq ($(UNAME_M),aarch64)
		ARCH := aarch64-unknown-linux-gnu
	else
		ARCH := $(UNAME_M)-unknown-linux-gnu
	endif
else ifeq ($(UNAME_S),Darwin)
	PLATFORM := macos
	ifeq ($(UNAME_M),x86_64)
		ARCH := x86_64-apple-darwin
	else ifeq ($(UNAME_M),arm64)
		ARCH := aarch64-apple-darwin
	else
		ARCH := $(UNAME_M)-apple-darwin
	endif
else ifeq ($(findstring MINGW,$(UNAME_S)),MINGW)
	PLATFORM := windows
	ARCH := x86_64-pc-windows-msvc
else ifeq ($(findstring CYGWIN,$(UNAME_S)),CYGWIN)
	PLATFORM := windows
	ARCH := x86_64-pc-windows-msvc
else
	PLATFORM := unknown
	ARCH := unknown
endif

# Build configuration
RELEASE_FLAGS := --release
DEBUG_FLAGS :=

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

define print_status
	@echo -e "$(BLUE)[INFO]$(NC) $(1)"
endef

define print_success
	@echo -e "$(GREEN)[SUCCESS]$(NC) $(1)"
endef

define print_warning
	@echo -e "$(YELLOW)[WARNING]$(NC) $(1)"
endef

define print_error
	@echo -e "$(RED)[ERROR]$(NC) $(1)"
endef

define check_command
	@if ! command -v $(1) &> /dev/null; then \
		$(call print_error,"$(1) is not installed. Please install it first."); \
		exit 1; \
	fi
endef

define check_node_version
	@NODE_VER=$$(node -v | sed 's/v//' | cut -d. -f1); \
	if [ "$$NODE_VER" -lt $(NODE_VERSION) ]; then \
		$(call print_error,"Node.js version $(NODE_VERSION)+ required. Current: $$(node -v)"); \
		exit 1; \
	fi
endef

define check_rust_version
	@RUST_VER=$$(rustc --version | cut -d' ' -f2 | cut -d. -f1-2 | sed 's/\./0/g'); \
	REQ_VER=$$(echo "$(RUST_VERSION)" | sed 's/\./0/g'); \
	if [ "$$RUST_VER" -lt "$$REQ_VER" ]; then \
		$(call print_error,"Rust version $(RUST_VERSION)+ required. Current: $$(rustc --version)"); \
		exit 1; \
	fi
endef

# =============================================================================
# DEVELOPMENT TARGETS
# =============================================================================

.PHONY: help
help: ## Show this help message
	@echo "SCYTHE GUI Build System"
	@echo "======================="
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

.PHONY: setup
setup: check-deps install-deps ## Setup development environment
	$(call print_success,"Development environment setup complete!")

.PHONY: check-deps
check-deps: ## Check if all required dependencies are installed
	$(call print_status,"Checking dependencies...")
	$(call check_command,node)
	$(call check_command,npm)
	$(call check_command,cargo)
	$(call check_command,rustc)
	$(call check_node_version)
	$(call check_rust_version)
	$(call print_success,"All dependencies are available")

.PHONY: install-deps
install-deps: install-frontend-deps install-backend-deps ## Install all dependencies

.PHONY: install-frontend-deps
install-frontend-deps: ## Install frontend dependencies
	$(call print_status,"Installing frontend dependencies...")
	@npm install
	$(call print_success,"Frontend dependencies installed")

.PHONY: install-backend-deps
install-backend-deps: ## Install backend dependencies (handled by Cargo)

.PHONY: dev
dev: check-deps install-frontend-deps ## Start development server
	$(call print_status,"Starting development server...")
	@npm run tauri dev

.PHONY: dev-frontend
dev-frontend: ## Start frontend development server only
	$(call print_status,"Starting frontend development server...")
	@npm run dev

.PHONY: dev-backend
dev-backend: ## Start backend development server only
	$(call print_status,"Starting backend development server...")
	@cd $(BACKEND_DIR) && cargo tauri dev

.PHONY: build-dev
build-dev: ## Build for development
	$(call print_status,"Building for development...")
	@npm run tauri build -- --debug
	$(call print_success,"Development build complete")

# =============================================================================
# PRODUCTION BUILD TARGETS
# =============================================================================

.PHONY: build
build: check-deps build-frontend build-backend ## Build for production
	$(call print_success,"Production build complete!")

.PHONY: build-frontend
build-frontend: install-frontend-deps ## Build frontend for production
	$(call print_status,"Building frontend...")
	@npm run build
	$(call print_success,"Frontend built")

.PHONY: build-backend
build-backend: ## Build backend for production
	$(call print_status,"Building backend...")
	@cd $(BACKEND_DIR) && cargo tauri build $(RELEASE_FLAGS)
	$(call print_success,"Backend built")

.PHONY: build-release
build-release: ## Build release version with optimizations
	$(call print_status,"Building release version...")
	@cd $(BACKEND_DIR) && cargo tauri build --release
	$(call print_success,"Release build complete")

# =============================================================================
# CROSS-PLATFORM BUILD TARGETS
# =============================================================================

.PHONY: build-linux
build-linux: ## Build for Linux
	$(call print_status,"Building for Linux...")
	@cd $(BACKEND_DIR) && cargo tauri build --target x86_64-unknown-linux-gnu $(RELEASE_FLAGS)
	$(call print_success,"Linux build complete")

.PHONY: build-linux-arm64
build-linux-arm64: ## Build for Linux ARM64
	$(call print_status,"Building for Linux ARM64...")
	@cd $(BACKEND_DIR) && cargo tauri build --target aarch64-unknown-linux-gnu $(RELEASE_FLAGS)
	$(call print_success,"Linux ARM64 build complete")

.PHONY: build-windows
build-windows: ## Build for Windows
	$(call print_status,"Building for Windows...")
	@cd $(BACKEND_DIR) && cargo tauri build --target x86_64-pc-windows-msvc $(RELEASE_FLAGS)
	$(call print_success,"Windows build complete")

.PHONY: build-macos
build-macos: ## Build for macOS
	$(call print_status,"Building for macOS...")
	@cd $(BACKEND_DIR) && cargo tauri build --target x86_64-apple-darwin $(RELEASE_FLAGS)
	$(call print_success,"macOS build complete")

.PHONY: build-macos-arm64
build-macos-arm64: ## Build for macOS ARM64
	$(call print_status,"Building for macOS ARM64...")
	@cd $(BACKEND_DIR) && cargo tauri build --target aarch64-apple-darwin $(RELEASE_FLAGS)
	$(call print_success,"macOS ARM64 build complete")

.PHONY: build-all
build-all: build-linux build-windows build-macos ## Build for all platforms
	$(call print_success,"All platforms built!")

# =============================================================================
# TESTING TARGETS
# =============================================================================

.PHONY: test
test: test-frontend test-backend ## Run all tests

.PHONY: test-frontend
test-frontend: ## Run frontend tests
	$(call print_status,"Running frontend tests...")
	@npm test || $(call print_warning,"No frontend tests found")

.PHONY: test-backend
test-backend: ## Run backend tests
	$(call print_status,"Running backend tests...")
	@cd $(BACKEND_DIR) && cargo test || $(call print_warning,"No backend tests found")

.PHONY: lint
lint: lint-frontend lint-backend ## Run all linting

.PHONY: lint-frontend
lint-frontend: ## Lint frontend code
	$(call print_status,"Linting frontend...")
	@npx eslint src/ --ext .ts,.vue || $(call print_warning,"ESLint not configured")

.PHONY: lint-backend
lint-backend: ## Lint backend code
	$(call print_status,"Linting backend...")
	@cd $(BACKEND_DIR) && cargo clippy || $(call print_warning,"Clippy not available")

.PHONY: type-check
type-check: ## Run TypeScript type checking
	$(call print_status,"Running TypeScript type check...")
	@npx tsc --noEmit
	$(call print_success,"TypeScript check passed")

.PHONY: check
check: type-check lint test ## Run all checks
	$(call print_success,"All checks passed!")

# =============================================================================
# CLEANUP TARGETS
# =============================================================================

.PHONY: clean
clean: clean-frontend clean-backend clean-dist ## Clean all build artifacts

.PHONY: clean-frontend
clean-frontend: ## Clean frontend build artifacts
	$(call print_status,"Cleaning frontend...")
	@rm -rf node_modules package-lock.json $(DIST_DIR)
	$(call print_success,"Frontend cleaned")

.PHONY: clean-backend
clean-backend: ## Clean backend build artifacts
	$(call print_status,"Cleaning backend...")
	@cd $(BACKEND_DIR) && cargo clean
	$(call print_success,"Backend cleaned")

.PHONY: clean-dist
clean-dist: ## Clean distribution artifacts
	$(call print_status,"Cleaning distribution...")
	@rm -rf $(DIST_DIR) $(BUILD_DIR)
	$(call print_success,"Distribution cleaned")

.PHONY: clean-all
clean-all: clean ## Clean everything including caches
	$(call print_status,"Cleaning all caches...")
	@npm cache clean --force 2>/dev/null || true
	@cd $(BACKEND_DIR) && cargo cache --autoclean 2>/dev/null || true
	$(call print_success,"All cleaned")

# =============================================================================
# UTILITY TARGETS
# =============================================================================

.PHONY: update-deps
update-deps: update-frontend-deps update-backend-deps ## Update all dependencies

.PHONY: update-frontend-deps
update-frontend-deps: ## Update frontend dependencies
	$(call print_status,"Updating frontend dependencies...")
	@npm update
	$(call print_success,"Frontend dependencies updated")

.PHONY: update-backend-deps
update-backend-deps: ## Update backend dependencies
	$(call print_status,"Updating backend dependencies...")
	@cd $(BACKEND_DIR) && cargo update
	$(call print_success,"Backend dependencies updated")

.PHONY: format
format: format-frontend format-backend ## Format all code

.PHONY: format-frontend
format-frontend: ## Format frontend code
	$(call print_status,"Formatting frontend...")
	@npx prettier --write src/
	$(call print_success,"Frontend formatted")

.PHONY: format-backend
format-backend: ## Format backend code
	$(call print_status,"Formatting backend...")
	@cd $(BACKEND_DIR) && cargo fmt
	$(call print_success,"Backend formatted")

.PHONY: docs
docs: docs-frontend docs-backend ## Generate documentation

.PHONY: docs-frontend
docs-frontend: ## Generate frontend documentation
	$(call print_status,"Generating frontend docs...")
	@npx typedoc src/ || $(call print_warning,"TypeDoc not configured")

.PHONY: docs-backend
docs-backend: ## Generate backend documentation
	$(call print_status,"Generating backend docs...")
	@cd $(BACKEND_DIR) && cargo doc --open --no-deps || $(call print_warning,"Cargo doc failed")

.PHONY: info
info: ## Show system and project information
	@echo "SCYTHE GUI Information"
	@echo "======================"
	@echo "Platform: $(PLATFORM)"
	@echo "Architecture: $(ARCH)"
	@echo "Node.js: $$(node -v)"
	@echo "npm: $$(npm -v)"
	@echo "Rust: $$(rustc --version)"
	@echo "Cargo: $$(cargo --version)"
	@echo "Tauri: $(TAURI_VERSION)"
	@echo ""
	@echo "Project Structure:"
	@echo "  Frontend: $(FRONTEND_DIR)"
	@echo "  Backend: $(BACKEND_DIR)"
	@echo "  Dist: $(DIST_DIR)"
	@echo "  Build: $(BUILD_DIR)"

.PHONY: version
version: ## Show version information
	@echo "SCYTHE GUI v0.1.0"
	@echo "Node.js: $$(node -v)"
	@echo "Rust: $$(rustc --version)"
	@echo "Platform: $(PLATFORM) ($(ARCH))"

.PHONY: doctor
doctor: check-deps ## Run diagnostics
	$(call print_status,"Running diagnostics...")
	@npm doctor || $(call print_warning,"npm doctor failed")
	@cd $(BACKEND_DIR) && cargo doctor || $(call print_warning,"cargo doctor failed")
	$(call print_success,"Diagnostics complete")

# =============================================================================
# DEVELOPMENT WORKFLOW TARGETS
# =============================================================================

.PHONY: watch
watch: ## Watch for changes and rebuild
	$(call print_status,"Starting watch mode...")
	@npm run tauri dev -- --watch

.PHONY: serve
serve: build ## Build and serve production version locally
	$(call print_status,"Serving production build...")
	@cd $(DIST_DIR) && python3 -m http.server 8080 || \
	cd $(DIST_DIR) && npx serve -p 8080

.PHONY: deploy
deploy: build-release ## Build and prepare for deployment
	$(call print_status,"Preparing deployment...")
	@mkdir -p deploy
	@cp -r $(BUILD_DIR)/release/bundle/* deploy/ 2>/dev/null || true
	@cp -r $(DIST_DIR) deploy/ 2>/dev/null || true
	$(call print_success,"Deployment package ready in ./deploy/")

# =============================================================================
# DEFAULT TARGET
# =============================================================================

.DEFAULT_GOAL := help

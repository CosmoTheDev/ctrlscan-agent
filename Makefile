.PHONY: build install clean clean-db test lint js-lint doctor mcp-playwright mcp-playwright-gateway mcp-sqlite setup

JS_UI := internal/gateway/ui

BINARY   := ctrlscan
INSTALL  := $(HOME)/.ctrlscan/bin/$(BINARY)
GOFLAGS  :=

build:
	CGO_ENABLED=1 go build $(GOFLAGS) -o $(BINARY) .

install: build
	@mkdir -p $(HOME)/.ctrlscan/bin
	cp $(BINARY) $(INSTALL)
	@echo "Installed to $(INSTALL)"
	@echo ""
	@shell_name="$${SHELL##*/}"; \
	profile_file="$$HOME/.profile"; \
	if [ "$$shell_name" = "zsh" ]; then \
		profile_file="$$HOME/.zshrc"; \
	elif [ "$$shell_name" = "bash" ]; then \
		profile_file="$$HOME/.bashrc"; \
	fi; \
	if command -v ctrlscan >/dev/null 2>&1; then \
		echo "ctrlscan is already available on your PATH."; \
	else \
		echo "Add to your shell profile if not already done:"; \
		echo "  export PATH=\"\$$HOME/.ctrlscan/bin:\$$PATH\""; \
		echo ""; \
		echo "Append this line to $$profile_file:"; \
		echo "  echo 'export PATH=\"\$$HOME/.ctrlscan/bin:\$$PATH\"' >> $$profile_file"; \
	fi

uninstall:
	rm -f $(INSTALL)

setup:
	@echo "Setting up build dependencies..."
	@if command -v gcc >/dev/null 2>&1; then \
		echo "gcc is already installed: $$(gcc --version | head -1)"; \
	else \
		echo "gcc not found, installing..."; \
		if [ "$$(uname)" = "Darwin" ]; then \
			echo "macOS detected"; \
			if xcode-select -p >/dev/null 2>&1; then \
				echo "Xcode CLI tools already installed"; \
			else \
				echo "Installing Xcode Command Line Tools..."; \
				xcode-select --install; \
			fi; \
		elif [ "$$(uname)" = "Linux" ]; then \
			echo "Linux detected"; \
			if command -v apt-get >/dev/null 2>&1; then \
				echo "Using apt..."; \
				sudo apt-get update && sudo apt-get install -y gcc; \
			elif command -v dnf >/dev/null 2>&1; then \
				echo "Using dnf..."; \
				sudo dnf install -y gcc; \
			elif command -v yum >/dev/null 2>&1; then \
				echo "Using yum..."; \
				sudo yum install -y gcc; \
			elif command -v pacman >/dev/null 2>&1; then \
				echo "Using pacman..."; \
				sudo pacman -S --noconfirm gcc; \
			elif command -v apk >/dev/null 2>&1; then \
				echo "Using apk..."; \
				sudo apk add gcc musl-dev; \
			else \
				echo "Unknown Linux package manager. Please install gcc manually."; \
				exit 1; \
			fi; \
		elif echo "$$(uname)" | grep -qiE "mingw|msys|cygwin"; then \
			echo "Windows (MinGW/MSYS2/Cygwin) detected"; \
			if command -v pacman >/dev/null 2>&1; then \
				echo "Using pacman (MSYS2)..."; \
				pacman -S --noconfirm mingw-w64-x86_64-gcc; \
			else \
				echo "Please install MinGW-w64 gcc:"; \
				echo "  Option 1: Install MSYS2 and run: pacman -S mingw-w64-x86_64-gcc"; \
				echo "  Option 2: choco install mingw"; \
				exit 1; \
			fi; \
		else \
			echo "Unknown OS: $$(uname). Please install gcc manually."; \
			exit 1; \
		fi; \
	fi
	@echo ""
	@echo "Setup complete. Run 'make install' to build and install ctrlscan."

clean:
	rm -f $(BINARY)

clean-db:
	rm -f $(HOME)/.ctrlscan/ctrlscan.db
	rm -f $(HOME)/.ctrlscan/ctrlscan.db-wal
	rm -f $(HOME)/.ctrlscan/ctrlscan.db-shm

test:
	go test ./... -v -count=1

lint:
	@which golangci-lint >/dev/null 2>&1 || (echo "golangci-lint not found; install from https://golangci-lint.run" && exit 1)
	golangci-lint run ./...

js-lint:
	@which node >/dev/null 2>&1 || (echo "node not found; install Node.js to run js-lint" && exit 1)
	@[ -d node_modules ] || npm install --silent
	@echo "→ biome check"
	node_modules/.bin/biome check $(JS_UI)/js/ $(JS_UI)/app.js
	@echo "→ bundle check (esbuild)"
	node_modules/.bin/esbuild $(JS_UI)/app.js --bundle --platform=browser --format=esm 1>/dev/null
	@echo "js-lint passed ✓"

tidy:
	go mod tidy

doctor:
	./$(BINARY) doctor

tools:
	./$(BINARY) doctor --install-tools

mcp-playwright:
	@mkdir -p .codex/playwright-artifacts
	npx -y @playwright/mcp@latest \
		--headless \
		--isolated \
		--output-dir .codex/playwright-artifacts \
		--save-trace \
		--save-session \
		--viewport-size 1440x900 \
		--timeout-action 10000 \
		--timeout-navigation 90000

mcp-playwright-gateway:
	@mkdir -p .codex/playwright-artifacts
	npx -y @playwright/mcp@latest \
		--headless \
		--isolated \
		--host 127.0.0.1 \
		--port 8931 \
		--shared-browser-context \
		--output-dir .codex/playwright-artifacts \
		--save-trace \
		--save-session \
		--viewport-size 1440x900 \
		--timeout-action 10000 \
		--timeout-navigation 90000

mcp-sqlite:
	bash scripts/mcp-sqlite.sh

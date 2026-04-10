.PHONY: build install _install clean clean-db test lint js-lint doctor mcp-playwright mcp-playwright-gateway mcp-sqlite apple-intelligence-setup

JS_UI := internal/gateway/ui

BINARY     := ctrlscan
INSTALL    := $(HOME)/.ctrlscan/bin/$(BINARY)
GOFLAGS    :=
VENDOR_GAI := vendor/go-apple-intelligence
GAI_DYLIB  := $(VENDOR_GAI)/lib/libFoundationModels.dylib
GAI_CLONE  := https://github.com/CosmoTheDev/go-apple-intelligence.git

# Auto-detect Apple Intelligence support: darwin + arm64 + vendor dylib present.
# Variables are re-evaluated in each make invocation, so `install` uses a
# recursive $(MAKE) call after apple-intelligence-setup builds the dylib.
GOTAGS    :=
APPLE_LIB :=
ifeq ($(shell uname -s 2>/dev/null),Darwin)
ifeq ($(shell uname -m 2>/dev/null),arm64)
ifneq ($(wildcard $(GAI_DYLIB)),)
GOTAGS    := apple_intelligence
APPLE_LIB := $(abspath $(VENDOR_GAI)/lib)
endif
endif
endif

build:
ifdef APPLE_LIB
	CGO_LDFLAGS="-L$(APPLE_LIB) -Wl,-rpath,$(APPLE_LIB)" go build $(GOFLAGS) -mod=mod -tags apple_intelligence -o $(BINARY) .
else
	go build $(GOFLAGS) -o $(BINARY) .
endif

# apple-intelligence-setup: clone + build the dylib into vendor/ on capable Macs.
# Runs before the recursive $(MAKE) _install so that GOTAGS is re-evaluated with
# the freshly-built dylib already present.
apple-intelligence-setup:
	@if [ "$$(uname -s)" = "Darwin" ] && [ "$$(uname -m)" = "arm64" ]; then \
		if [ -f "$(GAI_DYLIB)" ]; then \
			echo "  Apple Intelligence: dylib ready ($(GAI_DYLIB))"; \
		else \
			echo ""; \
			echo "  Apple Intelligence: setting up native dylib..."; \
			if [ ! -d "$(VENDOR_GAI)" ]; then \
				echo "  Cloning go-apple-intelligence into $(VENDOR_GAI)..."; \
				git clone --depth 1 "$(GAI_CLONE)" "$(VENDOR_GAI)" || { echo "  Clone failed — skipping Apple Intelligence."; exit 0; }; \
			fi; \
			echo "  Building native dylib (requires Xcode 26+)..."; \
			if (cd "$(VENDOR_GAI)" && make build-native); then \
				echo "  Apple Intelligence: dylib built successfully."; \
			else \
				echo "  Build failed — ensure Xcode 26+ is installed (xcode-select --install)."; \
			fi; \
		fi; \
	fi

# `install` runs setup first, then delegates to `_install` via a fresh $(MAKE)
# invocation so GOTAGS/APPLE_LIB are re-evaluated with the dylib now present.
install: apple-intelligence-setup
	@$(MAKE) --no-print-directory _install

_install: build
	@mkdir -p $(HOME)/.ctrlscan/bin
	cp $(BINARY) $(INSTALL)
	@echo "Installed to $(INSTALL)"
	@if [ -n "$(GOTAGS)" ]; then echo "  (built with Apple Intelligence support)"; fi
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

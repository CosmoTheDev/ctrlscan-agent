.PHONY: build install clean clean-db test lint js-lint doctor mcp-playwright mcp-playwright-gateway mcp-sqlite

JS_UI := internal/gateway/ui

BINARY   := ctrlscan
INSTALL  := $(HOME)/.ctrlscan/bin/$(BINARY)
GOFLAGS  :=

build:
	go build $(GOFLAGS) -o $(BINARY) .

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

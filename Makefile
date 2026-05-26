.PHONY: build test lint clean fmt wasm

BINARY := bin/nuwyre
CMD    := ./cmd/nuwyre

# WASM target — same internal/bundle + internal/checks code paths
# the native CLI uses, compiled to a WebAssembly module loaded by
# the marketing site's /verify route. Phase 5.5 Session 5.5.1B C4.
#
# Six tenants: T2 (must produce identical results to native binary),
# T3 (uploaded bundles never leave the browser), T5 (the "see for
# yourself" moment), T6 (user value at point of use without install).
WASM_OUT  := web/nuwyre.wasm
WASM_CMD  := ./cmd/nuwyre-wasm

build:
	go build -trimpath -o $(BINARY) $(CMD)

# wasm builds the WebAssembly module + copies wasm_exec.js from the
# Go toolchain alongside it. wasm_exec.js is the canonical Go-WASM
# loader glue (uses syscall/js); copying it from $(go env GOROOT)
# guarantees the loader version matches the compiler version.
#
# **-trimpath** (Phase 5.5 Session 5.5.1B reviewer fix-up, sec-aud
# M1+L4): strips build-environment absolute paths from the compiled
# binary. Without -trimpath, debug.Stack() output embedded in panic-
# recovered error messages leaks developer/CI runner paths to the
# customer-facing /verify route. -trimpath is also applied to ldflags
# to keep version-string injection consistent with the trimmed build.
wasm:
	mkdir -p web
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-X main.Version=$$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-pre)" -o $(WASM_OUT) $(WASM_CMD)
	@echo "WASM binary: $(WASM_OUT) ($$(du -h $(WASM_OUT) | cut -f1))"
	@cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/wasm_exec.js 2>/dev/null || \
	 cp "$$(go env GOROOT)/misc/wasm/wasm_exec.js" web/wasm_exec.js
	@echo "WASM loader: web/wasm_exec.js"

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -rf bin web coverage

fmt:
	gofmt -w .

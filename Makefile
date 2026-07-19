CARGO ?= cargo
MSRV_CARGO ?= rustup run 1.85.0 cargo
PREFIX ?= $(HOME)/.local
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

.PHONY: all build check verify test test-unit test-integration test-cli test-msrv \
	lint coverage coverage-html package test-install install uninstall clean

all: check

build:
	$(CARGO) build --release --locked

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) test --all-features --locked
	$(CARGO) clippy --all-targets --all-features --locked -- -D warnings

verify:
	$(MAKE) --no-print-directory check
	$(MAKE) --no-print-directory coverage
	$(MAKE) --no-print-directory test-msrv
	$(MAKE) --no-print-directory build
	$(MAKE) --no-print-directory package
	$(MAKE) --no-print-directory test-install

test:
	$(CARGO) test --all-features --locked

test-unit:
	$(CARGO) test --all-features --locked --lib --bins

test-integration:
	$(CARGO) test --all-features --locked --test pipeline

test-cli:
	$(CARGO) test --all-features --locked --test cli

test-msrv:
	$(MSRV_CARGO) test --all-features --locked

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --all-targets --all-features --locked -- -D warnings

coverage:
	$(CARGO) llvm-cov --all-features --workspace --summary-only \
		--fail-under-lines 90 --fail-under-file-lines 80 \
		--fail-under-regions 90 --fail-under-functions 95

coverage-html:
	$(CARGO) llvm-cov --all-features --workspace --html

package:
	$(CARGO) package --allow-dirty --locked

test-install:
	@stage=$$(mktemp -d /tmp/netwhy-install.XXXXXX); \
	trap 'rm -rf -- "$$stage"' EXIT; \
	$(MAKE) --no-print-directory install DESTDIR="$$stage" PREFIX=/usr; \
	binary="$$stage/usr/bin/netwhy"; \
	test -x "$$binary"; \
	"$$binary" --version; \
	"$$binary" --help >/dev/null; \
	$(MAKE) --no-print-directory uninstall DESTDIR="$$stage" PREFIX=/usr; \
	test ! -e "$$binary"

install: build
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 target/release/netwhy "$(DESTDIR)$(BINDIR)/netwhy"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/netwhy"

clean:
	$(CARGO) clean

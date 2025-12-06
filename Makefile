CARGO ?= cargo

.PHONY: build test deb arch fmt

build:
	$(CARGO) build --release

test:
	$(CARGO) test

fmt:
	$(CARGO) fmt

# Build a Debian package (requires cargo-deb)
deb:
	$(CARGO) deb

# Build an Arch package using the provided PKGBUILD
arch: build
	cd packaging/arch && makepkg -sf

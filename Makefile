SHELL := /usr/bin/env bash
TOOLS := $(CURDIR)/.tools/bin
ARCH ?= x86_64
MELANGE_SIGNING_KEY ?= $(CURDIR)/keys/baseless.rsa

.PHONY: tools verify-key packages static glibc debug smoke-static smoke-glibc smoke-debug

tools:
	bash scripts/install-tools.sh "$(TOOLS)"

verify-key:
	bash scripts/verify-signing-key.sh "$(MELANGE_SIGNING_KEY)" keys/baseless.rsa.pub

packages: tools verify-key
	MELANGE_BIN="$(TOOLS)/melange" MELANGE_SIGNING_KEY="$(MELANGE_SIGNING_KEY)" bash scripts/build-packages.sh "$(ARCH)"

static: tools
	APKO_BIN="$(TOOLS)/apko" bash scripts/build-image.sh static "$(ARCH)"

glibc: tools
	APKO_BIN="$(TOOLS)/apko" bash scripts/build-image.sh glibc "$(ARCH)"

debug: tools
	APKO_BIN="$(TOOLS)/apko" bash scripts/build-image.sh debug "$(ARCH)"

smoke-static: static
	bash scripts/smoke-test.sh "dist/baseless-static-$(ARCH).tar" static

smoke-glibc: glibc
	bash scripts/smoke-test.sh "dist/baseless-glibc-$(ARCH).tar" glibc

smoke-debug: debug
	bash scripts/smoke-test.sh "dist/baseless-debug-$(ARCH).tar" debug

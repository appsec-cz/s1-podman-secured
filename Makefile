.PHONY: help build clean install-deps

help:
	@echo "Podman Machine Image Builder - Debian 13"
	@echo ""
	@echo "Commands:"
	@echo "  make install-deps  - Install build dependencies"
	@echo "  make build         - Build Debian 13 image with Podman"
	@echo "  make clean         - Remove build artifacts"
	@echo ""

build:
	LIBGUESTFS_BACKEND_SETTINGS=force_tcg ./build.sh

clean:
	rm -rf cache output

install-deps:
	@echo "Installing dependencies..."
	sudo apt update
	sudo apt install -y \
		libguestfs-tools \
		qemu-utils \
		qemu-system \
		xz-utils \
		zstd \
		curl \
		debootstrap
	@echo "Done!"

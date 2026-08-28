#!/usr/bin/env bash

set -u

progname="unlockata"
distsdir="dists"

init() {
	if ! command -v go >/dev/null 2>&1; then
		echo "go command not found."
		exit 1
	fi

	if ! command -v tar >/dev/null 2>&1; then
		echo "tar command not found."
		exit 1
	fi

	if ! command -v zip >/dev/null 2>&1; then
		echo "zip command not found."
		exit 1
	fi

	if [ -d "$distsdir" ]; then
		read -r -p "$distsdir directory exists. Remove to continue? [y/N]: " answer

		case "$answer" in
			y|Y)
				rm -rf -- "$distsdir"
				;;
			*)
				echo "Cannot crossbuild without removing existing $distsdir."
				exit 1
				;;
		esac
	fi

	mkdir -p -- "$distsdir"
	cd -- "$distsdir"
}

preparedist() {
	local os="$1"
	local arch="$2"
	local distdir="$progname-$os-$arch"

	mkdir -p -- "$distdir"
	cp -- ../LICENSE "$distdir/"
	cp -- ../README.md "$distdir/"
}

compile() {
	local os="$1"
	local arch="$2"
	local distdir="$progname-$os-$arch"
	local winex=""

	if [ "$os" = "windows" ]; then
		winex=".exe"
	fi

	echo "--- Compiling for $os/$arch platform"

	if ! CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -o "$distdir/$progname$winex" ../; then

		echo "--- Compilation failed for $os/$arch. Destroying distdir..."
		rm -rf -- "$distdir"
	fi
}

maketarballs() {
	shopt -s nullglob

	for distdir in "$progname"-*; do
		[ -d "$distdir" ] || continue

		case "$distdir" in
			*-windows-*)
				echo "--- Making zip ${distdir}.zip"
				zip -rq -- "${distdir}.zip" "$distdir"
				;;

			*)
				echo "--- Making tarball ${distdir}.tar.gz"
				tar -czf "${distdir}.tar.gz" "$distdir"
				;;
		esac
	done

	shopt -u nullglob
}

removedists() {
	echo "--- Cleaning up"

	shopt -s nullglob

	for archive in "$progname"-*.tar.gz "$progname"-*.zip; do
		case "$archive" in
			*.tar.gz)
				distdir="${archive%.tar.gz}"
				;;
			*.zip)
				distdir="${archive%.zip}"
				;;
		esac

		rm -rf -- "$distdir"
	done

	shopt -u nullglob
}

close() {
	echo "--- Result:"
	ls -lah
	echo "--- Tarballs & zips are available in $(pwd)"
}

crosscompile() {
	go tool dist list | grep -E '^(linux)/(386|amd64|arm|arm64|loong64|riscv64)$' | while IFS=/ read os arch; do
		preparedist $os $arch
		compile $os $arch
	done
}

init
crosscompile
maketarballs
removedists
close

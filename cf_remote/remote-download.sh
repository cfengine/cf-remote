#!/bin/bash

set -e

OPTS=$(getopt -o IChc: --long insecure,curl,help,checksum: -n "$0" -- "$@") || exit 1

usage() {
  cat << EOF 
Usage: $0 [OPTIONS] <package_url>
A script to download packages from url securely.

Options:
  -c, --checksum VAL    Provide a SHA256 checksum to verify package integrity
  -C, --curl            Use curl instead of default wget
  -I, --insecure        Skip package integrity verification
EOF
  exit 0
}

# Arg parsing
eval set -- "$OPTS"

INSECURE=0
USE_CURL=0
CHECKSUM=""

while true; do
  case "$1" in
    -h|--help)      usage ;;
    -I|--insecure)  INSECURE=1; shift ;;
    -C|--curl)      USE_CURL=1; shift ;;
    -c|--checksum)  CHECKSUM="$2"; shift 2 ;;
    --)             shift; break ;;
    *)              echo "Error"; exit 1 ;;
  esac
done

PACKAGE=$1
if [ -z "$PACKAGE" ]; then
  usage
fi

# temp file

tmpfile=$(mktemp)
cleanup() {
  rm -f "$tmpfile"
}
trap cleanup EXIT QUIT TERM INT

# Download

if [ "$USE_CURL" -eq 1 ]; then
  curl --fail -sS -o "$tmpfile" "$PACKAGE"
else
  wget -nv -O "$tmpfile" "$PACKAGE"
fi

# Checksum

filename="$(basename "$PACKAGE")"

if [ -n "$CHECKSUM" ]; then
    hash="$(sha256sum "$tmpfile" | awk '{print $1}')"

    if [[ "$CHECKSUM" != "$hash" ]]; then
        if [ "$INSECURE" -eq 0 ]; then
          echo "Package '$PACKAGE' doesn't match the expected checksum '$CHECKSUM'. Run with --insecure to skip"
          exit 1
        fi
        echo "Package '$PACKAGE' doesn't match the expected checksum '$CHECKSUM'. Continuing due to insecure flag"
    fi
fi

mv "$tmpfile" "$filename"


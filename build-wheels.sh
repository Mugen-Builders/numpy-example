#!/bin/bash
# Builds pre-compiled wheels for linux/riscv64 using Docker + QEMU emulation.
# Run this once on your host before `cartesi build`.
# Output wheels are saved to ./wheels/ and used by the Dockerfile.

set -e

WHEELS_DIR="$(dirname "$0")/wheels"
mkdir -p "$WHEELS_DIR"

echo "Building riscv64 wheels into $WHEELS_DIR ..."

docker run --rm \
  --platform linux/riscv64 \
  -v "$WHEELS_DIR:/wheels" \
  cartesi/python:3.10-slim-jammy \
  sh -c "
    set -e
    apt-get update -q
    apt-get install -y --no-install-recommends \
      build-essential \
      cmake \
      ninja-build \
      pkg-config \
      patchelf
    NPY_BLAS_ORDER="" NPY_LAPACK_ORDER="" pip wheel 'numpy>=1.26.0' --no-deps -w /wheels
    echo 'Done. Wheels:'
    ls /wheels
  "

echo "Wheel build complete. Files in $WHEELS_DIR:"
ls "$WHEELS_DIR"

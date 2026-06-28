#!/bin/bash

echo "Building dispatch-warp binaries for all platforms..."

# Create build directory if it doesn't exist
mkdir -p build

# Windows AMD64
echo "Compiling Windows AMD64..."
GOOS=windows GOARCH=amd64 go build -o build/dispatch-warp-windows-amd64.exe ./src

# Linux AMD64
echo "Compiling Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -o build/dispatch-warp-linux-amd64 ./src

# macOS AMD64 (Intel)
echo "Compiling macOS AMD64..."
GOOS=darwin GOARCH=amd64 go build -o build/dispatch-warp-darwin-amd64 ./src

# macOS ARM64 (Apple Silicon)
echo "Compiling macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build -o build/dispatch-warp-darwin-arm64 ./src

echo ""
echo "Build complete! Binaries are located in the build/ directory:"
ls -1 build

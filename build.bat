@echo off
echo Building dispatch-warp binaries for all platforms...

:: Create build directory if it doesn't exist
if not exist "build" mkdir build

:: Windows AMD64
echo Compiling Windows AMD64...
set GOOS=windows
set GOARCH=amd64
go build -o build/dispatch-warp-windows-amd64.exe ./src

:: Linux AMD64
echo Compiling Linux AMD64...
set GOOS=linux
set GOARCH=amd64
go build -o build/dispatch-warp-linux-amd64 ./src

:: macOS AMD64 (Intel)
echo Compiling macOS AMD64...
set GOOS=darwin
set GOARCH=amd64
go build -o build/dispatch-warp-darwin-amd64 ./src

:: macOS ARM64 (Apple Silicon)
echo Compiling macOS ARM64...
set GOOS=darwin
set GOARCH=arm64
go build -o build/dispatch-warp-darwin-arm64 ./src

:: Reset env vars
set GOOS=
set GOARCH=

echo.
echo Build complete! Binaries are located in the build/ directory:
dir build /B

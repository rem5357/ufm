@echo off
REM Build UFM for Windows

echo Building UFM for Windows...

cargo build --release

if exist target\release\ufm.exe (
    echo.
    echo Build successful!
    echo Binary location: target\release\ufm.exe
    echo.
    echo To install for Claude Desktop, add to claude_desktop_config.json:
    echo {
    echo   "mcpServers": {
    echo     "ufm": {
    echo       "command": "%CD%\target\release\ufm.exe"
    echo     }
    echo   }
    echo }
) else (
    echo Build failed!
    exit /b 1
)

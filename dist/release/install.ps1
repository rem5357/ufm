# UFM Windows Installer
# Run as: powershell -ExecutionPolicy Bypass -File install.ps1
# Or just double-click ufm.exe and it will self-install on first run

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\UFM",
    [switch]$AddToPath = $true,
    [switch]$Silent = $false,
    [switch]$SkipClaudeConfig = $false
)

$ErrorActionPreference = "Stop"

# Version info
$Version = "0.11.0"
$UpdateUrl = "http://goldshire:8080/ufm"

function Write-Status {
    param([string]$Message)
    if (-not $Silent) {
        Write-Host "[UFM] $Message" -ForegroundColor Cyan
    }
}

function Write-Success {
    param([string]$Message)
    if (-not $Silent) {
        Write-Host "[OK] $Message" -ForegroundColor Green
    }
}

function Write-Warn {
    param([string]$Message)
    if (-not $Silent) {
        Write-Host "[WARN] $Message" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   UFM - Universal File Manager v$Version" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Status "Installing to: $InstallDir"

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Success "Created directory: $InstallDir"
}

# Copy UFM executable
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path $ScriptDir "ufm.exe"
$InstalledExe = Join-Path $InstallDir "ufm.exe"

if (-not (Test-Path $ExePath)) {
    # Try downloading from update server
    Write-Status "Downloading UFM from $UpdateUrl..."
    try {
        Invoke-WebRequest -Uri "$UpdateUrl/ufm.exe" -OutFile $InstalledExe
        Write-Success "Downloaded UFM"
    } catch {
        Write-Error "Failed to download UFM: $_"
        exit 1
    }
} else {
    Copy-Item $ExePath -Destination $InstallDir -Force
    Write-Success "Copied UFM executable"
}

# Create UFM config directory
$ConfigDir = "$env:APPDATA\UFM"
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    Write-Success "Created config directory: $ConfigDir"
}

# Create default UFM config if not exists
$ConfigPath = Join-Path $ConfigDir "config.toml"
if (-not (Test-Path $ConfigPath)) {
    $DefaultConfig = @"
# UFM Configuration
name = "UFM"
version = "$Version"

[security]
# Allow access to user profile directories by default
allowed_paths = [
    "~",
    "C:\\Users\\$env:USERNAME"
]

# Deny access to system directories
denied_paths = [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)"
]
"@
    Set-Content -Path $ConfigPath -Value $DefaultConfig
    Write-Success "Created UFM config: $ConfigPath"
}

# Add to PATH if requested
if ($AddToPath) {
    $UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        $NewPath = "$UserPath;$InstallDir"
        [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
        Write-Success "Added UFM to PATH"
    } else {
        Write-Status "UFM already in PATH"
    }
}

# Configure Claude Desktop automatically
if (-not $SkipClaudeConfig) {
    $ClaudeConfigDir = "$env:APPDATA\Claude"
    $ClaudeConfigPath = Join-Path $ClaudeConfigDir "claude_desktop_config.json"

    # Use forward slashes for the command path (works better in JSON)
    $UfmCommand = ($InstalledExe -replace '\\', '/')

    Write-Status "Configuring Claude Desktop..."

    if (Test-Path $ClaudeConfigPath) {
        # Read existing config
        $ConfigContent = Get-Content $ClaudeConfigPath -Raw
        $Config = $ConfigContent | ConvertFrom-Json

        # Check if ufm already exists and is using mcp-remote (old config)
        $NeedsUpdate = $false
        if ($Config.mcpServers.ufm) {
            # Check if it's the old mcp-remote style
            if ($Config.mcpServers.ufm.args -contains "mcp-remote") {
                Write-Status "Found old UFM config (mcp-remote), updating to local..."
                $NeedsUpdate = $true
            } elseif ($Config.mcpServers.ufm.command -ne $UfmCommand) {
                Write-Status "Updating UFM path..."
                $NeedsUpdate = $true
            } else {
                Write-Status "Claude Desktop already configured for UFM"
            }
        } else {
            $NeedsUpdate = $true
        }

        if ($NeedsUpdate) {
            # Create backup
            $BackupPath = "$ClaudeConfigPath.backup"
            Copy-Item $ClaudeConfigPath $BackupPath -Force
            Write-Status "Backed up existing config to: $BackupPath"

            # Update or add UFM config
            $UfmConfig = @{
                command = $UfmCommand
                args = @("--network")
                alwaysAllow = @(
                    "ufm_list",
                    "ufm_stat",
                    "ufm_read",
                    "ufm_exists",
                    "ufm_search",
                    "ufm_archive_list",
                    "ufm_archive_read",
                    "ufm_crawl",
                    "ufm_nodes",
                    "ufm_ping"
                )
            }

            # Add or update the ufm entry
            if (-not $Config.mcpServers) {
                $Config | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue @{} -Force
            }
            $Config.mcpServers | Add-Member -NotePropertyName "ufm" -NotePropertyValue $UfmConfig -Force

            # Write updated config
            $Config | ConvertTo-Json -Depth 10 | Set-Content $ClaudeConfigPath -Encoding UTF8
            Write-Success "Updated Claude Desktop config"
        }
    } else {
        # Create new config
        if (-not (Test-Path $ClaudeConfigDir)) {
            New-Item -ItemType Directory -Path $ClaudeConfigDir -Force | Out-Null
        }

        $NewConfig = @{
            mcpServers = @{
                ufm = @{
                    command = $UfmCommand
                    args = @("--network")
                    alwaysAllow = @(
                        "ufm_list",
                        "ufm_stat",
                        "ufm_read",
                        "ufm_exists",
                        "ufm_search",
                        "ufm_archive_list",
                        "ufm_archive_read",
                        "ufm_crawl",
                        "ufm_nodes",
                        "ufm_ping"
                    )
                }
            }
        }

        $NewConfig | ConvertTo-Json -Depth 10 | Set-Content $ClaudeConfigPath -Encoding UTF8
        Write-Success "Created Claude Desktop config"
    }
}

# Verify installation
Write-Host ""
if (Test-Path $InstalledExe) {
    Write-Status "Verifying installation..."
    & $InstalledExe --version
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Success "UFM installed successfully!"
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Restart Claude Desktop to load the new UFM" -ForegroundColor White
Write-Host "  2. UFM will run locally with P2P networking enabled" -ForegroundColor White
Write-Host ""
Write-Host "To check for updates later, run:" -ForegroundColor Yellow
Write-Host "  ufm --check-update" -ForegroundColor White
Write-Host ""

# Keep window open if double-clicked
if (-not $Silent) {
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

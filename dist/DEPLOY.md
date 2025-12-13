# UFM Deployment Guide

## Building Releases

Run the build script from the project root:

```bash
./dist/build-release.sh
```

This will:
1. Build UFM for Linux (x86_64)
2. Build UFM for Windows (x86_64)
3. Copy the installer script
4. Generate `version.json` with checksums

## Distributing via Nginx on Goldshire

### 1. Set up the web directory

```bash
ssh goldshire
sudo mkdir -p /var/www/ufm
sudo chown $USER:$USER /var/www/ufm
```

### 2. Deploy the release files

From your development machine:

```bash
scp -r dist/release/* goldshire:/var/www/ufm/
```

### 3. Configure Nginx

Copy the Nginx config:

```bash
scp dist/nginx/ufm.conf goldshire:/tmp/
ssh goldshire
sudo mv /tmp/ufm.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/ufm.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 4. Verify deployment

```bash
curl http://goldshire:8080/ufm/version.json
```

Should return:
```json
{
  "version": "0.11.0",
  "build": 55,
  "download_url": "http://goldshire:8080/ufm/ufm.exe",
  ...
}
```

## Installing UFM on Windows

### Option 1: PowerShell Installer (Recommended)

1. Download `install.ps1` from `http://goldshire:8080/ufm/install.ps1`
2. Open PowerShell as Administrator
3. Run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File install.ps1
   ```

### Option 2: Manual Installation

1. Download `ufm.exe` from `http://goldshire:8080/ufm/ufm.exe`
2. Place in desired location (e.g., `C:\Program Files\UFM\`)
3. Add to PATH if desired
4. Configure Claude Desktop MCP (see below)

## Claude Desktop MCP Configuration

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ufm": {
      "command": "C:/Users/YOUR_USER/AppData/Local/UFM/ufm.exe",
      "args": []
    }
  }
}
```

## Updating UFM

### Check for updates:
```bash
ufm --check-update
```

### Download and install update:
```bash
ufm --update
```

The auto-update will:
1. Check `http://goldshire:8080/ufm/version.json` for new versions
2. Download the new binary
3. Verify SHA256 checksum
4. Replace the executable (requires restart)

## Release Files

| File | Description |
|------|-------------|
| `ufm.exe` | Windows executable |
| `ufm-linux-x86_64` | Linux executable |
| `install.ps1` | Windows PowerShell installer |
| `version.json` | Update manifest with version info and checksums |

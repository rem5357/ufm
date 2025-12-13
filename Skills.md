# UFM Development Rules

## Build & Deployment Workflow

Follow these rules for EVERY code change:

### 1. Increment Build Number
- Edit `ufm/Cargo.toml` and increment the build number in the `[package.metadata]` section
- Build number increases by 1 for every edit/rebuild cycle

### 2. Rebuild After Each Edit
```bash
cd /home/mithroll/Projects/UFM/ufm
cargo build --release
```

### 3. Build Windows & Deploy to Web Server
```bash
cd /home/mithroll/Projects/UFM/ufm
./dist/build-release.sh

# Deploy (we're on goldshire, so copy directly)
cp dist/release/* /var/www/ufm/

# Update running daemon
sudo systemctl stop ufm
cp dist/release/ufm-linux-x86_64 ~/.local/bin/ufm
chmod +x ~/.local/bin/ufm
sudo systemctl start ufm
```

### 4. Version Updates
- Only update the version number (in Cargo.toml) when the user explicitly requests it
- Build numbers increment automatically with each edit

### 5. Git Commit After Each Edit
```bash
git add -A
git commit -m "Description of change (build XX)"
```

### 6. GitHub Push
- Push to GitHub every 5 builds OR when the user explicitly requests it
```bash
git push origin main
```

## Quick Reference

| Action | When |
|--------|------|
| Increment build # | Every edit |
| Rebuild | Every edit |
| Deploy to goldshire | Every edit |
| Git commit | Every edit |
| Update version | User request only |
| Push to GitHub | Every 5 builds or user request |

## Current State

Check current version/build:
```bash
grep -E "^version|^build" ufm/Cargo.toml
```

Check what's deployed:
```bash
cat ufm/dist/release/version.json
```

Check UFM status on goldshire:
```bash
ssh goldshire "systemctl status ufm"
```

# Hostinger VPS Deployment Guide

Deploy the minimal AI automation stack on a cheap Hostinger VPS.

## VPS Selection

**Recommended Plan**: KVM 1 or KVM 2
- 1-2 vCPU
- 4GB RAM
- 50GB SSD
- ~$4-8/month

This is more than enough for the bot + occasional Claude API calls.

## Initial Setup

### 1. SSH In

```bash
ssh root@your-vps-ip
```

### 2. Create Non-Root User

```bash
adduser potato
usermod -aG sudo potato
su - potato
```

### 3. Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Python 3.11+
sudo apt install python3.11 python3.11-venv python3-pip -y

# Git
sudo apt install git -y
```

### 4. Clone Repo

```bash
cd ~
git clone https://github.com/youruser/Couch.Potato.git
cd Couch.Potato/automation
```

### 5. Setup Environment

```bash
# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp config.example.env .env
nano .env  # Add your API keys
```

## Running the Bot

### Option A: Screen (Simple)

```bash
screen -S potato
source venv/bin/activate
python bot.py

# Detach: Ctrl+A, D
# Reattach: screen -r potato
```

### Option B: Systemd Service (Production)

Create service file:

```bash
sudo nano /etc/systemd/system/couch-potato.service
```

Contents:

```ini
[Unit]
Description=Couch.Potato Telegram Bot
After=network.target

[Service]
Type=simple
User=potato
WorkingDirectory=/home/potato/Couch.Potato/automation
Environment=PATH=/home/potato/Couch.Potato/automation/venv/bin
EnvironmentFile=/home/potato/Couch.Potato/automation/.env
ExecStart=/home/potato/Couch.Potato/automation/venv/bin/python bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable couch-potato
sudo systemctl start couch-potato

# Check status
sudo systemctl status couch-potato

# View logs
sudo journalctl -u couch-potato -f
```

## IPython Cockpit Access

### Option A: SSH Tunnel (Secure)

From your local machine:

```bash
ssh -L 8888:localhost:8888 potato@your-vps-ip
```

On the VPS:

```bash
cd ~/Couch.Potato/automation
source venv/bin/activate
jupyter notebook --no-browser --port=8888
```

Then open `http://localhost:8888` in your browser.

### Option B: Direct Access (Quick & Dirty)

On VPS:

```bash
jupyter notebook --ip=0.0.0.0 --port=8888 --no-browser
```

Then open `http://your-vps-ip:8888`

**Note**: This exposes Jupyter to the internet. Use a strong password or token.

## Security Hardening

### Firewall

```bash
sudo ufw allow OpenSSH
sudo ufw allow 443  # if needed
sudo ufw enable
```

### Fail2ban

```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
```

### SSH Key Only

```bash
# On your local machine
ssh-copy-id potato@your-vps-ip

# On VPS - disable password auth
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no
sudo systemctl restart sshd
```

## Updating

```bash
cd ~/Couch.Potato
git pull
cd automation
source venv/bin/activate
pip install -r requirements.txt --upgrade
sudo systemctl restart couch-potato
```

## Troubleshooting

### Bot not responding

```bash
# Check if running
sudo systemctl status couch-potato

# Check logs
sudo journalctl -u couch-potato -n 50

# Test manually
cd ~/Couch.Potato/automation
source venv/bin/activate
python bot.py
```

### API errors

```bash
# Test Claude API
python -c "from brain import ask_claude; import asyncio; print(asyncio.run(ask_claude('ping')))"
```

### Memory issues

```bash
# Check usage
free -h
htop

# Add swap if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Cost Summary

| Item | Monthly |
|------|---------|
| Hostinger VPS KVM 1 | ~$4 |
| Claude API (light use) | ~$5-10 |
| Telegram | Free |
| **Total** | **~$10-15** |

For heavier usage (lots of triage, report drafting), budget ~$20-25/mo.

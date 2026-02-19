# 🛋️ Couch Potato Controller - Setup Guide

Control your computer's keyboard and mouse from your iPhone while relaxing on the couch!

## 📱 What You Need

- **iPhone**: Running Pythonista 3 app
- **Computer**: Windows, macOS, or Linux
- **WiFi**: Both devices on the same network

## 🚀 Quick Setup (5 minutes)

### Step 1: Prepare Your Computer

1. **Install Python 3.7+** (if not already installed)
   - Check: `python3 --version`

2. **Install required libraries:**
   ```bash
   pip3 install websockets pynput
   ```

3. **Download the files** to your computer:
   - `receiver_server.py`
   - Save to a folder you can find easily

4. **Run the receiver server:**
   ```bash
   python3 receiver_server.py
   ```

5. **Note the IP address** shown (e.g., `192.168.1.100:8765`)

### Step 2: Set Up Pythonista on iPhone

1. **Open Pythonista** on your iPhone

2. **Create a new folder** (optional but recommended):
   - Tap `+` → `Folder` → Name it "CouchPotato"

3. **Add the files:**

   **Method A - Copy/Paste (Easiest):**
   - Tap `+` → `Empty Script`
   - Name it `pythonista_server.py`
   - Copy the contents from `pythonista_server.py`
   - Paste and save
   - Repeat for `couch_controller.html`

   **Method B - Import from iCloud:**
   - Save files to iCloud Drive
   - In Pythonista: `+` → `Import` → Navigate to files

4. **Run the server:**
   - Tap `pythonista_server.py`
   - Tap ▶️ (run button)
   - You'll see: `Server running on port 8080`

### Step 3: Connect and Control!

1. **Open Safari on your iPhone**
   - Go to: `http://localhost:8080`

2. **Configure connection:**
   - Tap `⚙️ Settings` tab
   - Enter your computer's address: `192.168.1.100:8765`
   - Tap `Connect to Computer`

3. **Start controlling:**
   - Tap `🖱️ Trackpad` - Drag to move mouse, tap buttons to click
   - Tap `⌨️ Keyboard` - Type with virtual keyboard

## 🎮 Usage Tips

### Trackpad Mode
- **Drag anywhere** to move the cursor
- **Sensitivity**: Movements are 2x amplified for speed
- **Tap buttons** for Left/Middle/Right click
- Works great for browsing, navigating

### Keyboard Mode
- **Text Input Field**: Type naturally, characters sent in real-time
- **Virtual Keyboard**: Tap keys for special characters
- **Modifiers**: Tap Ctrl/Shift/Alt/⌘ then tap another key
  - Example: Ctrl+C → Tap Ctrl (it highlights) → Tap C
- **Function Keys**: F1-F4 + Esc + Delete on top row

### Common Shortcuts
- **Copy**: Ctrl → C
- **Paste**: Ctrl → V
- **Undo**: Ctrl → Z
- **Tab Switch**: Ctrl → Tab
- **Close Window**: Alt → F4 (Windows) or ⌘ → Q (Mac)

## 🔧 Troubleshooting

### "Failed to connect" error

**Check 1: Same WiFi Network**
- iPhone and computer must be on same WiFi
- Turn off cellular data temporarily
- Verify WiFi name matches on both devices

**Check 2: Server Running**
- Make sure `receiver_server.py` is running
- Terminal should show: "Waiting for connections..."
- If it stopped, run it again

**Check 3: Firewall**
- Windows: Allow Python through Windows Defender Firewall
- Mac: System Preferences → Security → Firewall → Allow incoming
- Linux: `sudo ufw allow 8765`

**Check 4: Correct IP Address**
- IP shown in receiver server: `192.168.1.100:8765`
- Enter EXACTLY that in Settings (including `:8765`)
- Don't use `localhost` - use the actual IP

### Mouse not moving smoothly

- **Solution**: Increase sensitivity in your iPhone
- Try slower drag movements
- Ensure iPhone isn't in Low Power Mode

### Keyboard not working

- **Check modifiers**: Make sure Ctrl/Shift/Alt are OFF (not highlighted)
- **Try text input**: Type in the text field at top instead
- **Restart both servers** if keys seem stuck

### Can't access http://localhost:8080

- **Check Pythonista**: Make sure server is running (not stopped)
- **Try the IP**: Use `http://192.168.x.x:8080` shown in Pythonista
- **Reload page**: Pull down to refresh in Safari

## 🔒 Security Notes

- This runs on your **local network only**
- No internet connection required
- No data sent to external servers
- Both servers are visible only to devices on your WiFi

## 💡 Advanced Tips

### Keep Pythonista Running
- iOS suspends background apps after a few minutes
- Workaround: Keep Pythonista in foreground
- Or: Use Safari in split-screen mode

### Run on Mac Startup (Computer)
1. Create a script: `start_receiver.sh`
   ```bash
   #!/bin/bash
   cd /path/to/couch-potato
   python3 receiver_server.py
   ```
2. Make executable: `chmod +x start_receiver.sh`
3. Add to Login Items (Mac) or Startup (Windows)

### Multiple Computers
- Run receiver server on each computer (different IPs)
- Save different addresses in Settings
- Switch between them by changing address and reconnecting

### Use Over Internet (Advanced)
⚠️ **Not recommended for security reasons**, but possible:
1. Set up port forwarding on router (port 8765)
2. Use dynamic DNS service
3. Connect using public IP
4. Better option: Use VPN to access home network

## 📊 Performance

- **Latency**: ~10-50ms on good WiFi
- **Range**: Anywhere in WiFi coverage
- **Battery**: Pythonista uses minimal battery
- **Better than Bluetooth**:
  - Longer range
  - More stable
  - No pairing needed

## 🆘 Still Not Working?

1. **Restart everything:**
   - Close Pythonista completely
   - Stop receiver server (Ctrl+C)
   - Restart both

2. **Check Python version:**
   ```bash
   python3 --version  # Should be 3.7 or higher
   ```

3. **Reinstall dependencies:**
   ```bash
   pip3 uninstall websockets pynput
   pip3 install websockets pynput
   ```

4. **Test basic connectivity:**
   ```bash
   # On computer, note the IP
   ifconfig  # Mac/Linux
   ipconfig  # Windows

   # On iPhone Safari, visit:
   http://192.168.1.100:8080
   ```

## 🎯 What's Next?

Once you have it working:
- Try controlling a presentation (Keyboard → Arrow keys)
- Browse YouTube from your couch (Trackpad)
- Play simple mouse-based games
- Control media playback (Space, Arrow keys)

## ❓ FAQ

**Q: Does this work over the internet?**
A: Designed for local network only. Internet use requires advanced networking.

**Q: Can I use it on Android?**
A: Not with Pythonista (iOS only), but you can adapt the HTML to any web server.

**Q: Will it work with Bluetooth disabled?**
A: Yes! Uses WiFi only, no Bluetooth needed.

**Q: Can multiple phones connect?**
A: Yes, receiver server supports multiple clients simultaneously.

**Q: Is there lag?**
A: Minimal on good WiFi (10-50ms). Bluetooth would be similar or worse.

**Q: Can I customize the keyboard layout?**
A: Yes! Edit `couch_controller.html` - it's just HTML/CSS/JavaScript.

---

**Enjoy controlling your computer from the couch!** 🛋️✨

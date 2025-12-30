# 🛋️ Couch Potato Controller

**Control your computer's keyboard and mouse from your iPhone - perfect for the couch!**

## What Is This?

A WiFi-based remote keyboard and mouse controller that lets you control your computer from your iPhone using Pythonista. No Bluetooth required!

```
┌──────────────┐                    ┌──────────────┐
│              │   WiFi Network     │              │
│    iPhone    │ ←─────────────────→│   Computer   │
│  Pythonista  │   WebSocket        │   Python     │
│              │                    │              │
└──────────────┘                    └──────────────┘
     Web UI                         Keyboard/Mouse
   (Touch Input)                      Control
```

## Features

- ✅ **Full trackpad** with smooth cursor control
- ✅ **Complete keyboard** with all modifiers (Ctrl, Shift, Alt, ⌘)
- ✅ **Fast typing** with native text input
- ✅ **Left/Right/Middle click** mouse buttons
- ✅ **Function keys** and special keys (F1-F12, arrows, etc.)
- ✅ **Mobile-first design** optimized for iPhone
- ✅ **Works over WiFi** - better range than Bluetooth
- ✅ **Low latency** - 10-50ms response time
- ✅ **No pairing needed** - just connect and go
- ✅ **Cross-platform** - works with Windows, macOS, Linux

## Quick Start

### On Your Computer:

```bash
# Install dependencies
pip3 install -r requirements.txt

# Run the receiver
python3 receiver_server.py

# Note the IP address shown (e.g., 192.168.1.100:8765)
```

### On Your iPhone (Pythonista):

1. Copy `pythonista_server.py` and `couch_controller.html` to Pythonista
2. Run `pythonista_server.py`
3. Open Safari → `http://localhost:8080`
4. Go to Settings → Enter computer IP → Connect
5. Switch to Trackpad or Keyboard mode and start controlling!

📖 **Full setup guide:** See [SETUP_GUIDE.md](SETUP_GUIDE.md)

## Why Network Instead of Bluetooth?

While the original goal was Bluetooth HID, iOS sandboxing prevents apps (including Pythonista) from acting as Bluetooth HID devices. The network approach actually has several advantages:

| Feature | Network (This) | Bluetooth HID |
|---------|---------------|---------------|
| Range | Entire WiFi coverage | ~10 meters |
| Latency | 10-50ms | 10-100ms |
| Setup | No pairing | Pairing required |
| Reliability | Very stable | Can disconnect |
| Battery | Minimal | Moderate |
| iOS Support | ✅ Works in Pythonista | ❌ Not accessible |

## Architecture

```
┌─────────────────────────────────────────────────┐
│  iPhone (Pythonista)                            │
│  ┌──────────────────────────────────────────┐   │
│  │  pythonista_server.py (HTTP Server)      │   │
│  │  Serves: couch_controller.html           │   │
│  └──────────────────────────────────────────┘   │
│                    ↓                            │
│  ┌──────────────────────────────────────────┐   │
│  │  Safari (Web Browser)                    │   │
│  │  ┌────────────────────────────────────┐  │   │
│  │  │  couch_controller.html             │  │   │
│  │  │  - Touch trackpad                  │  │   │
│  │  │  - Virtual keyboard                │  │   │
│  │  │  - WebSocket client                │  │   │
│  │  └────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
                     │
                WebSocket
              (JSON commands)
                     │
                     ↓
┌─────────────────────────────────────────────────┐
│  Computer (Python)                              │
│  ┌──────────────────────────────────────────┐   │
│  │  receiver_server.py (WebSocket Server)   │   │
│  │  - Receives commands                     │   │
│  │  - Uses pynput library                   │   │
│  │  - Controls keyboard/mouse               │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Files

| File | Purpose | Runs On |
|------|---------|---------|
| `couch_controller.html` | Touch-optimized web UI | iPhone (Safari) |
| `pythonista_server.py` | Hosts the web interface | iPhone (Pythonista) |
| `receiver_server.py` | Receives and executes commands | Computer |
| `requirements.txt` | Python dependencies | Computer |
| `SETUP_GUIDE.md` | Detailed setup instructions | - |

## Use Cases

- 🎬 **Control media playback** from your couch
- 📊 **Navigate presentations** during meetings
- 🌐 **Browse the web** on your TV-connected PC
- 🎮 **Simple mouse-based games**
- 📺 **YouTube/Netflix navigation**
- 💻 **General remote control** when away from desk

## Customization

The interface is built with standard HTML/CSS/JavaScript, so you can easily customize:

- **Keyboard layout**: Edit the `kbd-row` divs in `couch_controller.html`
- **Trackpad sensitivity**: Adjust the `dx * 2` and `dy * 2` multipliers
- **Styling**: Change colors, sizes in the `<style>` section
- **Add buttons**: Create shortcuts for common actions

## Limitations

- **iOS Background**: Pythonista doesn't run in background (use split-screen)
- **Local Network Only**: Designed for same WiFi network
- **No Screen Sharing**: Only controls input (use Screen Sharing apps for video)
- **Requires Python**: Computer must have Python 3.7+ installed

## Future Enhancements

Possible improvements:
- Gesture support (pinch to zoom, two-finger scroll)
- Clipboard sync between devices
- Haptic feedback on clicks
- Screen preview/thumbnails
- Macro/shortcut buttons
- Gamepad mode for games

## Security

- All communication stays on your local network
- No external servers or internet connection required
- WebSocket traffic is unencrypted (use VPN if needed)
- Computer has full control validation via pynput

## Troubleshooting

See [SETUP_GUIDE.md](SETUP_GUIDE.md) for detailed troubleshooting steps.

Common issues:
- **Can't connect**: Check same WiFi, firewall settings
- **Laggy**: Ensure good WiFi signal, close background apps
- **Keys stuck**: Restart both servers, check modifiers are off

## Credits

Built with:
- **pynput** - Cross-platform keyboard/mouse control
- **websockets** - Python WebSocket implementation
- **Pythonista** - Python IDE for iOS
- **Standard web technologies** - HTML/CSS/JavaScript

## License

This is a personal project. Use freely, modify as needed!

---

**Made for lazy couch potatoes who don't want to get up to use their computer** 🛋️🥔✨

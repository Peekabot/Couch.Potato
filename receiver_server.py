"""
Couch Potato Controller - Receiver Server
==========================================
Run this on the computer you want to control from your iPhone.
This receives commands via WebSocket and controls keyboard/mouse.
"""

import asyncio
import websockets
import json
import socket
from pynput import mouse, keyboard
from pynput.mouse import Button, Controller as MouseController
from pynput.keyboard import Key, Controller as KeyboardController

# Configuration
PORT = 8765

# Initialize controllers
mouse_controller = MouseController()
keyboard_controller = KeyboardController()

def get_local_ip():
    """Get the local IP address of this device"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "localhost"

# Key mapping for special keys
KEY_MAP = {
    'Escape': Key.esc,
    'Tab': Key.tab,
    'Backspace': Key.backspace,
    'Enter': Key.enter,
    'Delete': Key.delete,
    'ArrowUp': Key.up,
    'ArrowDown': Key.down,
    'ArrowLeft': Key.left,
    'ArrowRight': Key.right,
    'F1': Key.f1,
    'F2': Key.f2,
    'F3': Key.f3,
    'F4': Key.f4,
    'F5': Key.f5,
    'F6': Key.f6,
    'F7': Key.f7,
    'F8': Key.f8,
    'F9': Key.f9,
    'F10': Key.f10,
    'F11': Key.f11,
    'F12': Key.f12,
    'Home': Key.home,
    'End': Key.end,
    'PageUp': Key.page_up,
    'PageDown': Key.page_down,
    ' ': Key.space,
}

def handle_mouse_move(data):
    """Handle mouse movement"""
    try:
        dx = data.get('dx', 0)
        dy = data.get('dy', 0)

        # Get current position
        current_x, current_y = mouse_controller.position

        # Move mouse
        mouse_controller.position = (current_x + dx, current_y + dy)

    except Exception as e:
        print(f"❌ Mouse move error: {e}")

def handle_mouse_click(data):
    """Handle mouse clicks"""
    try:
        button_name = data.get('button', 'left')

        # Map button name to pynput button
        button_map = {
            'left': Button.left,
            'right': Button.right,
            'middle': Button.middle
        }

        button = button_map.get(button_name, Button.left)

        # Perform click
        mouse_controller.click(button)
        print(f"🖱️  {button_name.title()} click")

    except Exception as e:
        print(f"❌ Mouse click error: {e}")

def handle_key_press(data):
    """Handle keyboard input"""
    try:
        key = data.get('key', '')
        modifiers = data.get('modifiers', {})

        # Collect modifier keys
        mods_to_press = []
        if modifiers.get('ctrl'):
            mods_to_press.append(Key.ctrl)
        if modifiers.get('shift'):
            mods_to_press.append(Key.shift)
        if modifiers.get('alt'):
            mods_to_press.append(Key.alt)
        if modifiers.get('meta'):
            mods_to_press.append(Key.cmd)  # Windows key on Windows, Cmd on Mac

        # Press modifier keys
        for mod in mods_to_press:
            keyboard_controller.press(mod)

        # Press the actual key
        if key in KEY_MAP:
            # Special key
            keyboard_controller.press(KEY_MAP[key])
            keyboard_controller.release(KEY_MAP[key])
        else:
            # Regular character
            keyboard_controller.press(key)
            keyboard_controller.release(key)

        # Release modifier keys
        for mod in reversed(mods_to_press):
            keyboard_controller.release(mod)

        # Log the key press
        key_desc = key if len(key) == 1 else f"<{key}>"
        if mods_to_press:
            mod_names = []
            if modifiers.get('ctrl'):
                mod_names.append('Ctrl')
            if modifiers.get('shift'):
                mod_names.append('Shift')
            if modifiers.get('alt'):
                mod_names.append('Alt')
            if modifiers.get('meta'):
                mod_names.append('⌘')
            print(f"⌨️  {'+'.join(mod_names)}+{key_desc}")
        else:
            print(f"⌨️  {key_desc}")

    except Exception as e:
        print(f"❌ Key press error: {e}")

async def handle_client(websocket, path):
    """Handle WebSocket client connection"""
    client_address = websocket.remote_address[0]
    print(f"\n✅ Client connected from {client_address}")

    try:
        async for message in websocket:
            try:
                # Parse JSON message
                data = json.loads(message)
                msg_type = data.get('type')

                # Route to appropriate handler
                if msg_type == 'mouse_move':
                    handle_mouse_move(data)
                elif msg_type == 'mouse_click':
                    handle_mouse_click(data)
                elif msg_type == 'key_press':
                    handle_key_press(data)
                else:
                    print(f"⚠️  Unknown message type: {msg_type}")

            except json.JSONDecodeError:
                print(f"⚠️  Invalid JSON received")
            except Exception as e:
                print(f"❌ Error handling message: {e}")

    except websockets.exceptions.ConnectionClosed:
        print(f"\n👋 Client disconnected ({client_address})")
    except Exception as e:
        print(f"❌ Connection error: {e}")

async def main():
    """Start the WebSocket server"""
    local_ip = get_local_ip()

    print("=" * 60)
    print("🛋️  Couch Potato Controller - Receiver Server")
    print("=" * 60)
    print(f"\n✅ Server starting on port {PORT}")
    print(f"\n📱 Enter this address in your iPhone app:")
    print(f"   {local_ip}:{PORT}")
    print(f"\n💡 Instructions:")
    print(f"   1. Make sure your iPhone and computer are on the same WiFi")
    print(f"   2. Open the controller on your iPhone")
    print(f"   3. Go to Settings tab")
    print(f"   4. Enter: {local_ip}:{PORT}")
    print(f"   5. Tap Connect")
    print(f"\n⏹️  Press Ctrl+C to stop the server")
    print("=" * 60)
    print("\n📡 Waiting for connections...\n")

    async with websockets.serve(handle_client, "0.0.0.0", PORT):
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    try:
        # Check if pynput is installed
        try:
            import pynput
        except ImportError:
            print("\n❌ Error: pynput library not found!")
            print("   Install it with: pip install pynput")
            print("   Or: pip3 install pynput\n")
            exit(1)

        # Check if websockets is installed
        try:
            import websockets
        except ImportError:
            print("\n❌ Error: websockets library not found!")
            print("   Install it with: pip install websockets")
            print("   Or: pip3 install websockets\n")
            exit(1)

        # Run the server
        asyncio.run(main())

    except KeyboardInterrupt:
        print("\n\n👋 Server stopped")
    except Exception as e:
        print(f"\n❌ Error: {e}")

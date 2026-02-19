"""
Couch Potato Controller - Pythonista Server
============================================
Run this on your iPhone using Pythonista to host the controller interface.
The web interface will be accessible from your iPhone's browser.
"""

import http.server
import socketserver
import socket
import os
import sys
from pathlib import Path

# Configuration
PORT = 8080
HTML_FILE = "couch_controller.html"

def get_local_ip():
    """Get the local IP address of this device"""
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "localhost"

class CouchPotatoHandler(http.server.SimpleHTTPRequestHandler):
    """Custom handler to serve the controller interface"""

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/' or self.path == '/index.html':
            # Serve the controller interface
            self.path = '/' + HTML_FILE

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def log_message(self, format, *args):
        """Custom logging"""
        print(f"[{self.log_date_time_string()}] {format % args}")

def start_server():
    """Start the HTTP server"""
    # Change to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Check if HTML file exists
    if not os.path.exists(HTML_FILE):
        print(f"❌ Error: {HTML_FILE} not found!")
        print(f"   Make sure {HTML_FILE} is in the same directory as this script.")
        sys.exit(1)

    # Get local IP
    local_ip = get_local_ip()

    # Create server
    handler = CouchPotatoHandler

    try:
        with socketserver.TCPServer(("", PORT), handler) as httpd:
            print("=" * 60)
            print("🛋️  Couch Potato Controller Server")
            print("=" * 60)
            print(f"\n✅ Server running on port {PORT}")
            print(f"\n📱 Open on your iPhone:")
            print(f"   http://localhost:{PORT}")
            print(f"   http://{local_ip}:{PORT}")
            print(f"\n💡 Instructions:")
            print(f"   1. Open one of the URLs above in Safari")
            print(f"   2. Go to Settings tab")
            print(f"   3. Enter your computer's IP address")
            print(f"   4. Make sure receiver_server.py is running on your computer")
            print(f"   5. Tap Connect and start controlling!")
            print(f"\n⏹️  Press Ctrl+C to stop the server")
            print("=" * 60)
            print()

            # Serve forever
            httpd.serve_forever()

    except KeyboardInterrupt:
        print("\n\n👋 Server stopped")
        sys.exit(0)
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"\n❌ Error: Port {PORT} is already in use!")
            print(f"   Try closing other programs or use a different port.")
        else:
            print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    start_server()

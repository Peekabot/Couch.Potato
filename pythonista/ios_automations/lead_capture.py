"""
Lead Capture - Pythonista iOS Automation
Scan business cards and send leads to the iSH Flask server.
Run this in Pythonista on iPhone/iPad.
"""

import ui
import requests
import json

# Server URL (change to your iSH server address)
SERVER_URL = "http://localhost:5000"


class LeadScanner(ui.View):
    def __init__(self):
        self.name = "Lead Scanner"
        self.background_color = "white"

        # Scan button
        self.scan_btn = ui.Button(title="Scan Business Card")
        self.scan_btn.action = self.scan_card
        self.scan_btn.frame = (50, 50, 200, 40)
        self.scan_btn.background_color = "#007AFF"
        self.scan_btn.tint_color = "white"
        self.add_subview(self.scan_btn)

        # Manual input field
        self.text_field = ui.TextField(
            placeholder="Or paste text here...",
            frame=(50, 110, 280, 36),
        )
        self.add_subview(self.text_field)

        # Submit button
        self.submit_btn = ui.Button(title="Submit Lead")
        self.submit_btn.action = self.submit_text
        self.submit_btn.frame = (50, 160, 200, 40)
        self.submit_btn.background_color = "#34C759"
        self.submit_btn.tint_color = "white"
        self.add_subview(self.submit_btn)

        # Status label
        self.result_label = ui.Label(frame=(50, 220, 300, 200))
        self.result_label.number_of_lines = 0
        self.result_label.text = "Ready to capture leads."
        self.add_subview(self.result_label)

    def scan_card(self, sender):
        """Pick an image and attempt OCR via clipboard or camera."""
        try:
            import photos
            import clipboard

            img = photos.pick_image()
            if img is None:
                self.result_label.text = "No image selected."
                return

            # In a real implementation, send the image to an OCR service.
            # For now, fall back to whatever is on the clipboard.
            text = clipboard.get() or "No text on clipboard"
            self._send_lead(text, source="camera")
        except ImportError:
            self.result_label.text = "photos/clipboard modules only available in Pythonista."

    def submit_text(self, sender):
        """Send whatever is typed in the text field."""
        text = self.text_field.text.strip()
        if not text:
            self.result_label.text = "Please enter some text first."
            return
        self._send_lead(text, source="manual")

    def _send_lead(self, text, source="unknown"):
        try:
            response = requests.post(
                f"{SERVER_URL}/api/lead",
                json={"text": text, "source": source},
                timeout=5,
            )
            if response.status_code == 200:
                self.result_label.text = f"Lead saved: {text[:60]}..."
            else:
                self.result_label.text = f"Server error {response.status_code}"
        except requests.exceptions.ConnectionError:
            self.result_label.text = "Cannot connect. Start the iSH Flask server first."
        except Exception as e:
            self.result_label.text = f"Error: {e}"


def main():
    v = LeadScanner()
    v.present("sheet")


if __name__ == "__main__":
    main()

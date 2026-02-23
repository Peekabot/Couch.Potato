"""
Business Dashboard - Pythonista iOS UI App
Fetches metrics from the iSH Flask server and displays them in a
native-looking iOS interface.
Run this in Pythonista on iPhone/iPad.
"""

import ui
import requests
import json

SERVER_URL = "http://localhost:5000"


class DashboardView(ui.View):
    def __init__(self):
        self.name = "Business Dashboard"
        self.background_color = "#F2F2F7"
        self._build_ui()

    def _build_ui(self):
        # Title
        title = ui.Label(frame=(0, 20, 375, 40))
        title.text = "Business Dashboard"
        title.font = ("<system-bold>", 20)
        title.alignment = ui.ALIGN_CENTER
        self.add_subview(title)

        # Refresh button
        refresh_btn = ui.Button(title="Refresh")
        refresh_btn.frame = (280, 22, 80, 36)
        refresh_btn.action = self.refresh
        self.add_subview(refresh_btn)

        # Stats table
        self.table = ui.TableView(frame=(0, 70, 375, 300))
        self.table.data_source = self._make_data_source([])
        self.add_subview(self.table)

        # Status label
        self.status_label = ui.Label(frame=(10, 380, 355, 40))
        self.status_label.text = "Tap Refresh to load data."
        self.status_label.number_of_lines = 0
        self.add_subview(self.status_label)

    def _make_data_source(self, items):
        ds = ui.ListDataSource(items)
        return ds

    def refresh(self, sender=None):
        self.status_label.text = "Loading..."
        try:
            resp = requests.get(f"{SERVER_URL}/api/leads", timeout=5)
            leads = resp.json()
            items = [
                f"[{l['source']}] {str(l['data'])[:50]}" for l in leads
            ]
            if not items:
                items = ["No leads yet."]
            self.table.data_source = self._make_data_source(items)
            self.table.reload()
            self.status_label.text = f"{len(leads)} lead(s) loaded."
        except requests.exceptions.ConnectionError:
            self.status_label.text = "Cannot connect. Is the iSH server running?"
        except Exception as e:
            self.status_label.text = f"Error: {e}"


def main():
    v = DashboardView()
    v.present("fullscreen")


if __name__ == "__main__":
    main()

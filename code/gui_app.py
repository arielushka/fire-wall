import json
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from scapy.all import sniff

from firewall import FirewallMonitor, load_json


class FireWallGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Fire Wall")
        self.root.geometry("820x520")

        self.monitor = None
        self.thread = None
        self.stop_capture = threading.Event()
        self.seen_events = set()

        self.count_var = tk.StringVar(value="200")
        self.status_var = tk.StringVar(value="Ready")

        self.build_screen()
        self.show_rules()

    def build_screen(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Packets").pack(side="left")
        ttk.Entry(top, textvariable=self.count_var, width=8).pack(side="left", padx=6)
        ttk.Button(top, text="Start", command=self.start).pack(side="left", padx=4)
        ttk.Button(top, text="Stop", command=self.stop).pack(side="left", padx=4)
        ttk.Label(top, textvariable=self.status_var).pack(side="right")

        tabs = ttk.Notebook(self.root)
        tabs.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.summary_box = tk.Text(tabs, wrap="word")
        self.events_box = tk.Text(tabs, wrap="word")
        self.rules_box = tk.Text(tabs, wrap="none")

        tabs.add(self.summary_box, text="Summary")
        tabs.add(self.events_box, text="Events")
        tabs.add(self.rules_box, text="Rules")

        self.write_box(self.summary_box, "Press Start to capture packets.")

    def start(self):
        if self.thread and self.thread.is_alive():
            messagebox.showinfo("Fire Wall", "Capture is already running.")
            return

        try:
            count = int(self.count_var.get())
        except ValueError:
            messagebox.showerror("Fire Wall", "Packet count must be a number.")
            return

        self.monitor = FirewallMonitor()
        self.seen_events.clear()
        self.stop_capture.clear()
        self.status_var.set("Capturing...")
        self.write_box(self.events_box, "")
        self.update_screen()

        self.thread = threading.Thread(target=self.capture, args=(count,), daemon=True)
        self.thread.start()

    def capture(self, count):
        try:
            sniff(
                prn=self.handle_packet,
                store=False,
                count=count,
                stop_filter=lambda packet: self.stop_capture.is_set(),
            )
            self.root.after(0, lambda: self.status_var.set("Done"))
        except Exception as error:
            self.root.after(0, lambda error=error: messagebox.showerror("Capture error", str(error)))
            self.root.after(0, lambda: self.status_var.set("Error"))

    def handle_packet(self, packet):
        self.monitor.handle_packet(packet)
        self.root.after(0, self.update_screen)

    def stop(self):
        self.stop_capture.set()
        self.status_var.set("Stopping...")

    def update_screen(self):
        if not self.monitor:
            return

        self.write_box(self.summary_box, self.monitor.summary_text())

        lines = []
        for event in self.monitor.events:
            if event["id"] in self.seen_events:
                continue
            self.seen_events.add(event["id"])
            lines.append(
                f"{event['time']} | {event['severity']} | {event['type']} | {event['message']}"
            )

        if lines:
            self.events_box.insert(tk.END, "\n".join(lines) + "\n")

    def show_rules(self):
        files = ["app_settings.json", "firewall_rules.json", "detection_rules.json", "services.json"]
        text = []
        for name in files:
            text.append(name)
            text.append("-" * len(name))
            text.append(json.dumps(load_json(name), indent=4))
            text.append("")
        self.write_box(self.rules_box, "\n".join(text))

    def write_box(self, box, text):
        box.delete("0.0 + 1 lines", tk.END)
        box.insert(tk.END, text)


def main():
    root = tk.Tk()
    FireWallGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()


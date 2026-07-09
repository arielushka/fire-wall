import json
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from scapy.all import sniff

from config_loader import load_app_settings, load_json_config
from sniffer_app import NetworkFirewallApp


RULE_FILES = [
    "app_settings.json",
    "firewall_rules.json",
    "detection_rules.json",
    "services.json",
]


class FirewallGui:
    def __init__(self, root):
        self.root = root
        self.settings = load_app_settings()
        self.app = None
        self.capture_thread = None
        self.stop_capture = threading.Event()
        self.event_ids_on_screen = set()

        self.packet_count = tk.StringVar(value=str(self.settings["packet_count"]))
        self.status = tk.StringVar(value="Ready")

        self.packet_total = tk.StringVar(value="0")
        self.allowed_total = tk.StringVar(value="0")
        self.blocked_total = tk.StringVar(value="0")
        self.alert_total = tk.StringVar(value="0")
        self.event_total = tk.StringVar(value="0")

        self.build_screen()
        self.show_rules()

    def build_screen(self):
        self.root.title("Fire Wall")
        self.root.geometry("920x620")
        self.root.minsize(760, 520)

        self.build_toolbar()

        tabs = ttk.Notebook(self.root)
        tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        dashboard_tab = ttk.Frame(tabs, padding=12)
        events_tab = ttk.Frame(tabs, padding=12)
        rules_tab = ttk.Frame(tabs, padding=12)

        tabs.add(dashboard_tab, text="Dashboard")
        tabs.add(events_tab, text="Events")
        tabs.add(rules_tab, text="Rules")

        self.build_dashboard_tab(dashboard_tab)
        self.build_events_tab(events_tab)
        self.build_rules_tab(rules_tab)

    def build_toolbar(self):
        toolbar = ttk.Frame(self.root, padding=12)
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="Packets").pack(side="left")
        ttk.Entry(toolbar, textvariable=self.packet_count, width=10).pack(
            side="left",
            padx=(6, 12),
        )
        ttk.Button(toolbar, text="Start", command=self.start_capture).pack(
            side="left",
            padx=4,
        )
        ttk.Button(toolbar, text="Stop", command=self.stop_capture_after_next_packet).pack(
            side="left",
            padx=4,
        )
        ttk.Label(toolbar, textvariable=self.status).pack(side="right")

    def build_dashboard_tab(self, parent):
        counters = ttk.Frame(parent)
        counters.pack(fill="x")

        self.add_counter(counters, "Packets", self.packet_total)
        self.add_counter(counters, "Allowed", self.allowed_total)
        self.add_counter(counters, "Blocked", self.blocked_total)
        self.add_counter(counters, "Alerts", self.alert_total)
        self.add_counter(counters, "Events", self.event_total)

        self.summary_text = tk.Text(parent, height=16, wrap="word")
        self.summary_text.pack(fill="both", expand=True, pady=(16, 0))
        self.write_text(self.summary_text, "Start a capture to see results.")

    def add_counter(self, parent, title, value):
        box = ttk.LabelFrame(parent, text=title, padding=10)
        box.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Label(box, textvariable=value, font=("Segoe UI", 18, "bold")).pack()

    def build_events_tab(self, parent):
        columns = ("time", "severity", "action", "type", "flow", "message")
        self.events_table = ttk.Treeview(parent, columns=columns, show="headings")

        widths = {
            "time": 140,
            "severity": 80,
            "action": 90,
            "type": 150,
            "flow": 180,
            "message": 300,
        }

        for column in columns:
            self.events_table.heading(column, text=column.title())
            self.events_table.column(column, width=widths[column], anchor="w")

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.events_table.yview)
        self.events_table.configure(yscrollcommand=scrollbar.set)
        self.events_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def build_rules_tab(self, parent):
        ttk.Button(parent, text="Refresh Rules", command=self.show_rules).pack(
            anchor="w",
            pady=(0, 8),
        )
        self.rules_text = tk.Text(parent, wrap="none")
        self.rules_text.pack(fill="both", expand=True)

    def start_capture(self):
        if self.capture_thread and self.capture_thread.is_alive():
            messagebox.showinfo("Capture running", "A capture is already running.")
            return

        try:
            packets_to_capture = int(self.packet_count.get())
            if packets_to_capture < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid count", "Packet count must be a positive number.")
            return

        self.prepare_new_capture(packets_to_capture)
        self.capture_thread = threading.Thread(
            target=self.capture_packets,
            args=(packets_to_capture,),
            daemon=True,
        )
        self.capture_thread.start()

    def prepare_new_capture(self, packets_to_capture):
        self.stop_capture.clear()
        self.event_ids_on_screen.clear()
        self.clear_events_table()

        settings = dict(self.settings)
        settings["packet_count"] = packets_to_capture
        settings["summary_interval"] = 0

        self.app = NetworkFirewallApp(settings)
        self.status.set("Capturing...")
        self.refresh_dashboard()

    def capture_packets(self, packet_count):
        try:
            sniff(
                prn=self.handle_packet,
                store=False,
                count=packet_count,
                stop_filter=lambda packet: self.stop_capture.is_set(),
            )
            self.root.after(0, lambda: self.status.set("Finished"))
        except Exception as error:
            self.root.after(0, lambda error=error: self.show_capture_error(error))
        finally:
            self.root.after(0, self.refresh_dashboard)

    def handle_packet(self, packet):
        self.app.handle_packet(packet)
        self.root.after(0, self.refresh_dashboard)

    def stop_capture_after_next_packet(self):
        self.stop_capture.set()
        self.status.set("Stopping after next packet...")

    def refresh_dashboard(self):
        if not self.app:
            return

        self.packet_total.set(str(self.app.stats.get_total_packets()))
        self.allowed_total.set(str(self.app.firewall.allowed_count))
        self.blocked_total.set(str(self.app.firewall.blocked_count))
        self.alert_total.set(str(self.app.firewall.alert_count))
        self.event_total.set(str(len(self.app.events.events)))

        self.add_new_events_to_table()
        self.show_summary()

    def add_new_events_to_table(self):
        for event in self.app.events.events:
            if event.event_id in self.event_ids_on_screen:
                continue

            flow = f"{event.src_ip or '-'} -> {event.dst_ip or '-'}"
            self.events_table.insert(
                "",
                "end",
                values=(
                    event.time,
                    event.severity,
                    event.action,
                    event.event_type,
                    flow,
                    event.message,
                ),
            )
            self.event_ids_on_screen.add(event.event_id)

    def show_summary(self):
        lines = [
            f"Packets checked: {self.app.stats.get_total_packets()}",
            f"Allowed: {self.app.firewall.allowed_count}",
            f"Blocked: {self.app.firewall.blocked_count}",
            f"Alerts: {self.app.firewall.alert_count}",
            f"Events file: {self.settings['event_output_file']}",
            "",
            "Top blocked reasons:",
            *self.reason_lines(self.app.firewall.blocked_reasons),
            "",
            "Top alert reasons:",
            *self.reason_lines(self.app.firewall.alert_reasons),
        ]
        self.write_text(self.summary_text, "\n".join(lines))

    def reason_lines(self, reasons):
        if not reasons:
            return ["None"]

        sorted_reasons = sorted(reasons.items(), key=lambda item: item[1], reverse=True)
        return [f"- {count} x {reason}" for reason, count in sorted_reasons[:8]]

    def show_rules(self):
        sections = []
        for file_name in RULE_FILES:
            data = load_json_config(file_name)
            sections.append(f"{file_name}\n{'=' * len(file_name)}")
            sections.append(json.dumps(data, indent=4, ensure_ascii=False))

        if hasattr(self, "rules_text"):
            self.write_text(self.rules_text, "\n\n".join(sections), readonly=False)

    def write_text(self, widget, text, readonly=True):
        widget.config(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        if readonly:
            widget.config(state="disabled")

    def clear_events_table(self):
        for item in self.events_table.get_children():
            self.events_table.delete(item)

    def show_capture_error(self, error):
        self.status.set("Error")
        messagebox.showerror(
            "Capture error",
            f"{error}\n\nTry running as Administrator and make sure Npcap is installed.",
        )


def main():
    root = tk.Tk()
    FirewallGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()

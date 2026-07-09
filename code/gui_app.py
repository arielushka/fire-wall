import json
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from scapy.all import sniff

from config_loader import load_app_settings, load_json_config
from sniffer_app import NetworkFirewallApp


class FirewallGui:
    def __init__(self, root):
        self.root = root
        self.settings = load_app_settings()
        self.app = None
        self.capture_thread = None
        self.stop_capture = threading.Event()
        self.displayed_event_ids = set()

        self.count_var = tk.StringVar(value=str(self.settings["packet_count"]))
        self.status_var = tk.StringVar(value="Ready")
        self.packets_var = tk.StringVar(value="0")
        self.allowed_var = tk.StringVar(value="0")
        self.blocked_var = tk.StringVar(value="0")
        self.alerts_var = tk.StringVar(value="0")
        self.events_var = tk.StringVar(value="0")

        self.build_window()
        self.refresh_rules()

    def build_window(self):
        self.root.title("Anti Virus Network Firewall")
        self.root.geometry("920x620")
        self.root.minsize(760, 520)

        toolbar = ttk.Frame(self.root, padding=12)
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="Packets").pack(side="left")
        ttk.Entry(toolbar, textvariable=self.count_var, width=10).pack(
            side="left",
            padx=(6, 12),
        )
        ttk.Button(toolbar, text="Start", command=self.start_capture).pack(
            side="left",
            padx=4,
        )
        ttk.Button(toolbar, text="Stop", command=self.stop_running_capture).pack(
            side="left",
            padx=4,
        )
        ttk.Label(toolbar, textvariable=self.status_var).pack(side="right")

        tabs = ttk.Notebook(self.root)
        tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        dashboard_tab = ttk.Frame(tabs, padding=12)
        events_tab = ttk.Frame(tabs, padding=12)
        rules_tab = ttk.Frame(tabs, padding=12)

        tabs.add(dashboard_tab, text="Dashboard")
        tabs.add(events_tab, text="Events")
        tabs.add(rules_tab, text="Rules")

        self.build_dashboard(dashboard_tab)
        self.build_events(events_tab)
        self.build_rules(rules_tab)

    def build_dashboard(self, parent):
        counters = ttk.Frame(parent)
        counters.pack(fill="x")

        self.add_counter(counters, "Packets", self.packets_var)
        self.add_counter(counters, "Allowed", self.allowed_var)
        self.add_counter(counters, "Blocked", self.blocked_var)
        self.add_counter(counters, "Alerts", self.alerts_var)
        self.add_counter(counters, "Events", self.events_var)

        self.summary_text = tk.Text(parent, height=16, wrap="word")
        self.summary_text.pack(fill="both", expand=True, pady=(16, 0))
        self.summary_text.insert("1.0", "Start a capture to see results.")
        self.summary_text.config(state="disabled")

    def add_counter(self, parent, label, variable):
        frame = ttk.LabelFrame(parent, text=label, padding=10)
        frame.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Label(frame, textvariable=variable, font=("Segoe UI", 18, "bold")).pack()

    def build_events(self, parent):
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

        scrollbar = ttk.Scrollbar(
            parent,
            orient="vertical",
            command=self.events_table.yview,
        )
        self.events_table.configure(yscrollcommand=scrollbar.set)
        self.events_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def build_rules(self, parent):
        ttk.Button(parent, text="Refresh Rules", command=self.refresh_rules).pack(
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
            packet_count = int(self.count_var.get())
            if packet_count < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid count", "Packet count must be a positive number.")
            return

        self.stop_capture.clear()
        self.displayed_event_ids.clear()
        self.clear_events_table()

        settings = dict(self.settings)
        settings["packet_count"] = packet_count
        settings["summary_interval"] = 0
        self.app = NetworkFirewallApp(settings)
        self.status_var.set("Capturing...")
        self.refresh_dashboard()

        self.capture_thread = threading.Thread(
            target=self.capture_packets,
            args=(packet_count,),
            daemon=True,
        )
        self.capture_thread.start()

    def capture_packets(self, packet_count):
        try:
            sniff(
                prn=self.handle_packet,
                store=False,
                count=packet_count,
                stop_filter=lambda packet: self.stop_capture.is_set(),
            )
            self.root.after(0, lambda: self.status_var.set("Finished"))
        except Exception as error:
            self.root.after(0, lambda error=error: self.show_capture_error(error))
        finally:
            self.root.after(0, self.refresh_dashboard)

    def handle_packet(self, packet):
        self.app.handle_packet(packet)
        self.root.after(0, self.refresh_dashboard)

    def stop_running_capture(self):
        self.stop_capture.set()
        self.status_var.set("Stopping after next packet...")

    def refresh_dashboard(self):
        if not self.app:
            return

        self.packets_var.set(str(self.app.stats.get_total_packets()))
        self.allowed_var.set(str(self.app.firewall.allowed_count))
        self.blocked_var.set(str(self.app.firewall.blocked_count))
        self.alerts_var.set(str(self.app.firewall.alert_count))
        self.events_var.set(str(len(self.app.events.events)))
        self.refresh_event_table()
        self.refresh_summary_text()

    def refresh_event_table(self):
        for event in self.app.events.events:
            if event.event_id in self.displayed_event_ids:
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
            self.displayed_event_ids.add(event.event_id)

    def refresh_summary_text(self):
        lines = [
            f"Packets checked: {self.app.stats.get_total_packets()}",
            f"Allowed: {self.app.firewall.allowed_count}",
            f"Blocked: {self.app.firewall.blocked_count}",
            f"Alerts: {self.app.firewall.alert_count}",
            f"Events file: {self.settings['event_output_file']}",
            "",
            "Top blocked reasons:",
        ]

        lines.extend(self.format_reason_counts(self.app.firewall.blocked_reasons))
        lines.append("")
        lines.append("Top alert reasons:")
        lines.extend(self.format_reason_counts(self.app.firewall.alert_reasons))

        self.summary_text.config(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("1.0", "\n".join(lines))
        self.summary_text.config(state="disabled")

    def format_reason_counts(self, reasons):
        if not reasons:
            return ["None"]

        sorted_reasons = sorted(
            reasons.items(),
            key=lambda item: item[1],
            reverse=True,
        )
        return [f"- {count} x {reason}" for reason, count in sorted_reasons[:8]]

    def refresh_rules(self):
        rule_files = [
            "app_settings.json",
            "firewall_rules.json",
            "detection_rules.json",
            "services.json",
        ]
        sections = []

        for file_name in rule_files:
            data = load_json_config(file_name)
            sections.append(f"{file_name}\n{'=' * len(file_name)}")
            sections.append(json.dumps(data, indent=4, ensure_ascii=False))

        if hasattr(self, "rules_text"):
            self.rules_text.delete("1.0", "end")
            self.rules_text.insert("1.0", "\n\n".join(sections))

    def clear_events_table(self):
        for item in self.events_table.get_children():
            self.events_table.delete(item)

    def show_capture_error(self, error):
        self.status_var.set("Error")
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

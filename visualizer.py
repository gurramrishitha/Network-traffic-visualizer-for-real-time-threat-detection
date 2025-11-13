import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import defaultdict, deque
from scapy.all import sniff, Packet, TCP, UDP, ICMP, IP  # Import specific layers
import threading
import datetime
import csv
import time

# Import from your detector.py
from detector import analyze_packet

neon_colors = ['#39ff14', '#ff073a', '#00ffff', '#ff9ff3', '#feca57', '#5f27cd', '#10ac84', '#f368e0']


class NetworkGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Visualizer & Threat Detector")
        self.root.configure(bg='black')

        # Define protocols to track and plot
        self.protocols_to_track = ["TCP", "UDP", "ICMP", "Other"]
        self.protocol_colors = {
            "TCP": neon_colors[0],
            "UDP": neon_colors[1],
            "ICMP": neon_colors[2],
            "Other": neon_colors[3]
        }

        self.packets_for_export = []  # Store raw packet summaries for export
        self.packet_counts_interval = defaultdict(int)  # Counts per interval
        self.total_packet_counts = defaultdict(int)  # Cumulative counts
        self.protocol_history = defaultdict(lambda: deque(maxlen=60))  # History of cumulative counts (e.g., 60 seconds)

        self.time_points = deque(maxlen=60)  # Max 60 data points on x-axis
        self.running = False
        self.paused = False
        self.start_time = 0

        # Packet display
        self.packet_display_label = tk.Label(root, text="Live Packet Feed:", bg='black', fg='lime',
                                             font=("Arial", 12, "bold"))
        self.packet_display_label.pack(fill=tk.X, pady=(5, 0))
        self.packet_display = scrolledtext.ScrolledText(root, height=8, bg='black', fg='lime', font=("Courier", 9))
        self.packet_display.pack(fill=tk.X, padx=5)

        # Alerts display
        self.alerts_label = tk.Label(root, text="Real-Time Threat Alerts:", bg='black', fg='red',
                                     font=("Arial", 12, "bold"))
        self.alerts_label.pack(fill=tk.X, pady=(5, 0))
        self.alerts_display = scrolledtext.ScrolledText(root, height=4, bg='black', fg='red',
                                                        font=("Courier", 9, "bold"))
        self.alerts_display.pack(fill=tk.X, padx=5)

        # Buttons
        self.button_frame = tk.Frame(root, bg='black')
        self.button_frame.pack(pady=10)

        btn_style = {"width": 10, "font": ("Arial", 10, "bold"), "relief": tk.RAISED, "borderwidth": 2}
        self.start_button = tk.Button(self.button_frame, text="Start", command=self.start_sniffing, bg="#2ecc71",
                                      fg="black", **btn_style)  # Green
        self.stop_button = tk.Button(self.button_frame, text="Stop", command=self.stop_sniffing, bg="#e74c3c",
                                     fg="black", **btn_style)  # Red
        self.pause_button = tk.Button(self.button_frame, text="Pause", command=self.toggle_pause, bg="#f39c12",
                                      fg="black", **btn_style)  # Orange
        self.export_button = tk.Button(self.button_frame, text="Export CSV", command=self.export_csv, bg="#3498db",
                                       fg="black", **btn_style)  # Blue

        self.start_button.grid(row=0, column=0, padx=5)
        self.stop_button.grid(row=0, column=1, padx=5)
        self.pause_button.grid(row=0, column=2, padx=5)
        self.export_button.grid(row=0, column=3, padx=5)

        # Matplotlib plot
        self.figure, self.ax = plt.subplots(facecolor='black')
        self.canvas = FigureCanvasTkAgg(self.figure, master=root)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.setup_plot_style()

    def setup_plot_style(self):
        self.ax.clear()
        self.ax.set_facecolor('black')
        self.ax.tick_params(axis='x', colors='white')
        self.ax.tick_params(axis='y', colors='white')
        self.ax.spines['bottom'].set_color('white')
        self.ax.spines['left'].set_color('white')
        self.ax.spines['top'].set_color('black')  # Hide top/right spines for cleaner look
        self.ax.spines['right'].set_color('black')
        self.ax.set_title("Live Protocol Distribution", color='white', fontsize=14)
        self.ax.set_xlabel("Time (seconds)", color='white', fontsize=10)
        self.ax.set_ylabel("Cumulative Packet Count", color='white', fontsize=10)
        self.ax.grid(True, color='#444444', linestyle='--', linewidth=0.5)  # Darker grid

    def start_sniffing(self):
        if self.running:
            messagebox.showinfo("Info", "Sniffing is already active.")
            return
        self.running = True
        self.paused = False
        self.pause_button.config(text="Pause", bg="#f39c12")  # Reset pause button

        # Clear previous data
        self.packets_for_export = []
        self.packet_counts_interval = defaultdict(int)
        self.total_packet_counts = defaultdict(int)
        self.time_points.clear()
        for proto in self.protocols_to_track:
            self.protocol_history[proto].clear()

        self.packet_display.delete(1.0, tk.END)
        self.alerts_display.delete(1.0, tk.END)

        self.start_time = time.time()

        # Initialize plot starting point (t=0, count=0)
        self.time_points.append(0)
        for proto in self.protocols_to_track:
            self.protocol_history[proto].append(0)
        self.update_plot()  # Show initial empty plot

        self.sniff_thread = threading.Thread(target=self.sniff_packets_thread, daemon=True)
        self.sniff_thread.start()
        self.update_gui_loop()
        self.packet_display.insert(tk.END, "[INFO] Sniffing started...\n")

    def stop_sniffing(self):
        if not self.running:
            return
        self.running = False
        # No need to join sniff_thread if it uses a stoppable sniff call or checks self.running
        self.packet_display.insert(tk.END, "[INFO] Sniffing stopped.\n")
        self.packet_display.see(tk.END)

    def toggle_pause(self):
        if not self.running:
            messagebox.showinfo("Info", "Sniffing is not active.")
            return
        self.paused = not self.paused
        if self.paused:
            self.pause_button.config(text="Resume", bg="#2ecc71")  # Green for Resume
            self.packet_display.insert(tk.END, "[INFO] Sniffing paused.\n")
        else:
            self.pause_button.config(text="Pause", bg="#f39c12")  # Orange for Pause
            self.packet_display.insert(tk.END, "[INFO] Sniffing resumed.\n")
        self.packet_display.see(tk.END)

    def sniff_packets_thread(self):
        # Sniff will call process_packet for each packet
        # The `stop_filter` can be used for cleaner thread termination if needed,
        # or simply relying on self.running check in process_packet is often sufficient.
        sniff(prn=self.process_packet, store=False, stop_filter=lambda p: not self.running)

    def process_packet(self, packet: Packet):
        if not self.running or self.paused:
            return

        # Store for CSV export (consider memory for very long captures)
        # Limiting the stored packets for export might be wise for long runs
        if len(self.packets_for_export) < 20000:  # Example limit
            self.packets_for_export.append(packet)

        # Protocol Identification for Graph
        identified_protocol_for_graph = "Other"  # Default
        if packet.haslayer(TCP):
            identified_protocol_for_graph = "TCP"
        elif packet.haslayer(UDP):
            identified_protocol_for_graph = "UDP"
        elif packet.haslayer(ICMP):
            identified_protocol_for_graph = "ICMP"

        self.packet_counts_interval[identified_protocol_for_graph] += 1

        # Display packet summary in the packet feed
        try:
            now_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            # Provide more details if IP layer exists
            if IP in packet:
                summary = f"[{now_str}] {packet[IP].src} -> {packet[IP].dst} | {packet.summary().split(' / ', 2)[-1]}\n"
            else:
                summary = f"[{now_str}] {packet.summary()}\n"

            self.packet_display.insert(tk.END, summary)
            if self.packet_display.yview()[1] > 0.9:  # Autoscroll if near the end
                self.packet_display.see(tk.END)
        except Exception as e:
            print(f"Error processing packet summary: {e}")

        # Threat Detection - Call analyze_packet from detector.py
        threat_message = analyze_packet(packet)
        if threat_message:
            alert_now_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            full_alert_message = f"[{alert_now_str}] ALERT: {threat_message}\n"
            self.alerts_display.insert(tk.END, full_alert_message)
            if self.alerts_display.yview()[1] > 0.9:  # Autoscroll
                self.alerts_display.see(tk.END)
            # Simple visual feedback for new alert
            original_fg = self.alerts_display.cget("fg")
            self.alerts_display.config(fg="yellow")
            self.root.after(300, lambda: self.alerts_display.config(fg=original_fg))

    def update_gui_loop(self):
        if self.running and not self.paused:
            self.update_graph_data()
        if self.running:  # Keep loop going if running, even if paused (to allow unpausing)
            self.root.after(1000, self.update_gui_loop)  # Update every 1 second

    def update_graph_data(self):
        if not self.running or self.paused:  # Should already be checked by caller, but good practice
            return

        current_relative_time = round(time.time() - self.start_time, 1)
        self.time_points.append(current_relative_time)

        for proto in self.protocols_to_track:
            self.total_packet_counts[proto] += self.packet_counts_interval.get(proto, 0)
            self.protocol_history[proto].append(self.total_packet_counts[proto])

        # print(f"Time: {current_relative_time}, TCP: {self.total_packet_counts['TCP']}, UDP: {self.total_packet_counts['UDP']}, ICMP: {self.total_packet_counts['ICMP']}, Other: {self.total_packet_counts['Other']}")
        # print(f"Interval counts: {dict(self.packet_counts_interval)}")

        self.packet_counts_interval = defaultdict(int)  # Reset for next interval
        self.update_plot()

    def update_plot(self):
        self.setup_plot_style()  # Redraw axes and labels

        plotted_something = False
        for proto in self.protocols_to_track:
            counts = self.protocol_history.get(proto)
            if counts and len(self.time_points) == len(counts):
                # Only plot if there's actual data or it's one of the primary protocols
                if any(c > 0 for c in counts) or proto in ["TCP", "UDP", "ICMP"]:
                    self.ax.plot(list(self.time_points), list(counts), label=proto,
                                 color=self.protocol_colors.get(proto, "#ffffff"), marker='o', markersize=3,
                                 linewidth=1.5)
                    plotted_something = True
            elif counts:
                # This might happen if time_points and counts deques aren't perfectly aligned due to timing.
                # For robustness, plot the minimum available length.
                min_len = min(len(self.time_points), len(counts))
                if min_len > 0:
                    time_data = list(self.time_points)[-min_len:]
                    count_data = list(counts)[-min_len:]
                    if any(c > 0 for c in count_data) or proto in ["TCP", "UDP", "ICMP"]:
                        self.ax.plot(time_data, count_data, label=proto,
                                     color=self.protocol_colors.get(proto, "#ffffff"), marker='o', markersize=3,
                                     linewidth=1.5)
                        plotted_something = True

        if plotted_something and self.ax.get_legend_handles_labels()[1]:  # Check if there are labels to show
            legend = self.ax.legend(loc='upper left', fontsize=8, facecolor='black', labelcolor='white', framealpha=0.7)
            for text in legend.get_texts():
                text.set_color('white')  # Ensure legend text is white
        elif self.ax.get_legend() is not None:  # Clear previous legend if nothing plotted
            self.ax.get_legend().remove()

        self.canvas.draw()

    def export_csv(self):
        if not self.packets_for_export:
            messagebox.showwarning("No Data", "No packets captured in this session to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Save Packet Data As CSV"
        )
        if not file_path:
            return

        try:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                # Header
                writer.writerow(["Timestamp", "Source IP", "Dest IP", "Protocol", "Length", "Summary", "Alert"])

                for pkt_time, pkt, alert_msg in self.generate_export_data():  # Using a generator
                    writer.writerow([pkt_time, pkt.get("src_ip", "N/A"), pkt.get("dst_ip", "N/A"),
                                     pkt.get("proto", "N/A"), pkt.get("len", "N/A"), pkt.get("summary", "N/A"),
                                     alert_msg if alert_msg else ""])
            messagebox.showinfo("Export Successful", f"Packet data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred while exporting:\n{e}")

    def generate_export_data(self):
        """Generator to process packets for export, associating alerts if any occurred around packet time."""
        # This is a simplified association. For precise alert-packet matching,
        # you'd need to store packet timestamps and alert timestamps more granularly.
        # For now, we just re-analyze for the export.
        for packet_obj in self.packets_for_export:
            timestamp = datetime.datetime.fromtimestamp(packet_obj.time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            src_ip, dst_ip, proto_name, length = "N/A", "N/A", "N/A", "N/A"

            if IP in packet_obj:
                src_ip = packet_obj[IP].src
                dst_ip = packet_obj[IP].dst
                length = packet_obj[IP].len

            if TCP in packet_obj:
                proto_name = "TCP"
            elif UDP in packet_obj:
                proto_name = "UDP"
            elif ICMP in packet_obj:
                proto_name = "ICMP"
            else:
                # Try to get a general name
                try:
                    proto_name = packet_obj.name
                except:
                    pass

            summary = packet_obj.summary()
            alert = analyze_packet(packet_obj)  # Re-analyze for export; could also store original alert

            yield timestamp, {"src_ip": src_ip, "dst_ip": dst_ip, "proto": proto_name, "len": length, "summary": summary}, alert
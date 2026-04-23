import psutil
import time
import threading
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from collections import defaultdict

# Alert
class Alert:
    def __init__(self, title, description, risk, mitigation):
        self.title = title
        self.description = description
        self.risk = risk
        self.mitigation = mitigation
        self.time = datetime.now()

alerts = []
connection_tracker = defaultdict(int)
recent_alerts = set()

RISKY_PORTS = [21, 22, 23, 445, 3389]
MAX_CONNECTIONS_PER_IP = 15

running = True
# Alert
def create_alert(title, description, risk, mitigation):
    alert_key = f"{title}-{description}"
    if alert_key in recent_alerts:
        return
    recent_alerts.add(alert_key)
    alert = Alert(title, description, risk, mitigation)
    alerts.append(alert)
    print(f"[ALERT] {title} | Risk: {risk}")

# Network Scanner
def scan_connections():
    connections = psutil.net_connections(kind="inet")

    for conn in connections:
        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            connection_tracker[remote_ip] += 1

            #connections from IP
            if connection_tracker[remote_ip] > MAX_CONNECTIONS_PER_IP:
                create_alert(
                    "Connections Detected",
                    f"High number of connections from {remote_ip}",
                    8,
                    "Enable firewall rate limiting and investigate the remote host to detect the cause of the high level of network connections."
                )

            #Risk Port Usage
            if remote_port in RISKY_PORTS:
                create_alert(
                    "Suspicious Port Activity",
                    f"Connection detected on risky port {remote_port} from {remote_ip}",
                    7,
                    "Disable unnecessary applications and restrict access to sensitive ports to protect sensitive data and information."
                )

            #Unknown External IP
            if not remote_ip.startswith(("192.168.", "10.", "172.16.")):
                create_alert(
                    "External Network Connection",
                    f"Unauthorised connection to external IP {remote_ip}",
                    5,
                    "Verify the use of external connections and apply firewall protection policies."
                )
# Report
def generate_report():
    print("\nGenerating security report...")

    alerts.sort(key=lambda x: x.risk, reverse=True)

    path = "SecurityReport.txt"
    report_text = "---- Network Intrusion Detection System Report ----\n\n"

    if not alerts:
        report_text += "No threats detected.\n"
    else:
        for alert in alerts:
            report_text += f"Time: {alert.time}\n"
            report_text += f"Threat: {alert.title}\n"
            report_text += f"Description: {alert.description}\n"
            report_text += f"Risk Score: {alert.risk}/10\n"
            report_text += f"Mitigation: {alert.mitigation}\n"
            report_text += "-" * 60 + "\n\n"

    with open(path, "w") as file:
        file.write(report_text)

    print(f"Report saved as: {path}")
    return report_text

def start_monitoring():
    global running
    print("---- Network Intrusion Detection System ----")
    print("Monitoring network...\n")
    try:
        while running:
            scan_connections()
            time.sleep(2)
    except KeyboardInterrupt:
        generate_report()

def run_nids():
    start_monitoring()

def start_ids():
    thread = threading.Thread(target=run_nids)
    thread.daemon = True
    thread.start()

def show_report(report_text):
    report_window = tk.Toplevel(root)
    report_window.title("Security Report")
    report_window.geometry("600x500")
    
    text_box = tk.Text(report_window, wrap="word")
    text_box.insert("1.0", report_text)
    text_box.pack(expand=True, fill="both")

def stop_app():
    global running
    print("Stopping Scan")
    running = False
    time.sleep(2)
    print(f"Alerts Identified: {len(alerts)}")
    report_text = generate_report()

    messagebox.showinfo("Report Saved", "Security Report Generated.")
    show_report(report_text)
    print("Security Report Generated.")
    

root = tk.Tk()
root.title("Network Intrusion Detection System Monitor")
root.geometry("300x150")

label = tk.Label(root, text="NIDS Running In Background", font=("Arial",12))
label.pack(pady=20)

start_button = tk.Button(root, text="Start Network Scan", command=start_ids)
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Scan", command=stop_app)
stop_button.pack(pady=5)

root.mainloop()

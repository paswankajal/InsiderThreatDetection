import os
import psutil
import time
import datetime
import sqlite3
import getpass
import tkinter as tk
from tkinter import ttk, messagebox

# --- CONFIG ---
SENSITIVE_DIRS = ["C:/Users/Public/Documents", "C:/ImportantData"]  # Change paths
WORK_HOURS = (9, 18)  # 24-hour format
DB_FILE = "insider_threat_logs.db"

# --- DATABASE SETUP ---
def setup_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                      timestamp TEXT,
                      username TEXT,
                      event_type TEXT,
                      details TEXT)''')
    conn.commit()
    conn.close()

# --- LOGGING FUNCTION ---
def log_event(event_type, details):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs VALUES (?, ?, ?, ?)",
                   (datetime.datetime.now().isoformat(), getpass.getuser(), event_type, details))
    conn.commit()
    conn.close()

# --- MONITORING FUNCTIONS ---
def monitor_file_access():
    for dir_path in SENSITIVE_DIRS:
        if os.path.exists(dir_path):
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    path = os.path.join(root, file)
                    try:
                        access_time = os.path.getatime(path)
                        if time.time() - access_time < 60:
                            log_event("File Access", f"Accessed: {path}")
                    except Exception:
                        pass

def monitor_working_hours():
    current_hour = datetime.datetime.now().hour
    if current_hour < WORK_HOURS[0] or current_hour >= WORK_HOURS[1]:
        log_event("Off-hour Access", f"Accessed system at {current_hour}:00")

def monitor_usb_devices():
    drives = [d.device for d in psutil.disk_partitions() if 'removable' in d.opts]
    for drive in drives:
        log_event("USB Inserted", f"Drive: {drive}")

def monitor_suspicious_processes():
    suspicious = ["cmd.exe", "powershell.exe", "taskkill.exe"]
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() in suspicious:
                log_event("Suspicious Process", f"Process: {proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# --- GUI SETUP ---
def refresh_logs(tree):
    for row in tree.get_children():
        tree.delete(row)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    for row in cursor.fetchall():
        tree.insert("", "end", values=row)
    conn.close()

def start_monitoring():
    setup_db()
    messagebox.showinfo("Insider Threat Tool", "Monitoring started in background. Logs will update every 60 seconds.")

    def run_loop():
        while True:
            monitor_file_access()
            monitor_working_hours()
            monitor_usb_devices()
            monitor_suspicious_processes()
            time.sleep(60)

    import threading
    threading.Thread(target=run_loop, daemon=True).start()

# --- GUI WINDOW ---
def launch_gui():
    setup_db()
    root = tk.Tk()
    root.title("Insider Threat Detection Tool")
    root.geometry("800x400")

    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)

    columns = ("Timestamp", "User", "Event Type", "Details")
    tree = ttk.Treeview(frame, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=200)

    tree.pack(fill="both", expand=True)

    refresh_btn = ttk.Button(root, text="🔄 Refresh Logs", command=lambda: refresh_logs(tree))
    refresh_btn.pack(pady=5)

    start_btn = ttk.Button(root, text="▶ Start Monitoring", command=start_monitoring)
    start_btn.pack(pady=5)

    root.mainloop()

# --- MAIN ---
if __name__ == "__main__":
    launch_gui()

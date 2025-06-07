import wmi
import psutil
import logging
import time
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox



# پیکربندی لاگ‌گیری
logging.basicConfig(
    filename="system_logs.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ایجاد شی WMI
w = wmi.WMI()

blocked_apps = ["Taskmgr.exe", "chrome.exe"]
monitoring = False

def list_processes_gui():
    output_box.delete('1.0', tk.END)
    output_box.insert(tk.END, f"{'PID':<10}{'Name':<25}{'CPU (%)':<10}{'RAM (MB)':<10}\n")
    output_box.insert(tk.END, "-" * 60 + "\n")

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'] or "N/A"
            cpu = proc.info['cpu_percent']
            ram = proc.info['memory_info'].rss / (1024 * 1024)
            output_box.insert(tk.END, f"{pid:<10}{name:<25}{cpu:<10.1f}{ram:<10.1f}\n")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    logging.info("Listed processes via GUI")

def kill_process_gui():
    pid = pid_entry.get()
    try:
        process = w.Win32_Process(ProcessId=int(pid))[0]
        process.Terminate()
        output_box.insert(tk.END, f"Killed {process.Name} (PID: {pid})\n")
        logging.info(f"Killed process via GUI: {process.Name} (PID: {pid})")
    except:
        messagebox.showerror("Error", "Invalid PID or Process not found.")
        logging.warning(f"Failed to kill process with PID: {pid}")

def enforce_restrictions():
    while monitoring:
        for process in w.Win32_Process():
            if process.Name in blocked_apps:
                try:
                    process.Terminate()
                    logging.info(f"Terminated blocked app: {process.Name} (PID: {process.ProcessId})")
                    output_box.insert(tk.END, f"Blocked: {process.Name}\n")
                except:
                    pass
        time.sleep(3)

def start_monitoring():
    global monitoring
    monitoring = True
    thread = threading.Thread(target=enforce_restrictions)
    thread.daemon = True
    thread.start()
    output_box.insert(tk.END, "Monitoring started.\n")
    logging.info("Started monitoring")

def stop_monitoring():
    global monitoring
    monitoring = False
    output_box.insert(tk.END, "Monitoring stopped.\n")
    logging.info("Stopped monitoring")

def show_logs():
    log_window = tk.Toplevel(root)
    log_window.title("Logs")
    log_text = scrolledtext.ScrolledText(log_window, width=80, height=20)
    log_text.pack()
    try:
        with open("system_logs.log", "r") as log_file:
            log_text.insert(tk.END, log_file.read())
    except FileNotFoundError:
        log_text.insert(tk.END, "Log file not found.")

root = tk.Tk()
root.title("System Manager")
root.geometry("600x500")

frame = tk.Frame(root)
frame.pack(pady=10)

btn_list = tk.Button(frame, text="List Processes", command=list_processes_gui)
btn_list.grid(row=0, column=0, padx=5)

tk.Label(frame, text="PID:").grid(row=0, column=1)
pid_entry = tk.Entry(frame)
pid_entry.grid(row=0, column=2)

btn_kill = tk.Button(frame, text="Kill Process", command=kill_process_gui)
btn_kill.grid(row=0, column=3, padx=5)

btn_start = tk.Button(frame, text="Start Monitor", command=start_monitoring)
btn_start.grid(row=1, column=0, pady=5)

btn_stop = tk.Button(frame, text="Stop Monitor", command=stop_monitoring)
btn_stop.grid(row=1, column=1, pady=5)

btn_logs = tk.Button(frame, text="Show Logs", command=show_logs)
btn_logs.grid(row=1, column=2, pady=5)

output_box = scrolledtext.ScrolledText(root, width=70, height=20)
output_box.pack()

root.mainloop()
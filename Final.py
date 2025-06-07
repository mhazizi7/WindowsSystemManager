import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
import threading
import wmi
import logging
from datetime import datetime
import winrm

# ---------- تنظیم لاگ ----------
logging.basicConfig(filename='system_logs.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# ---------- اپلیکیشن‌های مسدود ----------
blocked_apps = ['taskmgr.exe', 'chrome.exe']
monitoring = False

# ---------- توابع محلی ----------
def list_local_processes():
    output_text.delete('1.0', tk.END)
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            output_text.insert(tk.END, f"{info['pid']:>5} | {info['name']:<25} | "
                                       f"CPU: {info['cpu_percent']:.1f}% | RAM: {info['memory_percent']:.1f}%\n")
        except psutil.NoSuchProcess:
            continue

def kill_local_process():
    pid = pid_entry.get()
    if pid.isdigit():
        try:
            p = psutil.Process(int(pid))
            p.terminate()
            log_action(f"Terminated process {p.name()} (PID: {pid})")
            messagebox.showinfo("Success", f"Process {p.name()} terminated.")
            list_local_processes()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Input Error", "Please enter a valid PID.")

def monitor_blocked_apps():
    global monitoring
    while monitoring:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() in blocked_apps:
                    psutil.Process(proc.info['pid']).terminate()
                    log_action(f"Blocked app terminated: {proc.info['name']}")
            except:
                continue

def toggle_monitoring():
    global monitoring
    monitoring = not monitoring
    if monitoring:
        threading.Thread(target=monitor_blocked_apps, daemon=True).start()
        monitor_btn.config(text="Stop Monitoring")
    else:
        monitor_btn.config(text="Start Monitoring")

# ---------- WinRM ----------
def connect_remote(ip, username, password):
    try:
        session = winrm.Session(ip, auth=(username, password))
        return session
    except Exception as e:
        messagebox.showerror("Connection Error", str(e))
        return None

def execute_remote_command():
    ip = ip_entry.get()
    user = user_entry.get()
    pwd = pass_entry.get()
    cmd = cmd_entry.get()
    if not (ip and user and pwd and cmd):
        messagebox.showwarning("Input Error", "Fill in all remote fields.")
        return

    session = connect_remote(ip, user, pwd)
    if session:
        try:
            result = session.run_cmd(cmd)
            output = result.std_out.decode() or result.std_err.decode()
            remote_output.delete('1.0', tk.END)
            remote_output.insert(tk.END, output)
            log_action(f"Executed on {ip}: {cmd}")
            with open(f'remote_{ip.replace(".", "_")}.log', 'a') as f:
                f.write(f"[{datetime.now()}] {cmd}\n{output}\n")
        except Exception as e:
            messagebox.showerror("Command Error", str(e))

# ---------- لاگ ----------
def log_action(action):
    logging.info(action)

def show_logs():
    try:
        with open('system_logs.log', 'r') as f:
            log_data = f.read()
        log_window = tk.Toplevel(root)
        log_window.title("Logs")
        log_text = scrolledtext.ScrolledText(log_window, width=100, height=30)
        log_text.pack()
        log_text.insert(tk.END, log_data)
    except Exception as e:
        messagebox.showerror("Log Error", str(e))

# ---------- GUI ----------
root = tk.Tk()
root.title("System Management")
root.geometry("900x600")
root.configure(bg='#1e1e1e')

style = ttk.Style(root)
style.theme_use("clam")
style.configure("TNotebook", background="#1e1e1e", foreground="white")
style.configure("TFrame", background="#1e1e1e")
style.configure("TLabel", background="#1e1e1e", foreground="white")
style.configure("TButton", background="#444", foreground="white")
style.map("TButton", background=[('active', '#666')])
style.configure("TNotebook.Tab", background="#333", foreground="white")

tab_control = ttk.Notebook(root)

# --- Local Tab ---
local_tab = ttk.Frame(tab_control)
tab_control.add(local_tab, text="Local Management")

ttk.Label(local_tab, text="PID to Kill:").grid(row=0, column=0, padx=5, pady=5)
pid_entry = ttk.Entry(local_tab)
pid_entry.grid(row=0, column=1, padx=5)

ttk.Button(local_tab, text="List Processes", command=list_local_processes).grid(row=1, column=0, padx=5, pady=5)
ttk.Button(local_tab, text="Kill Process", command=kill_local_process).grid(row=1, column=1, padx=5, pady=5)

monitor_btn = ttk.Button(local_tab, text="Start Monitoring", command=toggle_monitoring)
monitor_btn.grid(row=1, column=2, padx=5)

ttk.Button(local_tab, text="Show Logs", command=show_logs).grid(row=1, column=3, padx=5)

output_text = scrolledtext.ScrolledText(local_tab, width=100, height=25, bg="#2e2e2e", fg="white", insertbackground='white')
output_text.grid(row=2, column=0, columnspan=4, padx=10, pady=10)

# --- Remote Tab ---
remote_tab = ttk.Frame(tab_control)
tab_control.add(remote_tab, text="Remote Management")

ttk.Label(remote_tab, text="IP:").grid(row=0, column=0, padx=5, pady=5)
ip_entry = ttk.Entry(remote_tab)
ip_entry.grid(row=0, column=1)

ttk.Label(remote_tab, text="Username:").grid(row=1, column=0, padx=5, pady=5)
user_entry = ttk.Entry(remote_tab)
user_entry.grid(row=1, column=1)

ttk.Label(remote_tab, text="Password:").grid(row=2, column=0, padx=5, pady=5)
pass_entry = ttk.Entry(remote_tab, show="*")
pass_entry.grid(row=2, column=1)

ttk.Label(remote_tab, text="Command:").grid(row=3, column=0, padx=5, pady=5)
cmd_entry = ttk.Entry(remote_tab, width=50)
cmd_entry.grid(row=3, column=1, columnspan=2, sticky="we")

ttk.Button(remote_tab, text="Execute Command", command=execute_remote_command).grid(row=4, column=1, pady=5)

remote_output = scrolledtext.ScrolledText(remote_tab, width=100, height=25, bg="#2e2e2e", fg="white", insertbackground='white')
remote_output.grid(row=5, column=0, columnspan=4, padx=10, pady=10)

tab_control.pack(expand=1, fill="both")

root.mainloop()

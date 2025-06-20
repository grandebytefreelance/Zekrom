import psutil
import json
import threading
import time
import smtplib
from email.message import EmailMessage
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from win10toast import ToastNotifier
import os
import logging
import sqlite3
from logging.handlers import RotatingFileHandler
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import datetime

WINDOWS_SYSTEM_PROCS = {
    "System Idle Process", "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "explorer.exe", "taskhostw.exe",
    "dwm.exe", "spoolsv.exe", "sihost.exe", "fontdrvhost.exe", "SearchUI.exe", "RuntimeBroker.exe"
}

class ConfigManager:
    def __init__(self, config_path="config.json"):
        self.path = config_path
        self.config = {
            "cpu_threshold": 85,
            "ram_threshold": 90,
            "cpu_temp_threshold": 75,
            "ram_temp_threshold": 60,
            "email": "",
            "email_password": "",
            "exception_processes": [],
            "alert_cooldown_seconds": 300,
            "check_interval_seconds": 10,
            "log_file": "system_monitor.log",
            "db_file": "system_monitor.db"
        }
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    loaded = json.load(f)
                    self.config.update(loaded)
            except Exception as e:
                logging.error(f"Config load error: {e}")
        else:
            self.save()

    def save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Config save error: {e}")

    def __getitem__(self, key):
        return self.config.get(key)

    def __setitem__(self, key, value):
        self.config[key] = value

class DatabaseLogger:
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.lock = threading.Lock()
        self.create_tables()

    def create_tables(self):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_metrics (
                timestamp DATETIME PRIMARY KEY,
                cpu_percent REAL,
                ram_percent REAL,
                cpu_temp REAL,
                ram_temp REAL,
                battery_percent REAL,
                battery_plugged INTEGER
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                pid INTEGER,
                process_name TEXT,
                cpu_percent REAL,
                ram_percent REAL,
                action TEXT
            )
            """)
            self.conn.commit()

    def log_system_metrics(self, cpu, ram, cpu_temp, ram_temp, batt_percent, batt_plugged):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO system_metrics(timestamp, cpu_percent, ram_percent, cpu_temp, ram_temp, battery_percent, battery_plugged)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (datetime.datetime.now(), cpu, ram, cpu_temp, ram_temp, batt_percent, int(batt_plugged)))
            self.conn.commit()

    def log_process_event(self, pid, name, cpu, ram, action):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("""
            INSERT INTO process_events(timestamp, pid, process_name, cpu_percent, ram_percent, action)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.datetime.now(), pid, name, cpu, ram, action))
            self.conn.commit()

class EmailSender:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.logger = logging.getLogger("EmailSender")

    def send(self, subject, body):
        def _send():
            try:
                msg = EmailMessage()
                msg.set_content(body)
                msg["Subject"] = subject
                msg["From"] = self.email
                msg["To"] = self.email
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                    smtp.login(self.email, self.password)
                    smtp.send_message(msg)
                self.logger.info(f"Email sent: {subject}")
            except Exception as e:
                self.logger.error(f"Failed to send email: {e}")
        threading.Thread(target=_send, daemon=True).start()

class ProcessManager:
    def __init__(self, config, notifier, db_logger):
        self.config = config
        self.notifier = notifier
        self.db_logger = db_logger
        self.last_alert_time = {}
        self.windows_exceptions = set(proc.lower() for proc in WINDOWS_SYSTEM_PROCS)
        self.lock = threading.Lock()

    def is_exception(self, name):
        if not name:
            return True
        lname = name.lower()
        return (lname in self.windows_exceptions) or (lname in (p.lower() for p in self.config["exception_processes"]))

    def terminate_if_needed(self, proc):
        try:
            name = proc.name()
            lname = name.lower()
            with self.lock:
                cpu_threshold = self.config["cpu_threshold"]
                ram_threshold = self.config["ram_threshold"]
                exceptions = set(p.lower() for p in self.config["exception_processes"])
            if lname in self.windows_exceptions:
                return False
            if lname in exceptions:
                return False
            cpu = proc.cpu_percent(interval=0.1)
            ram = proc.memory_percent()
            if cpu > cpu_threshold or ram > ram_threshold:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except psutil.TimeoutExpired:
                    proc.kill()
                self.notifier.show_toast(f"Terminated {name} (PID {proc.pid}) for high usage")
                logging.info(f"Terminated process {name} (PID {proc.pid}), CPU: {cpu:.1f}%, RAM: {ram:.1f}%")
                self.db_logger.log_process_event(proc.pid, name, cpu, ram, "terminated")
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logging.error(f"Error terminating process: {e}")
        return False

    def alert_exceptions(self, email_sender):
        now = time.time()
        cooldown = self.config["alert_cooldown_seconds"]
        cpu_threshold = self.config["cpu_threshold"]
        ram_threshold = self.config["ram_threshold"]
        for name in self.config["exception_processes"]:
            lname = name.lower()
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pname = proc.info['name']
                    if pname and pname.lower() == lname:
                        cpu = proc.cpu_percent(interval=0.1)
                        ram = proc.memory_percent()
                        key = f"exception_{lname}"
                        if (now - self.last_alert_time.get(key, 0)) > cooldown:
                            if cpu > cpu_threshold or ram > ram_threshold:
                                self.notifier.show_toast(f"Exception process {name} exceeds usage limits!")
                                email_sender.send(
                                    "Exception Process Alert",
                                    f"Exception process {name} (PID {proc.pid}) exceeded limits but was NOT terminated."
                                )
                                self.last_alert_time[key] = now
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    logging.error(f"Error alerting exceptions: {e}")

class BatteryMonitor:
    def __init__(self, notifier, config):
        self.notifier = notifier
        self.config = config
        self.last_battery_percent = None
        self.last_notification_percent = None
        self.lock = threading.Lock()

    def check_battery(self):
        batt = psutil.sensors_battery()
        if not batt:
            return None, None, None, None
        percent = batt.percent
        plugged = batt.power_plugged
        with self.lock:
            if self.last_battery_percent is None:
                self.last_battery_percent = percent
                self.last_notification_percent = None
                return percent, plugged, 0, 0
            cpu_temp, ram_temp = self.get_temperatures()
            if cpu_temp > self.config["cpu_temp_threshold"]:
                self.notifier.show_toast(f"CPU sıcaklığı kritik: {cpu_temp}°C")
            if ram_temp > self.config["ram_temp_threshold"]:
                self.notifier.show_toast(f"RAM sıcaklığı kritik: {ram_temp}°C")
            if not plugged:
                if self.last_notification_percent is None or percent < self.last_notification_percent:
                    if percent <= 20 and percent >= 5:
                        self.notifier.show_toast(f"Şarj seviyesi düşük: %{percent}")
                        self.last_notification_percent = percent
                    elif percent < 5:
                        self.notifier.show_toast(f"Şarj çok düşük: %{percent}")
                        self.last_notification_percent = percent
            self.last_battery_percent = percent
            return percent, plugged, cpu_temp, ram_temp

    def get_temperatures(self):
        temps = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
        cpu_temp = 0
        ram_temp = 0
        for name, entries in temps.items():
            for entry in entries:
                label = entry.label.lower() if entry.label else ""
                if "cpu" in label or "core" in label:
                    cpu_temp = max(cpu_temp, entry.current)
                elif "ram" in label:
                    ram_temp = max(ram_temp, entry.current)
        return cpu_temp, ram_temp

class SystemMonitorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("System Resource Monitor & Process Manager")
        self.config_manager = ConfigManager()
        self.config = self.config_manager.config
        self.setup_logging()
        self.notifier = ToastNotifier()
        self.email_sender = EmailSender(self.config.get("email"), self.config.get("email_password"))
        self.db_logger = DatabaseLogger(self.config["db_file"])
        self.process_manager = ProcessManager(self.config, self.notifier, self.db_logger)
        self.battery_monitor = BatteryMonitor(self.notifier, self.config)
        self.running = False
        self.monitor_thread = None
        self.cpu_usage_history = []
        self.ram_usage_history = []
        self.cpu_temp_history = []
        self.ram_temp_history = []
        self.battery_history = []
        self.battery_plugged_history = []
        self.build_gui()
        self.load_processes()
        self.update_process_list()
        self.master.protocol("WM_DELETE_WINDOW", self.shutdown)

    def setup_logging(self):
        log_file = self.config.get("log_file", "system_monitor.log")
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
        formatter = logging.Formatter('%(asctime)s %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        if not logger.handlers:
            logger.addHandler(handler)

    def build_gui(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

       
        self.tab_overview = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_overview, text="Overview")

        
        self.fig = Figure(figsize=(8, 4), dpi=100)
        self.ax_cpu = self.fig.add_subplot(221)
        self.ax_ram = self.fig.add_subplot(222)
        self.ax_cpu_temp = self.fig.add_subplot(223)
        self.ax_battery = self.fig.add_subplot(224)
        self.fig.tight_layout(pad=2)

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_overview)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        
        self.tab_processes = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_processes, text="Processes")

        proc_frame = ttk.LabelFrame(self.tab_processes, text="Monitored Processes")
        proc_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.proc_tree = ttk.Treeview(proc_frame, columns=("pid", "cpu", "ram"), show="headings")
        self.proc_tree.heading("pid", text="PID")
        self.proc_tree.heading("cpu", text="CPU %")
        self.proc_tree.heading("ram", text="RAM %")
        self.proc_tree.column("pid", width=60)
        self.proc_tree.column("cpu", width=80)
        self.proc_tree.column("ram", width=80)
        self.proc_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ex_frame = ttk.LabelFrame(self.tab_processes, text="Exception Processes (Won't terminate)")
        ex_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ex_listbox = tk.Listbox(ex_frame, height=6)
        self.ex_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(ex_frame)
        btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        ttk.Button(btn_frame, text="Add", command=self.add_exception_process).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="Remove", command=self.remove_exception_process).pack(fill=tk.X, pady=2)

        btn_frame2 = ttk.Frame(self.tab_processes)
        btn_frame2.pack(fill=tk.X, pady=5)
        self.start_btn = ttk.Button(btn_frame2, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame2, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="Save Config", command=self.save_config).pack(side=tk.RIGHT, padx=5)

        self.status_label = ttk.Label(self.master, text="Ready")
        self.status_label.pack(fill=tk.X)

    def add_exception_process(self):
        proc = simpledialog.askstring("Add Exception Process", "Enter process name (e.g. notepad.exe):", parent=self.master)
        if proc:
            proc = proc.strip()
            if proc.lower() not in (p.lower() for p in self.config["exception_processes"]):
                self.config["exception_processes"].append(proc)
                self.ex_listbox.insert(tk.END, proc)

    def remove_exception_process(self):
        selected = self.ex_listbox.curselection()
        if not selected:
            messagebox.showinfo("Info", "Please select a process to remove.")
            return
        index = selected[0]
        proc = self.ex_listbox.get(index)
        self.ex_listbox.delete(index)
        self.config["exception_processes"] = [p for p in self.config["exception_processes"] if p.lower() != proc.lower()]

    def load_processes(self):
        self.ex_listbox.delete(0, tk.END)
        for p in self.config["exception_processes"]:
            self.ex_listbox.insert(tk.END, p)

    def update_process_list(self):
        for i in self.proc_tree.get_children():
            self.proc_tree.delete(i)
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                if not proc.info['name']:
                    continue
                self.proc_tree.insert("", tk.END, values=(
                    proc.info['pid'],
                    f"{proc.cpu_percent(interval=0):.1f}",
                    f"{proc.memory_percent():.1f}"
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if self.running:
            self.master.after(5000, self.update_process_list)

    def monitor(self):
        while self.running:
            try:
                self.config["cpu_threshold"] = int(self.config.get("cpu_threshold", 85))
                self.config["ram_threshold"] = int(self.config.get("ram_threshold", 90))
                self.config["cpu_temp_threshold"] = int(self.config.get("cpu_temp_threshold", 75))
                self.config["ram_temp_threshold"] = int(self.config.get("ram_temp_threshold", 60))

                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory().percent
                cpu_temp, ram_temp = self.battery_monitor.get_temperatures()
                batt_percent, batt_plugged, _, _ = self.battery_monitor.check_battery()

                self.db_logger.log_system_metrics(cpu, ram, cpu_temp, ram_temp, batt_percent or 0, batt_plugged or False)

                self.process_manager.alert_exceptions(self.email_sender)
                for proc in psutil.process_iter():
                    self.process_manager.terminate_if_needed(proc)

                self.cpu_usage_history.append(cpu)
                self.ram_usage_history.append(ram)
                self.cpu_temp_history.append(cpu_temp)
                self.ram_temp_history.append(ram_temp)
                self.battery_history.append(batt_percent or 0)
                self.battery_plugged_history.append(int(batt_plugged) if batt_plugged is not None else 0)

                if len(self.cpu_usage_history) > 60:
                    self.cpu_usage_history.pop(0)
                    self.ram_usage_history.pop(0)
                    self.cpu_temp_history.pop(0)
                    self.ram_temp_history.pop(0)
                    self.battery_history.pop(0)
                    self.battery_plugged_history.pop(0)

                self.update_graphs()

                self.status_label.config(text=f"Monitoring... CPU {cpu:.1f}%, RAM {ram:.1f}%, Battery {batt_percent or 0:.1f}%")

                time.sleep(self.config.get("check_interval_seconds", 10))
            except Exception as e:
                logging.error(f"Monitor loop error: {e}")

    def update_graphs(self):
        times = list(range(-len(self.cpu_usage_history)+1, 1))

        self.ax_cpu.clear()
        self.ax_cpu.plot(times, self.cpu_usage_history, label="CPU %", color="blue")
        self.ax_cpu.set_ylim(0, 100)
        self.ax_cpu.set_title("CPU Usage")
        self.ax_cpu.legend(loc="upper left")

        self.ax_ram.clear()
        self.ax_ram.plot(times, self.ram_usage_history, label="RAM %", color="green")
        self.ax_ram.set_ylim(0, 100)
        self.ax_ram.set_title("RAM Usage")
        self.ax_ram.legend(loc="upper left")

        self.ax_cpu_temp.clear()
        self.ax_cpu_temp.plot(times, self.cpu_temp_history, label="CPU Temp (°C)", color="red")
        self.ax_cpu_temp.set_ylim(0, max(100, max(self.cpu_temp_history, default=0) + 10))
        self.ax_cpu_temp.set_title("CPU Temperature")
        self.ax_cpu_temp.legend(loc="upper left")

        self.ax_battery.clear()
        self.ax_battery.plot(times, self.battery_history, label="Battery %", color="orange")
        self.ax_battery.set_ylim(0, 100)
        self.ax_battery.set_title("Battery Level")
        self.ax_battery.legend(loc="upper left")

        self.canvas.draw_idle()

    def start_monitoring(self):
        if self.running:
            return
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor, daemon=True)
        self.monitor_thread.start()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.update_process_list()
        logging.info("Monitoring started.")

    def stop_monitoring(self):
        if not self.running:
            return
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Monitoring stopped.")
        logging.info("Monitoring stopped.")

    def save_config(self):
        self.config_manager.save()
        messagebox.showinfo("Saved", "Configuration saved successfully.")
        logging.info("Configuration saved by user.")

    def shutdown(self):
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        self.master.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemMonitorApp(root)
    root.mainloop()

import tkinter as tk
from tkinter import messagebox, ttk
import socket
import threading
import random
import time
import logging
from concurrent.futures import ThreadPoolExecutor
import json
import os

# Configure logging
logging.basicConfig(filename='port_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables to control the scanning process
scanning = False
stop_event = threading.Event()
start_time = None

# Define the filename for port services
port_services_file = 'port_services.json'

# Function to check if an IP address is valid
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Function to scan a single port
def scan_port(ip, port, delay):
    if stop_event.is_set():
        return None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        time.sleep(delay)
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Unknown"
            return (port, service)
        return None

# Function to scan multiple ports
def scan_ports(ip, start_port, end_port, num_threads, delay_range):
    global start_time
    open_ports = []
    ports = list(range(start_port, end_port + 1))
    random.shuffle(ports)
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(scan_port, ip, port, random.uniform(*delay_range)) for port in ports]
        for i, future in enumerate(futures):
            result = future.result()
            if result and not stop_event.is_set():
                open_ports.append(result)
            if stop_event.is_set():
                break
            # Update progress bar
            progress_var.set((i + 1) / len(futures) * 100)
            progress_bar.update()
    return open_ports

# Function to format time
def format_time(seconds):
    days = seconds // (24 * 3600)
    seconds %= (24 * 3600)
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return f"{days}d {hours}h {minutes}m {seconds}s"

# Function to start scanning ports
def start_scanning():
    global scanning, start_time
    ip = ip_entry.get()
    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
        num_threads = int(threads_entry.get())
        delay_min = float(delay_min_entry.get())
        delay_max = float(delay_max_entry.get())
        delay_range = (delay_min, delay_max)
        if not is_valid_ip(ip):
            raise ValueError("Invalid IP address")
        if start_port < 0 or end_port < 0 or start_port > end_port:
            raise ValueError("Invalid port range")
        if num_threads <= 0:
            raise ValueError("Number of threads must be positive")
    except ValueError as e:
        messagebox.showerror("Invalid Input", str(e))
        return

    scanning = True
    start_time = time.time()
    stop_event.clear()
    scan_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    progress_var.set(0)

    def run_scan():
        open_ports = scan_ports(ip, start_port, end_port, num_threads, delay_range)
        scanning = False
        elapsed_time = time.time() - start_time
        result_text.insert(tk.END, f"Scan completed in {format_time(elapsed_time)}\n")
        result_text.insert(tk.END, "Open ports:\n")
        for port, service in open_ports:
            result_text.insert(tk.END, f"Port {port}: {service}\n")
        scan_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)
        progress_var.set(0)

    threading.Thread(target=run_scan).start()

# Function to stop scanning ports
def stop_scanning():
    stop_event.set()
    scan_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

# Function to load port services from a file
def load_port_services():
    if os.path.exists(port_services_file):
        with open(port_services_file, 'r') as file:
            return json.load(file)
    return {}

# Function to save port services to a file
def save_port_services(port_services):
    with open(port_services_file, 'w') as file:
        json.dump(port_services, file)

# Function to find the service for a port
def find_service():
    try:
        port = entry.get()
        if not port.isdigit():
            raise ValueError("Port must be a number")
        service = port_services.get(port, 'Unknown Service')
        result_label.config(text=f"Port {port}: {service}")
    except ValueError as e:
        messagebox.showerror("Invalid Input", str(e))

# Function to add a new port-service mapping
def add_service():
    try:
        port = new_port_entry.get()
        service = new_service_entry.get()
        if not port.isdigit():
            raise ValueError("Port must be a number")
        if not service:
            raise ValueError("Service name cannot be empty")
        port_services[port] = service
        save_port_services(port_services)
        messagebox.showinfo("Success", f"Added Port {port} with Service '{service}'")
    except ValueError as e:
        messagebox.showerror("Invalid Input", str(e))

# Load the port services
port_services = load_port_services()

# Create the main window
root = tk.Tk()
root.title("Port Scanner and Service Finder")

# Create a tabbed interface
tab_control = ttk.Notebook(root)
tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)
tab_control.add(tab1, text='Port Scanner')
tab_control.add(tab2, text='Service Finder')
tab_control.pack(expand=1, fill='both')

# Port Scanner tab
tk.Label(tab1, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
ip_entry = tk.Entry(tab1)
ip_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(tab1, text="Start Port:").grid(row=1, column=0, padx=5, pady=5)
start_port_entry = tk.Entry(tab1)
start_port_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(tab1, text="End Port:").grid(row=2, column=0, padx=5, pady=5)
end_port_entry = tk.Entry(tab1)
end_port_entry.grid(row=2, column=1, padx=5, pady=5)

tk.Label(tab1, text="Threads:").grid(row=3, column=0, padx=5, pady=5)
threads_entry = tk.Entry(tab1)
threads_entry.grid(row=3, column=1, padx=5, pady=5)

tk.Label(tab1, text="Min Delay (s):").grid(row=4, column=0, padx=5, pady=5)
delay_min_entry = tk.Entry(tab1)
delay_min_entry.grid(row=4, column=1, padx=5, pady=5)

tk.Label(tab1, text="Max Delay (s):").grid(row=5, column=0, padx=5, pady=5)
delay_max_entry = tk.Entry(tab1)
delay_max_entry.grid(row=5, column=1, padx=5, pady=5)

scan_button = tk.Button(tab1, text="Start Scan", command=start_scanning)
scan_button.grid(row=6, column=0, padx=5, pady=5)

stop_button = tk.Button(tab1, text="Stop Scan", command=stop_scanning, state=tk.DISABLED)
stop_button.grid(row=6, column=1, padx=5, pady=5)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(tab1, variable=progress_var, maximum=100)
progress_bar.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

result_text = tk.Text(tab1, height=15, width=50)
result_text.grid(row=8, column=0, columnspan=2, padx=5, pady=5)

# Service Finder tab
tk.Label(tab2, text="Enter Port Number:").pack(pady=5)
entry = tk.Entry(tab2)
entry.pack(pady=5)
button = tk.Button(tab2, text="Find Service", command=find_service)
button.pack(pady=5)
result_label = tk.Label(tab2, text="")
result_label.pack(pady=5)

# Separator
separator = tk.Frame(tab2, height=2, bd=1, relief=tk.SUNKEN)
separator.pack(fill=tk.X, padx=5, pady=10)

tk.Label(tab2, text="Enter New Port Number:").pack(pady=5)
new_port_entry = tk.Entry(tab2)
new_port_entry.pack(pady=5)

tk.Label(tab2, text="Enter New Service Name:").pack(pady=5)
new_service_entry = tk.Entry(tab2)
new_service_entry.pack(pady=5)

add_button = tk.Button(tab2, text="Add Service", command=add_service)
add_button.pack(pady=5)

# Run the application
root.mainloop()

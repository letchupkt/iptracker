import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import platform
import socket
import uuid
import psutil
import re
import json
import webbrowser as web

# Function to validate the IP address format
def validate_ip(ip):
    ip_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_pattern.match(ip)

# Function to get IP information
def get_ip_info(ip_address):
    try:
        response = requests.get(f'http://ipapi.co/{ip_address}/json')
        ip_info = response.json()
        return ip_info
    except Exception as e:
        return {"error": str(e)}

# Function to get detailed device information
def get_device_info():
    system = platform.system()
    node = platform.node()
    release = platform.release()
    version = platform.version()
    machine = platform.machine()
    processor = platform.processor()
    python_version = platform.python_version()
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])
    fqdn = socket.getfqdn()
    
    uptime = psutil.boot_time()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        'System': system,
        'Node Name': node,
        'Release': release,
        'Version': version,
        'Machine': machine,
        'Processor': processor,
        'Python Version': python_version,
        'Local IP': local_ip,
        'Hostname': hostname,
        'MAC Address': mac_address,
        'FQDN': fqdn,
        'Uptime': uptime,
        'Memory': memory,
        'Disk': disk,
    }

# Function to display information in the UI
def show_info():
    ip_address = ip_entry.get()

    if not validate_ip(ip_address):
        messagebox.showwarning("Input Error", "Please enter a valid IP address.")
        return

    ip_info = get_ip_info(ip_address)
    if "error" in ip_info:
        messagebox.showerror("Error", f"Could not retrieve information: {ip_info['error']}")
        return

    device_info = get_device_info()

    info_text = f"IP Information:\n"
    for key, value in ip_info.items():
        info_text += f"  {key}: {value}\n"

    info_text += "\nDevice Information:\n"
    for key, value in device_info.items():
        info_text += f"  {key}: {value}\n"

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, info_text)
    
    history_list.insert(tk.END, ip_address)

# Function to clear the displayed information
def clear_info():
    output_text.delete(1.0, tk.END)
    ip_entry.delete(0, tk.END)

#contact dev function    
def contact_dev():
    web.open("https://www.instagram.com/letchu_pkt/")    

# Function to export information to a file
def export_info():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                             filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")])
    if not file_path:
        return
    
    content = output_text.get(1.0, tk.END).strip()
    
    if file_path.endswith(".json"):
        try:
            content_dict = {}
            for line in content.splitlines():
                if ": " in line:
                    key, value = line.split(": ", 1)
                    content_dict[key.strip()] = value.strip()
            content = json.dumps(content_dict, indent=4)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export as JSON: {e}")
            return

    with open(file_path, 'w') as file:
        file.write(content)
        
    messagebox.showinfo("Export Successful", f"Information exported to {file_path}")

# Create the main window
root = tk.Tk()
root.title("IP Address Tracker")

# Use ttk for modern UI components
mainframe = ttk.Frame(root, padding="5")
mainframe.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# IP Entry
ttk.Label(mainframe, text="Enter IP Address:", font=("Arial", 14)).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
ip_entry = ttk.Entry(mainframe, width=25, font=("Arial", 14))
ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

# Buttons
buttons_frame = ttk.Frame(mainframe, padding="5")
buttons_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E))

ttk.Button(buttons_frame, text="Track IP", command=show_info, style="TButton").grid(row=0, column=0, padx=5, pady=5)
ttk.Button(buttons_frame, text="Clear", command=clear_info, style="TButton").grid(row=0, column=1, padx=5, pady=5)
ttk.Button(buttons_frame, text="Export", command=export_info, style="TButton").grid(row=0, column=2, padx=5, pady=5)
ttk.Button(buttons_frame, text="Contact dev", command=contact_dev, style="TButton").grid(row=0, column=3, padx=5, pady=5)

# Output Text Box
output_text = tk.Text(mainframe, wrap='word', width=50, height=15, font=("Arial", 12))
output_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))

# Search History
history_frame = ttk.Frame(mainframe, padding="5")
history_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))

ttk.Label(history_frame, text="Search History:", font=("Arial", 14)).grid(row=0, column=0, sticky=tk.W)
history_list = tk.Listbox(history_frame, height=5, font=("Arial", 12))
history_list.grid(row=1, column=0, sticky=(tk.W, tk.E))

# Configure window resizing
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.columnconfigure(0, weight=1)
mainframe.columnconfigure(1, weight=1)

# Start the main event loop
root.mainloop()
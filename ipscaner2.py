import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import socket
import re
import xml.etree.ElementTree as ET
import threading
import ipaddress
import os
import requests
import json

class IPListWindow:
    def __init__(self, main_app):
        self.main_app = main_app
        self.window = tk.Toplevel(main_app.root)
        self.window.title("Saved IP Addresses")
    
        self.ip_listbox = tk.Listbox(self.window, height=15, width=40)
        self.ip_listbox.pack(pady=10)
    
        self.add_button = ttk.Button(self.window, text="+", command=self.add_ip)
        self.add_button.pack(side=tk.LEFT, padx=10)
    
        self.remove_button = ttk.Button(self.window, text="-", command=self.remove_ip)
        self.remove_button.pack(side=tk.LEFT)
    
        self.load_ips()
    
        self.ip_listbox.bind('<Double-1>', self.load_ip_to_main)
    
    def load_ips(self):
        if os.path.exists("pyiplist.txt"):
            with open("pyiplist.txt", "r") as file:
                ips = file.readlines()
            for ip in ips:
                self.ip_listbox.insert(tk.END, ip.strip())
    
    def add_ip(self):
        ip_or_domain = self.main_app.ip_var.get()
        if ip_or_domain:  # проверяем, что строка не пуста
            with open("pyiplist.txt", "a") as file:
                file.write(ip_or_domain + "\n")
            self.ip_listbox.insert(tk.END, ip_or_domain)
    
    def remove_ip(self):
        selected = self.ip_listbox.curselection()
        if selected:
            ip = self.ip_listbox.get(selected)
            self.ip_listbox.delete(selected)
            with open("pyiplist.txt", "r") as file:
                ips = file.readlines()
            ips.remove(ip + "\n")
            with open("pyiplist.txt", "w") as file:
                file.writelines(ips)
    
    def load_ip_to_main(self, event=None):
        selected = self.ip_listbox.curselection()
        if selected:
            ip = self.ip_listbox.get(selected)
            self.main_app.ip_var.set(ip)
            
class HelpWindow:
    """Window to display help for command flags."""
    def __init__(self, main_app):
        self.main_app = main_app
        self.window = tk.Toplevel(main_app.root)
        self.window.title("Command Flag Descriptions")
        
        # Display flag descriptions based on selected function
        function = main_app.function_var.get()
        descriptions = main_app.tooltips_description.get(function, {})
        
        for flag, desc in descriptions.items():
            label = ttk.Label(self.window, text=f"{flag}: {desc}", wraplength=400)
            label.pack(pady=5)          

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(self.tooltip, text=self.text, background="white", borderwidth=1, relief="solid")
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        
        # IP list button
        self.ip_list_button = ttk.Button(root, text="IP List", command=self.open_ip_list)
        self.ip_list_button.grid(row=8, column=0, columnspan=4, pady=10)
        
        self.process = None  # Process handler
        
        # Help button
        ttk.Button(root, text="Help", command=self.open_help).grid(row=9, column=0, columnspan=4, pady=10)

        # IP address input
        ttk.Label(root, text="IP Address:").grid(row=0, column=0, padx=10, pady=10)
        self.ip_var = tk.StringVar()
        ttk.Entry(root, textvariable=self.ip_var).grid(row=0, column=1, padx=10, pady=10)

        # MAC address input (for ARP)
        ttk.Label(root, text="MAC Address:").grid(row=0, column=2, padx=10, pady=10)
        self.mac_var = tk.StringVar()
        ttk.Entry(root, textvariable=self.mac_var).grid(row=0, column=3, padx=10, pady=10)
        
        # Port range input
        ttk.Label(root, text="Port Range (e.g. 20-80):").grid(row=1, column=0, padx=10, pady=10)
        self.port_var = tk.StringVar()
        ttk.Entry(root, textvariable=self.port_var).grid(row=1, column=1, padx=10, pady=10)
        
        # Добавляем метку для отображения внешнего IP-адреса
        self.external_ip_label = ttk.Label(root, text="External IP: Retrieving...")
        self.external_ip_label.grid(row=1, column=2, columnspan=2, pady=10)
        
        # Получаем внешний IP при инициализации
        self.get_external_ip()
        
        # Остановить процесс Button
        ttk.Button(root, text="Stop", command=self.stop_process).grid(row=2, column=2, pady=10)
        
        # Добавляем кнопку для получения внешнего IP
        ttk.Button(root, text="Get External IP", command=self.get_external_ip).grid(row=2, column=3, pady=10)
        
        # SSH details
        ttk.Label(root, text="SSH Login:").grid(row=3, column=0, padx=10, pady=10)
        self.ssh_login_var = tk.StringVar(value="root")
        ttk.Entry(root, textvariable=self.ssh_login_var).grid(row=3, column=1, padx=10, pady=10)
        
        # SSH port input
        ttk.Label(root, text="SSH Port:").grid(row=3, column=2, padx=10, pady=10)
        self.ssh_port_var = tk.StringVar(value="22")  # default SSH port is 22
        ttk.Entry(root, textvariable=self.ssh_port_var).grid(row=3, column=3, padx=10, pady=10)

        # SSH button
        ttk.Button(root, text="Connect via SSH", command=self.ssh_connect).grid(row=10, column=0, columnspan=4, pady=10)
        
        # Checkbox for -debug option
        self.debug_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(root, text="-debug", variable=self.debug_var).grid(row=1, column=2, padx=10, pady=10)
        
        # Checkbox for -type=ns option
        self.type_ns_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(root, text="-type=ns", variable=self.type_ns_var).grid(row=1, column=3, padx=10, pady=10)
        
        # Button to get root NS servers
        ttk.Button(root, text="Get Root NS Servers", command=self.get_root_ns).grid(row=6, column=0, columnspan=4, pady=10)
        
        # Additional options
        ttk.Label(root, text="Options:").grid(row=4, column=2, padx=10, pady=10)
        self.options_var = tk.StringVar()
        self.options_combobox = ttk.Combobox(root, textvariable=self.options_var)
        self.options_combobox.grid(row=4, column=3, padx=10, pady=10)
        
        self.tooltips_description = {
            "arp": {
                "-a": "Displays current ARP entries by interrogating the current protocol data.",
                "-n": "Displays ARP entries in numeric form.",
                "-d": "Deletes the host specified by inet_addr.",
                "-s": "Adds the host and associates the Internet address inet_addr with the Physical address eth_addr."
            },
            "nmap": {
                "": "No additional options",
                "-sP": "Ping scan - Determines if host is up",
                "-sS": "SYN scan - Stealthy scan method",
                "-sV": "Service/version detection",
                "-O": "OS detection"
            },
            "ping": {
                "-c": "Count of packets to send",
                "-t": "Time To Live",
                "-W": "Timeout for response"
            },
            "curl": {
                "-I": "Fetch the headers only.",
                "-L": "Follow redirects.",
                "-X": "Specify HTTP request method.",
                "-d": "Send the specified data in the POST request.",
                "-u": "Specify the user and password to use for authentication.",
                "-A": "User agent string to send to the server.",
                "-b": "Send cookies from the given file as cookie header in HTTP request.",
                "-c": "Save the cookies after the HTTP request is completed.",
                "-e": "Send the given URL in the Referer header.",
                "-H": "Include extra header in the request.",
                "-k": "Allow connections to SSL sites without certs.",
                "-o": "Write output to a file instead of stdout.",
                "-x": "Use the specified proxy."
            },
            "traceroute": {
                "-I": "Use ICMP ECHO for probes.",
                "-A": "Perform AS path lookups in routing registries and print results directly after the corresponding addresses.",
                "-F": "Set the \"don't fragment\" bit.",
                "-m": "Specify maximum TTL. Default is 30.",
                "-p": "Use the specified port number for probes.",
                "-q": "Specify the number of probes per TTL.",
                "-z": "Wait the number of milliseconds between sending probes."
            }
        }
        
        self.tooltips = {
            "-a": "Displays current ARP entries by interrogating the current protocol data.",
            "-n": "Displays ARP entries in numeric form.",
            "-d": "Deletes the host specified by inet_addr.",
            "-s": "Adds the host and associates the Internet address inet_addr with the Physical address eth_addr.",
            "-v": "Verbose mode.",
            "-i": "Specifies the network interface to use for ARP requests.",
            "-D": "Delete an ARP entry with the specified address.",
            "": "No additional options for Nmap.",
            "-sP": "Ping scan - Determines if host is up.",
            "-sS": "SYN scan - Stealthy scan method.",
            "-sV": "Service/version detection.",
            "-O": "OS detection.",
            "-4": "Force using IPv4.",
            "-6": "Force using IPv6.",
            "-a": "Resolve addresses to hostnames.",
            "-n": "Do not resolve addresses to hostnames.",
            "-t": "Answer Time To Live.",
            "-l": "Type Of Service.",
            "-f": "Don't Fragment flag."
        }

        # Function choice
        ttk.Label(root, text="Function:").grid(row=4, column=0, padx=10, pady=10)
        self.function_var = tk.StringVar(value="ping")
        function_combobox = ttk.Combobox(root, textvariable=self.function_var, values=("ping", "arp", "nmap", "network_scan", "nslookup", "curl", "routing_table", "traceroute", "whois", "dig"))
        function_combobox.grid(row=4, column=1, padx=10, pady=10)
        function_combobox.bind("<<ComboboxSelected>>", self.update_options)
        
        # Other function buttons
        ttk.Button(root, text="Network Scan", command=self.initiate_network_scan).grid(row=6, column=0, pady=10)
        ttk.Button(root, text="Port Scan", command=self.scan_ports).grid(row=6, column=1, pady=10)
        ttk.Button(root, text="Wake on LAN", command=self.wake_on_lan).grid(row=6, column=2, pady=10)
        ttk.Button(root, text="Show Routing Table", command=self.show_routing_table).grid(row=6, column=3, pady=10)

        # Results display
        self.results_txt = tk.Text(root, wrap=tk.WORD, width=100, height=23)
        self.results_txt.grid(row=7, column=0, columnspan=4, padx=10, pady=10)
        
        # Command execution buttons
        ttk.Button(root, text="Execute", command=self.execute).grid(row=5, column=0, pady=10)
        ttk.Button(root, text="Save Results", command=self.save_results).grid(row=5, column=1, pady=10)
        ttk.Button(root, text="Clear Results", command=self.clear_results).grid(row=5, column=2, pady=10)
        
        # Binding events
        self.root.bind('<Return>', self.execute_on_enter)
        self.update_options()  # Initial update for options
        
    def get_root_ns(self):
        command = ["nslookup", "-debug", "-type=ns", ".", "8.8.8.8"]
        response = subprocess.run(command, capture_output=True, text=True)
        self.results_txt.insert(tk.END, response.stdout)
        
    def set_tooltip(event):
        value = nmap_combobox.get()
        if value in nmap_tooltips:
            tooltip.text = nmap_tooltips[value]
            tooltip.show_tooltip()
        
        tooltip = ToolTip(nmap_combobox, "")
        nmap_combobox.bind("<<ComboboxSelected>>", set_tooltip)
        
    def set_arp_tooltip(event):
        value = arp_combobox.get()
        if value in arp_tooltips:
            tooltip.text = arp_tooltips[value]
            tooltip.show_tooltip()
    
        tooltip_arp = ToolTip(arp_combobox, "")
        arp_combobox.bind("<<ComboboxSelected>>", set_arp_tooltip)
        
    def update_options(self, event=None):
        function = self.function_var.get()
        
        # Define the options for each function
        options_dict = {
            "arp": ["-a", "-n", "-d", "-s", "-v", "-i", "-D"],
            "nmap": ["", "-sP", "-sS", "-sV", "-O"],
            "ping": ["-4", "-6", "-a", "-n", "-t", "-l", "-f"],
            "curl": ["-I", "-L", "-X", "-d", "-u", "-A", "-b", "-c", "-e", "-H", "-k", "-o", "-x"],
            "traceroute": ["-I", "-A", "-F", "-m", "-p", "-q", "-z"]
            # Add other functions here if they have options
        }
        
        # Define default options for each function
        default_options = {
            "arp": "-a",
            "nmap": "",
            "ping": "",
            "curl": "-I",
            "traceroute": ""
            # Add other functions here if they have default options
        }
        
        # Ensure that 'options' is always initialized
        options = options_dict.get(function, [])
        
        # Update the options combobox based on the selected function
        self.options_combobox["values"] = options
        self.options_var.set(default_options.get(function, ""))  # Set to default or reset if there isn't a default
        
        # Create tooltips for the options
        for option in options:
            tooltip_text = self.tooltips.get(option, "")
            ToolTip(self.options_combobox, tooltip_text)

    def execute(self):
        function = self.function_var.get()
        option = self.options_var.get()  # определение option
        
        if function == "ping":
            threading.Thread(target=self.ping_ip, args=(option,), daemon=True).start()
        elif function == "arp":
            self.arp_mac(option)
        elif function == "nmap":
            self.scan_ports(option)
        elif function == "wake-on-lan":
            self.wake_on_lan()
        elif function == "network_scan":
            ip = self.ip_var.get()
            if not ip.endswith("/24"):
                ip += "/24"
                self.ip_var.set(ip)
            threading.Thread(target=self.scan_network, daemon=True).start()
        elif function == "nslookup":
            self.nslookup_query()    
        elif function == "curl":
            self.execute_curl(self.options_var.get())
        elif function == "routing_table":
            self.show_routing_table()
        elif function == "whois":
            self.whois_query()
        elif function == "dig":
            self.dig_query()
        elif function == "routing_table":
            self.show_routing_table()
        elif function == "traceroute":
            self.execute_traceroute()


    def ping_ip(self, option=None):
        ip = self.ip_var.get()
        command = ["ping"]       
        
        if option:
            command.extend([option, ip])  # Add the option to the command if it's present
        else:
            command.extend(["-c", "4", ip])
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.process = process
        
        while True:
            line = process.stdout.readline()
            if not line:
                break
            self.results_txt.insert(tk.END, line)
            self.results_txt.see(tk.END)  # автоматическая прокрутка до конца
            self.root.update_idletasks()  # обновление интерфейса

    def arp_mac(self):
        mac = self.mac_var.get()
        command = ["arp"]
        if option:
            command.append(option)  # Add the option to the command if it's present
        command.append(mac)
        arp_option = self.arp_options_var.get()
        response = subprocess.run(["arp", arp_option, mac], capture_output=True, text=True)
        self.results_txt.insert(tk.END, response.stdout)

    def scan_ports(self):
        ip = self.ip_var.get()
        port_range = self.port_var.get()
        nmap_options = self.options_var.get()
        
        command = ["nmap", nmap_options, "-p", port_range, ip]
        response = subprocess.run(command, capture_output=True, text=True)
        self.results_txt.insert(tk.END, response.stdout)
        
    def execute_curl(self, option):
        url = self.ip_var.get().strip()  # удаляем пробелы
        if not url:
            messagebox.showerror("Error", "Please enter a URL for curl.")
            return
            
        command = ["curl"]
        if option == "-I":
            command.append("-I")
        elif option == "-L":
            command.append("-L")
        elif option == "-X":
            command.append("-X")
        elif option == "-d":
            command.append("-d")
        elif option == "-u":
            command.append("-u")
        elif option == "-A":
            command.append("-A")
        elif option == "-b":
            command.append("-b")
        elif option == "-c":
            command.append("-c")
        elif option == "-e":
            command.append("-e")
            
        
        command.append(url)
        
        response = subprocess.run(command, capture_output=True, text=True)
        self.results_txt.insert(tk.END, response.stdout)
        
    def execute_on_enter(self, event=None):
        self.execute()

    def initiate_network_scan(self):
        ip = self.get_local_ip()
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        self.ip_var.set(str(network))
        threading.Thread(target=self.scan_network, daemon=True).start()

    def wake_on_lan(self):
        mac_address = self.mac_var.get().replace(':', '')
        data = 'FFFFFFFFFFFF' + mac_address * 16
        send_data = bytes.fromhex(data)
        
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(send_data, ('<broadcast>', 9))
        
        self.results_txt.insert(tk.END, f"Magic packet sent to {self.mac_var.get()}\n")

    def save_results(self):
        file_name = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_name:
            with open(file_name, 'w') as file:
                file.write(self.results_txt.get(1.0, tk.END))
                
    def scan_network(self):
        ip = self.ip_var.get()  # e.g., "192.168.1.0/24"
        command = ["nmap", "-sn", "-oX", "-", ip]
        response = subprocess.run(command, capture_output=True, text=True)
        
        root = ET.fromstring(response.stdout)
        
        for host in root.findall("host"):
            status = host.find("status").get("state")
            if status == "up":
                ip_address = host.find("address[@addrtype='ipv4']").get("addr")
                host_name_elem = host.find("hostnames/hostname")
                host_name = host_name_elem.get("name") if host_name_elem is not None else None
                mac_address_elem = host.find("address[@addrtype='mac']")
                mac_address = mac_address_elem.get("addr") if mac_address_elem is not None else None
                vendor = mac_address_elem.get("vendor") if mac_address_elem is not None else None
                
                # Print results
                self.results_txt.insert(tk.END, f"IP Address: {ip_address}\n")
                if host_name:
                    self.results_txt.insert(tk.END, f"Host Name: {host_name}\n")
                if mac_address:
                    self.results_txt.insert(tk.END, f"MAC Address: {mac_address}\n")
                if vendor:
                    self.results_txt.insert(tk.END, f"Vendor: {vendor}\n")
                self.results_txt.insert(tk.END, "-"*40 + "\n")
    
    
    def nslookup_query(self):
        query = self.ip_var.get()
        if not query:
            messagebox.showerror("Error", "Please enter a domain name for nslookup.")
            return
        
        command = ["nslookup"]
        
        if self.debug_var.get():
            command.append("-debug")
        
        if self.type_ns_var.get():
            command.append("-type=ns")
        
        command.extend([query, "8.8.8.8"])
        
        response = subprocess.run(command, capture_output=True, text=True)
        self.results_txt.insert(tk.END, response.stdout)
        
    def ssh_connect(self):
        ip = self.ip_var.get()
        port = self.ssh_port_var.get()
        user = self.ssh_login_var.get()  # Используем ssh_login_var вместо ssh_user_var
        
        if not all([ip, port, user]):
            messagebox.showerror("Error", "Please fill in all SSH fields.")
            return
        
        try:
            subprocess.Popen(["open", f"ssh://{user}@{ip}:{port}"])
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def get_external_ip(self):
        try:
            response = requests.get('https://httpbin.org/ip', timeout=10)
            response.raise_for_status()
            external_ip = response.json().get('origin')
            self.external_ip_label.config(text=f"External IP: {external_ip}")
        except requests.RequestException:
            self.external_ip_label.config(text="External IP: Failed to retrieve")  
    
    @staticmethod        
    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.254.254.254', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

            
    def show_routing_table(self):
        """Show the system's routing table."""
        try:
            # Check the OS type and execute the corresponding command
            if os.name == "posix":
                response = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
            elif os.name == "nt":
                response = subprocess.run(["route", "print"], capture_output=True, text=True)
            else:
                self.results_txt.insert(tk.END, "Unsupported OS type.\n")
                return
        
            self.results_txt.insert(tk.END, response.stdout)
        except Exception as e:
            self.results_txt.insert(tk.END, f"Error: {e}\n")
            
    def execute_traceroute(self):
        ip = self.ip_var.get()
        command = ["traceroute", ip]
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.process = process
        
        while True:
            line = process.stdout.readline()
            if not line:
                break
            self.results_txt.insert(tk.END, line)
            self.results_txt.see(tk.END)  # автоматическая прокрутка до конца
            self.root.update_idletasks()  # обновление интерфейса
            
    def whois_query(self):
        domain = self.ip_var.get()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name for whois.")
            return
            
        command = ["whois", domain]
        response = subprocess.run(command, capture_output=True, text=True)
        self.results_txt.insert(tk.END, response.stdout)
        
    def dig_query(self):
        domain = self.ip_var.get()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name for dig.")
            return
            
        command = ["dig", domain]
        response = subprocess.run(command, capture_output=True, text=True)
        self.results_txt.insert(tk.END, response.stdout)
            
    def stop_process(self):
        if self.process:
            self.process.terminate()  # Завершает процесс
            self.results_txt.insert(tk.END, "\nProcess terminated by user.\n")
            self.process = None
            
    def clear_results(self):
        self.results_txt.delete(1.0, tk.END) 
        
    def open_ip_list(self):
        IPListWindow(self)
    
    def open_help(self):
        """Open the help window to display flag descriptions."""
        HelpWindow(self)

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    # Bind Enter key to execute_on_enter method
    root.mainloop()

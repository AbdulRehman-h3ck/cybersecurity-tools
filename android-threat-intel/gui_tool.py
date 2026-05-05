import sys
import os

# --- CRASH & RESOURCE FIX FOR PYINSTALLER ---
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

try:
    import androguard.core.resources
    os.environ["ANDROGUARD_RESOURCES"] = os.path.dirname(androguard.core.resources.__file__)
except:
    pass

import tkinter as tk
from tkinter import filedialog, messagebox
import threading
from analyzer import analyze_apk

class APKAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Android Threat Intel - Forensic Lab")
        self.root.geometry("700x550")
        self.root.configure(bg="#1e1e1e")

        # UI Design
        self.title_label = tk.Label(root, text="APK FORENSIC INTELLIGENCE", font=("Courier", 18, "bold"), fg="#00ff00", bg="#1e1e1e")
        self.title_label.pack(pady=20)

        self.btn_select = tk.Button(root, text="BROWSE APK", command=self.select_file, font=("Arial", 10, "bold"), bg="#444", fg="white", width=20)
        self.btn_select.pack(pady=10)

        self.file_label = tk.Label(root, text="No file selected", fg="#aaa", bg="#1e1e1e")
        self.file_label.pack()

        self.btn_analyze = tk.Button(root, text="START ANALYSIS", command=self.start_thread, font=("Arial", 12, "bold"), bg="#008cba", fg="white", width=25, state="disabled")
        self.btn_analyze.pack(pady=20)

        self.console_output = tk.Text(root, height=15, width=80, bg="black", fg="#33ff33", font=("Consolas", 10))
        self.console_output.pack(pady=10, padx=20)

        self.selected_path = ""

    def log(self, message):
        self.console_output.insert(tk.END, message + "\n")
        self.console_output.see(tk.END)

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Android Packages", "*.apk")])
        if file_path:
            # Path normalization for Windows/Linux
            self.selected_path = os.path.normpath(file_path)
            self.file_label.config(text=os.path.basename(self.selected_path), fg="#00ff00")
            self.btn_analyze.config(state="normal")
            self.log(f"[+] Selected: {os.path.basename(self.selected_path)}")

    def start_thread(self):
        self.btn_analyze.config(state="disabled")
        self.console_output.delete(1.0, tk.END)
        self.log("[!] Starting Engine...")
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        results = analyze_apk(self.selected_path)
        
        self.log(f"[*] Package: {results['package_name']}")
        self.log(f"[*] Version: {results['version']}")
        self.log(f"[*] Risk Score: {results['risk_score']}/100")
        self.log("-" * 50)
        self.log(f"VERDICT: {results['verdict']}")
        self.log("-" * 50)
        
        for flag in results['flags']:
            self.log(f" - {flag}")
            
        self.btn_analyze.config(state="normal")
        self.log("\n[+] Done.")

if __name__ == "__main__":
    root = tk.Tk()
    app = APKAnalyzerGUI(root)
    root.mainloop()

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
from analyzer import analyze_apk
from risk_engine import analyze_risk

class APKAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ APK Forensic Intelligence Tool")
        self.root.geometry("700x600")
        self.root.configure(bg="#1e1e1e")

        # --- UI STYLES ---
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Header
        self.header = tk.Label(root, text="APK FORENSIC LAB", font=("Arial", 24, "bold"), bg="#1e1e1e", fg="#3b82f6")
        self.header.pack(pady=20)

        # File Selection Frame
        self.file_frame = tk.Frame(root, bg="#1e1e1e")
        self.file_frame.pack(pady=10, fill="x", padx=40)

        self.path_entry = tk.Entry(self.file_frame, font=("Arial", 12), bg="#2d2d2d", fg="white", insertbackground="white")
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.browse_btn = tk.Button(self.file_frame, text="Browse APK", command=self.browse_file, bg="#3b82f6", fg="white", font=("Arial", 10, "bold"), padx=15)
        self.browse_btn.pack(side="right")

        # Scan Button
        self.scan_btn = tk.Button(root, text="START DEEP ANALYSIS", command=self.start_scan_thread, bg="#ef4444", fg="white", font=("Arial", 12, "bold"), pady=10)
        self.scan_btn.pack(pady=20, padx=40, fill="x")

        # Progress Bar
        self.progress = ttk.Progressbar(root, orient="horizontal", length=100, mode="indeterminate")
        
        # Results Area (Scrollable Text)
        self.result_area = tk.Text(root, font=("Consolas", 10), bg="#000000", fg="#10b981", padx=10, pady=10)
        self.result_area.pack(pady=10, padx=40, fill="both", expand=True)
        
        self.result_area.insert("1.0", "> Waiting for input...")

    def browse_file(self):
        filename = filedialog.askopenfilename(title="Select APK", filetypes=[("APK Files", "*.apk")])
        if filename:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, filename)

    def start_scan_thread(self):
        # Run scan in a separate thread so the GUI doesn't freeze
        apk_path = self.path_entry.get()
        if not apk_path or not os.path.exists(apk_path):
            messagebox.showerror("Error", "Please select a valid APK file first!")
            return
        
        self.scan_btn.config(state="disabled")
        self.result_area.delete("1.0", tk.END)
        self.result_area.insert(tk.END, "🔍 Decompiling & Analyzing APK...\n")
        self.progress.pack(pady=5, padx=40, fill="x")
        self.progress.start()
        
        thread = threading.Thread(target=self.run_analysis, args=(apk_path,))
        thread.start()

    def run_analysis(self, path):
        try:
            # 1. Core Logic
            raw_data = analyze_apk(path)
            if "error" in raw_data:
                self.update_result(f"❌ Error: {raw_data['error']}")
                return

            # 2. Risk Calculation
            report = analyze_risk(raw_data['permissions'], raw_data['urls'])

            # 3. Format Output
            output = f"📦 PACKAGE: {raw_data['package']}\n"
            output += f"🛡️ VERDICT: {report['verdict']}\n"
            output += f"📊 SCORE  : {report['score']}/100\n"
            output += "="*40 + "\n"
            output += "🚩 SECURITY FLAGS:\n"
            for flag in report['flags']:
                output += f" [!] {flag}\n"
            
            self.update_result(output)
        except Exception as e:
            self.update_result(f"❌ Critical Error: {str(e)}")
        finally:
            self.progress.stop()
            self.progress.forget()
            self.scan_btn.config(state="normal")

    def update_result(self, text):
        self.result_area.delete("1.0", tk.END)
        self.result_area.insert(tk.END, text)

if __name__ == "__main__":
    root = tk.Tk()
    app = APKAnalyzerGUI(root)
    root.mainloop()

import sys
import os

# --- NUCLEAR STDOUT FIX (DUMMY STREAM) ---
# Ye hissa sab se upar hona chahiye, kisi bhi import se pehle!
class DummyStream:
    def write(self, x): pass
    def flush(self): pass

if sys.stdout is None:
    sys.stdout = DummyStream()
if sys.stderr is None:
    sys.stderr = DummyStream()

# Ab baaki imports karein
import tkinter as tk
from tkinter import filedialog
import threading

# Yahan analyzer ko import karne se pehle ensure karein ke stdout fix ho chuka hai
try:
    from analyzer import analyze_apk
except Exception as e:
    # Agar phir bhi koi error aaye toh GUI khulne se pehle pata chal jaye
    pass

class APKAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Lab v1.0")
        self.root.geometry("650x500")
        self.root.configure(bg="#121212")

        tk.Label(root, text="APK THREAT ANALYZER", font=("Arial", 16, "bold"), fg="#00ff00", bg="#121212").pack(pady=20)
        
        self.btn_browse = tk.Button(root, text="SELECT APK", command=self.select_file, width=20, bg="#333", fg="white")
        self.btn_browse.pack(pady=10)

        self.lbl_status = tk.Label(root, text="Waiting for input...", fg="#888", bg="#121212")
        self.lbl_status.pack()

        self.console = tk.Text(root, height=12, width=70, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.console.pack(pady=20, padx=20)

        self.btn_run = tk.Button(root, text="START SCAN", command=self.run_task, state="disabled", bg="#005f73", fg="white")
        self.btn_run.pack(pady=10)

        self.file_path = ""

    def log(self, text):
        self.console.insert(tk.END, text + "\n")
        self.console.see(tk.END)

    def select_file(self):
        path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        if path:
            self.file_path = os.path.normpath(path)
            self.lbl_status.config(text=os.path.basename(self.file_path), fg="#00ff00")
            self.btn_run.config(state="normal")
            self.log(f"[+] Loaded: {os.path.basename(self.file_path)}")

    def run_task(self):
        self.btn_run.config(state="disabled")
        self.console.delete(1.0, tk.END)
        self.log("[!] Starting Analysis...")
        threading.Thread(target=self.process, daemon=True).start()

    def process(self):
        try:
            res = analyze_apk(self.file_path)
            self.log(f"[*] Package: {res['package_name']}")
            self.log(f"[*] Score: {res['risk_score']}/100")
            self.log("-" * 40)
            self.log(f"RESULT: {res['verdict']}")
            self.log("-" * 40)
            for f in res['flags']: self.log(f" - {f}")
        except Exception as e:
            self.log(f"[ERROR]: {str(e)}")
        finally:
            self.btn_run.config(state="normal")

if __name__ == "__main__":
    root = tk.Tk()
    app = APKAnalyzerGUI(root)
    root.mainloop()

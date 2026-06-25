import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import json
import webbrowser
import os
from pathlib import Path
from fpdf import FPDF 

# Matplotlib for Analytical Dashboards
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Backend Imports
from analyzer import APKAnalyzer
from risk_engine import ThreatIntelligenceEngine
from database import ThreatDatabase
from threat_graph import VisualThreatGraph
from cert_hunter import CertificateHunter
from ai_summarizer import AIReportSummarizer
from osint_hunter import OSINTHunter  # <--- NAYA OSINT HUNTER IMPORT

# --- Theme Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ThreatIntelGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Android Threat Intelligence Platform v2.0")
        self.geometry("950x680")
        self.minsize(800, 500)
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # INITIALIZING ALL ENGINES
        self.engine = ThreatIntelligenceEngine() 
        self.db = ThreatDatabase()
        self.ai_summarizer = AIReportSummarizer()
        self.osint = OSINTHunter() # <--- OSINT ENGINE INITIALIZED

        self.selected_file = None
        self.latest_report_text = "" 
        self.latest_raw_report = {} 
        self.latest_graph_file = "" 

        self._build_sidebar()
        self._build_main_frame()

    def _build_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="SOC Dashboard\n🛡️", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        self.btn_scan = ctk.CTkButton(self.sidebar_frame, text="🔍 New Scan", fg_color="#2a9d8f", hover_color="#21867a", command=self.reset_ui)
        self.btn_scan.grid(row=1, column=0, padx=20, pady=10)

        self.btn_history = ctk.CTkButton(self.sidebar_frame, text="📚 Threat History", command=self.show_history)
        self.btn_history.grid(row=2, column=0, padx=20, pady=10)

        self.btn_analytics = ctk.CTkButton(self.sidebar_frame, text="📊 Analytics Visuals", command=self.show_analytics, fg_color="#8338ec", hover_color="#3a0ca3")
        self.btn_analytics.grid(row=3, column=0, padx=20, pady=10)

        self.btn_graph = ctk.CTkButton(self.sidebar_frame, text="🕸️ Threat Graph", command=self.show_graph, state="disabled", fg_color="#fca311", hover_color="#e59800")
        self.btn_graph.grid(row=4, column=0, padx=20, pady=10)

        self.btn_export = ctk.CTkButton(self.sidebar_frame, text="📄 Export PDF", command=self.export_pdf, state="disabled", fg_color="#d62828", hover_color="#ae2012")
        self.btn_export.grid(row=5, column=0, padx=20, pady=10)

        self.btn_export_json = ctk.CTkButton(self.sidebar_frame, text="🏭 Export SIEM (JSON)", command=self.export_json, state="disabled", fg_color="#e07a5f", hover_color="#81b29a")
        self.btn_export_json.grid(row=6, column=0, padx=20, pady=10)

        self.btn_exit = ctk.CTkButton(self.sidebar_frame, text="❌ Exit", fg_color="#e63946", hover_color="#b52b36", command=self.destroy)
        self.btn_exit.grid(row=8, column=0, padx=20, pady=20)

    def _build_main_frame(self):
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(5, weight=1)

        self.lbl_title = ctk.CTkLabel(self.main_frame, text="Target APK Analysis", font=ctk.CTkFont(size=24, weight="bold"))
        self.lbl_title.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.btn_browse = ctk.CTkButton(self.main_frame, text="📁 Select APK File", command=self.select_file, width=200, height=40)
        self.btn_browse.grid(row=1, column=0, padx=20, pady=10)

        self.lbl_status = ctk.CTkLabel(self.main_frame, text="Waiting for target...", text_color="gray")
        self.lbl_status.grid(row=2, column=0, padx=20, pady=5)

        # 🔥 FAST VS DEEP SCAN SELECTOR
        self.scan_mode_var = ctk.StringVar(value="⚡ Fast Scan (10s)")
        self.scan_mode_selector = ctk.CTkSegmentedButton(
            self.main_frame, 
            values=["⚡ Fast Scan (10s)", "🧬 Deep JADX Scan (5m+)"], 
            variable=self.scan_mode_var,
            selected_color="#d62828",
            selected_hover_color="#ae2012"
        )
        self.scan_mode_selector.grid(row=3, column=0, padx=20, pady=5)

        # 🔥 JADX MINI PROGRESS BAR
        self.jadx_progressbar = ctk.CTkProgressBar(self.main_frame, mode="indeterminate", height=6, width=250, progress_color="#fca311")
        self.jadx_progressbar.grid(row=4, column=0, padx=20, pady=5)
        self.jadx_progressbar.set(0)
        self.jadx_progressbar.grid_remove() # Hide initially

        self.console = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Consolas", size=13), text_color="#00FF00", fg_color="#0a0a0a", corner_radius=8)
        self.console.grid(row=5, column=0, padx=20, pady=10, sticky="nsew")
        self.console.insert("0.0", "[*] System Ready. Awaiting APK upload...\n")
        self.console.configure(state="disabled")

        self.progressbar = ctk.CTkProgressBar(self.main_frame, mode="indeterminate", height=10)
        self.progressbar.grid(row=6, column=0, padx=20, pady=(0, 10), sticky="ew")
        self.progressbar.set(0)

        self.btn_start = ctk.CTkButton(self.main_frame, text="🚀 INITIATE THREAT SCAN", command=self.start_scan, state="disabled", fg_color="#005f73", hover_color="#0a9396", height=45, font=ctk.CTkFont(weight="bold"))
        self.btn_start.grid(row=7, column=0, padx=20, pady=(0, 20))

    def reset_ui(self):
        """Resets the UI for a new scan"""
        self.selected_file = None
        self.lbl_status.configure(text="Waiting for target...", text_color="gray")
        self.btn_start.configure(state="disabled", text="🚀 INITIATE THREAT SCAN")
        self.btn_export.configure(state="disabled")
        self.btn_export_json.configure(state="disabled")
        self.btn_graph.configure(state="disabled")
        self.console.configure(state="normal")
        self.console.delete("0.0", "end")
        self.console.insert("0.0", "[*] System Ready. Awaiting APK upload...\n")
        self.console.configure(state="disabled")

    def log(self, text):
        """Thread-safe way to update the UI text box"""
        self.after(0, self._safe_log, text)

    def _safe_log(self, text):
        self.console.configure(state="normal")
        self.console.insert("end", text + "\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    def select_file(self):
        path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        if path:
            self.selected_file = Path(path).resolve()
            self.lbl_status.configure(text=f"Target: {self.selected_file.name}", text_color="#00FF00")
            self.btn_start.configure(state="normal")
            
            self.btn_export.configure(state="disabled") 
            self.btn_export_json.configure(state="disabled")
            self.btn_graph.configure(state="disabled")
            
            self.console.configure(state="normal")
            self.console.delete("0.0", "end")
            self.console.configure(state="disabled")
            self.log(f"[+] Target loaded: {self.selected_file.name}")

    def start_scan(self):
        self.btn_start.configure(state="disabled", text="SCANNING...")
        self.btn_browse.configure(state="disabled")
        self.scan_mode_selector.configure(state="disabled")
        self.progressbar.start()

        selected_mode = self.scan_mode_var.get()
        mode_str = "DEEP (JADX)" if "Deep" in selected_mode else "FAST (Bytecode)"
        self.log(f"\n[!] Initiating Threat Intelligence Core... [Mode: {mode_str}]")
        
        if "Deep" in selected_mode:
            self.jadx_progressbar.grid()
            self.jadx_progressbar.start()
            self.log("[*] Note: Deep Scan selected. JADX engine is decompiling Java classes...")

        # Run backend logic in a separate thread so UI doesn't freeze
        threading.Thread(target=self.process_apk, args=(selected_mode,), daemon=True).start()

    def process_apk(self, selected_mode):
        try:
            self.log("[*] Phase 1: Extracting Manifest & Fingerprinting...")
            analyzer_instance = APKAnalyzer()
            
            is_deep_scan = True if "Deep" in selected_mode else False
            apk_data = analyzer_instance.analyze(str(self.selected_file), deep_scan=is_deep_scan)

            cert_hunter = CertificateHunter(self.selected_file)
            apk_cert_hash = cert_hunter.get_certificate_hash()
            self.log(f"[+] Cert SHA-256: {apk_cert_hash[:20]}...")

            # Hide JADX progress bar if it was active
            self.after(0, self.jadx_progressbar.stop)
            self.after(0, self.jadx_progressbar.grid_remove)

            if not apk_data:
                self._update_ui_post_scan("[-] ERROR: Extraction Failed.")
                return

            self.log("[*] Phase 2: Running Behavioral Rules, ML Prediction & Domain Intel...")
            report = self.engine.analyze(apk_data)
            self.latest_raw_report = report 

            self.log("[*] Phase 3: Generating Visual Threat Graph...")
            graph_maker = VisualThreatGraph(self.selected_file.name)
            self.latest_graph_file = f"graph_{self.selected_file.name}.html"
            graph_maker.generate_report(
                permissions=apk_data.get('permissions', []), 
                urls=apk_data.get('urls', []), 
                secrets=apk_data.get('secrets', {}),
                output_filename=self.latest_graph_file
            )

            self.log("[*] Phase 4: Archiving and Clustering in Threat Intel Database...")
            self.db.save_scan(
                package_name=apk_data.get('package_name', 'Unknown'),
                score=report['score'],
                verdict=report['verdict'],
                confidence=report['confidence'],
                traits_list=report['threat_personality'],
                cert_hash=apk_cert_hash
            )

            family_matches = self.db.check_cert_family(apk_cert_hash)

            # --- DYNAMIC REPORT GENERATION ---
            rep_str = []
            rep_str.append("==================================================")
            rep_str.append("        FINAL APK THREAT INTELLIGENCE REPORT      ")
            rep_str.append("==================================================")
            rep_str.append(f"[*] Package   : {apk_data.get('package_name', 'Unknown')}")
            rep_str.append(f"[*] Score     : {report['score']}/100")
            rep_str.append(f"[*] VERDICT   : {report['verdict']}")
            rep_str.append(f"[*] Confidence: {report['confidence']}")
            rep_str.append(f"[*] ML Model  : {report.get('ai_prediction', 'N/A')} (RandomForest)")
            
            self.log("[*] Phase 5: Generating AI Executive Summary via Provider...")
            executive_summary = self.ai_summarizer.generate_summary(report)
            
            rep_str.append("\n[🤖] CISO EXECUTIVE SUMMARY (AI-GENERATED):")
            rep_str.append(f"  {executive_summary}")
            
            rep_str.append("\n[>] THREAT PERSONALITY (DNA):")
            if report['threat_personality']:
                for trait in report['threat_personality']:
                    rep_str.append(f"  - {trait}")
            else:
                rep_str.append("  - None detected.")
                
            rep_str.append("\n[>] MALWARE FAMILY CLUSTERING (DNA MATCH):")
            rep_str.append(f"  - Cert Fingerprint: {apk_cert_hash}")
            if len(family_matches) > 1 and apk_cert_hash not in ["UNKNOWN", "UNSIGNED_OR_NOT_FOUND", "ERROR_EXTRACTING_CERT"]:
                rep_str.append("  [🚨] WARNING: Known Threat Actor Infrastructure Detected!")
                for match in family_matches:
                    if match['package_name'] != apk_data.get('package_name', 'Unknown'):
                        rep_str.append(f"       -> {match['package_name']} (Verdict: {match['verdict']}, Scanned on: {match['date']})")
            else:
                rep_str.append("  - No previous apps found with this signature. (Unique)")

            # Domain & IP Intel Processing
            dom_intel = report.get('domain_intel', {})
            ip_intel_data = apk_data.get('ip_intel', {})

            # --- SUSPICIOUS IPs, LOCATIONS & OSINT INTELLIGENCE (NEW!) ---
            rep_str.append("\n[>] SUSPICIOUS IPs, LOCATIONS & LIVE OSINT:")
            hardcoded_ips = dom_intel.get('hardcoded_ips', [])
            
            if ip_intel_data or hardcoded_ips:
                self.log("[*] Running Live OSINT Scans (AbuseIPDB, OTX, Shodan) on extracted IPs...")
                processed_ips = set()
                
                def process_ip_report(ip):
                    if ip in processed_ips: return
                    processed_ips.add(ip)
                    
                    loc_str = "Location/ISP Unknown"
                    if ip in ip_intel_data:
                        loc = ip_intel_data[ip]
                        loc_str = f"{loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')} (ISP: {loc.get('isp', 'Unknown')})"
                    
                    # Live OSINT Scan
                    rep_str.append(f"  [🌍] IP: {ip} -> {loc_str}")
                    osint_res = self.osint.full_ip_scan(ip)
                    
                    if osint_res['status'] == 'private_ip':
                        rep_str.append("      -> [Internal/Private IP - Skipped OSINT]")
                    else:
                        # AbuseIPDB Result
                        if osint_res.get('abuseipdb'):
                            score = osint_res['abuseipdb']['abuse_score']
                            if score > 0:
                                rep_str.append(f"      -> [🚨] AbuseIPDB: Malicious! (Score: {score}%, Reports: {osint_res['abuseipdb']['total_reports']})")
                            else:
                                rep_str.append("      -> [✅] AbuseIPDB: Clean")
                                
                        # AlienVault OTX Result
                        if osint_res.get('otx'):
                            pulses = osint_res['otx']['otx_pulses']
                            if pulses > 0:
                                rep_str.append(f"      -> [🚨] AlienVault OTX: Found in {pulses} Threat Pulses!")
                            else:
                                rep_str.append("      -> [✅] AlienVault OTX: No Threat Pulses")
                                
                        # Shodan Result
                        if osint_res.get('shodan'):
                            ports = osint_res['shodan']['ports']
                            vulns = osint_res['shodan']['vulns']
                            if ports:
                                rep_str.append(f"      -> [🔍] Shodan Open Ports: {ports}")
                            if vulns:
                                rep_str.append(f"      -> [💀] Shodan CVEs Found: {', '.join(vulns[:3])}")
                                
                # Scan Hardcoded IPs first
                for ip in hardcoded_ips:
                    process_ip_report(ip)
                        
                # Scan any other external lookup IPs
                for ip in ip_intel_data.keys():
                    process_ip_report(ip)
            else:
                rep_str.append("  - No suspicious IPs or locations detected.")

            # --- NETWORK & DOMAIN INTELLIGENCE ---
            rep_str.append("\n[>] NETWORK & DOMAIN INTELLIGENCE:")
            found_network_risks = False
            
            if dom_intel.get('tunneling_detected'):
                found_network_risks = True
                rep_str.append(f"  [🚨] Tunneling (C2) Detected: {', '.join(dom_intel['tunneling_detected'])}")
            if dom_intel.get('ddns_detected'):
                found_network_risks = True
                rep_str.append(f"  [🔴] Dynamic DNS Detected: {', '.join(dom_intel['ddns_detected'])}")
            if dom_intel.get('abused_platforms'):
                found_network_risks = True
                rep_str.append(f"  [🟠] Abused Platforms: {', '.join(dom_intel['abused_platforms'])}")
            if dom_intel.get('suspicious_tlds'):
                found_network_risks = True
                rep_str.append(f"  [🟡] Suspicious Domains: {', '.join(dom_intel['suspicious_tlds'])}")
            
            if not found_network_risks:
                 rep_str.append(f"  - No high-risk domains or C2 infrastructure identified. Extracted {len(dom_intel.get('unique_domains', []))} normal domains.")

            # OWASP & Hidden Payloads
            if report.get('owasp_vulns') or report.get('hidden_payloads'):
                rep_str.append("\n[>] VULNERABILITIES & PAYLOADS:")
                for vuln in report.get('owasp_vulns', []):
                    rep_str.append(f"  [!] OWASP: {vuln}")
                for payload in report.get('hidden_payloads', []):
                    rep_str.append(f"  [!] PAYLOAD: {payload}")

            rep_str.append("\n[>] EXPOSED SECRETS & API KEYS:")
            if report.get('secrets'):
                for sec_type, vals in report['secrets'].items():
                    rep_str.append(f"  [!] {sec_type} Found:")
                    for v in vals[:3]: 
                        rep_str.append(f"      -> {v}")
            else:
                rep_str.append("  - No hardcoded secrets found.")

            rep_str.append("\n[>] ATTACK CHAIN RECONSTRUCTION:")
            for step in report['attack_chain']:
                rep_str.append(f"  {step}")
                
            rep_str.append("\n[>] RED FLAGS DETECTED:")
            if report['flags']:
                for flag in report['flags']:
                    rep_str.append(f"  ! {flag}")
            else:
                rep_str.append("  - No significant red flags.")
            rep_str.append("==================================================")

            self.latest_report_text = "\n".join(rep_str)

            self.log("\n" + self.latest_report_text)
            self._update_ui_post_scan("[+] Scan Complete. Data archived in Threat History.")
            
        except Exception as e:
            self.after(0, self.jadx_progressbar.stop)
            self.after(0, self.jadx_progressbar.grid_remove)
            self.log(f"\n[-] FATAL ERROR: {str(e)}")
            self._update_ui_post_scan("[-] Scan Failed due to internal error.")

    def _update_ui_post_scan(self, msg):
        self.after(0, self._reset_buttons, msg)

    def _reset_buttons(self, msg):
        self.progressbar.stop()
        self.btn_start.configure(state="normal", text="🚀 INITIATE THREAT SCAN")
        self.btn_browse.configure(state="normal")
        self.scan_mode_selector.configure(state="normal")
        self.btn_export.configure(state="normal") 
        self.btn_export_json.configure(state="normal") 
        self.btn_graph.configure(state="normal") 
        self.log(f"\n{msg}")

    def show_graph(self):
        if self.latest_graph_file and os.path.exists(self.latest_graph_file):
            file_url = f"file://{os.path.abspath(self.latest_graph_file)}"
            webbrowser.open(file_url)
            self.log(f"\n[+] Interactive Graph opened in your browser.")
        else:
            self.log("[-] Graph file not found. Run a scan first.")

    def export_pdf(self):
        if not self.latest_report_text: return
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], initialfile=f"Threat_Report_{self.selected_file.name}.pdf")
        if not file_path: return
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Courier", size=10) 
            # Note: encode('ascii', 'ignore') removes emojis so FPDF doesn't crash
            clean_text = self.latest_report_text.encode('ascii', 'ignore').decode('ascii')
            for line in clean_text.split('\n'):
                pdf.multi_cell(0, 5, txt=line, align='L')
            pdf.output(file_path)
            self.log(f"\n[+] SUCCESS: PDF Report saved to -> {file_path}")
        except Exception as e:
            self.log(f"\n[-] ERROR: Failed to generate PDF: {str(e)}")

    def export_json(self):
        if not hasattr(self, 'latest_raw_report') or not self.latest_raw_report: return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")], initialfile=f"SIEM_IOCs_{self.selected_file.name}.json")
        if not file_path: return
        try:
            siem_data = {
                "target_file": str(self.selected_file.name),
                "risk_score": self.latest_raw_report.get('score', 0),
                "verdict": self.latest_raw_report.get('verdict', 'Unknown'),
                "ai_prediction": self.latest_raw_report.get('ai_prediction', 'N/A'),
                "iocs": {"red_flags": self.latest_raw_report.get('flags', [])}
            }
            with open(file_path, 'w') as f:
                json.dump(siem_data, f, indent=4)
            self.log(f"\n[+] SUCCESS: Enterprise SIEM JSON saved to -> {file_path}")
        except Exception as e:
            self.log(f"\n[-] ERROR: Failed to generate SIEM JSON: {str(e)}")

    def show_history(self):
        history_win = ctk.CTkToplevel(self)
        history_win.title("Threat History Database")
        history_win.geometry("750x550")
        history_win.attributes("-topmost", True)
        
        lbl_header = ctk.CTkLabel(history_win, text="Historical Scans Archive", font=ctk.CTkFont(size=20, weight="bold"))
        lbl_header.pack(pady=(20, 10))

        scroll_frame = ctk.CTkScrollableFrame(history_win, width=700, height=450, fg_color="transparent")
        scroll_frame.pack(padx=20, pady=10, fill="both", expand=True)

        records = self.db.get_all_scans()
        if not records:
            ctk.CTkLabel(scroll_frame, text="No scan history found. Run a scan first!", text_color="gray").pack(pady=40)
            return

        for rec in records:
            border_color = "#e63946" if rec['score'] >= 75 else "#fca311" if rec['score'] >= 40 else "#2a9d8f"
            card = ctk.CTkFrame(scroll_frame, border_width=2, border_color=border_color, corner_radius=10)
            card.pack(pady=8, padx=10, fill="x")

            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.pack(side="left", padx=15, pady=10, fill="x", expand=True)
            ctk.CTkLabel(info_frame, text=f"📅 {rec['date']}", font=ctk.CTkFont(size=11), text_color="gray").pack(anchor="w")
            ctk.CTkLabel(info_frame, text=f"📦 {rec['package_name']}", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(info_frame, text=f"Verdict: {rec['verdict']}", font=ctk.CTkFont(size=12)).pack(anchor="w")

            score_frame = ctk.CTkFrame(card, fg_color="transparent")
            score_frame.pack(side="right", padx=20, pady=10)
            ctk.CTkLabel(score_frame, text="SCORE", font=ctk.CTkFont(size=10)).pack()
            ctk.CTkLabel(score_frame, text=f"{rec['score']}", font=ctk.CTkFont(size=24, weight="bold"), text_color=border_color).pack()

    def show_analytics(self):
        records = self.db.get_all_scans()
        if not records: return
        dash_win = ctk.CTkToplevel(self)
        dash_win.title("Threat Analytics")
        dash_win.geometry("800x600")
        
        safe_count = sum(1 for r in records if r['score'] < 40)
        suspicious_count = sum(1 for r in records if 40 <= r['score'] < 75)
        malicious_count = sum(1 for r in records if r['score'] >= 75)
        
        plt.style.use('dark_background')
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        fig.patch.set_facecolor('#242424')
        
        ax1.pie([safe_count, suspicious_count, malicious_count], labels=['Safe', 'Suspicious', 'Malicious'], colors=['#2a9d8f', '#fca311', '#e63946'], autopct='%1.1f%%', startangle=90)
        ax1.set_title('Verdict Distribution')
        
        recent = records[:5]
        ax2.bar([r['package_name'].split('.')[-1][:10] for r in recent], [r['score'] for r in recent], color='#4cc9f0')
        ax2.set_title('Last 5 Scanned Scores')
        ax2.set_ylim(0, 100)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=dash_win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)

if __name__ == "__main__":
    app = ThreatIntelGUI()
    app.mainloop()

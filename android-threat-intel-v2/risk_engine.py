import re
import hashlib
import requests
import os
from dotenv import load_dotenv
from domain_intel import DomainIntelligence

# 🔥 Load environment variables taake keys safe rahein
load_dotenv()

try:
    from sklearn.ensemble import RandomForestClassifier
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[!] scikit-learn or numpy not installed. AI Engine disabled.")

class ThreatIntelligenceEngine:
    def __init__(self):
        # 🔥 SECURE KEY LOADING
        self.vt_api_key = os.getenv("VT_API_KEY")
        
        # Initialize Domain Intelligence
        self.domain_scanner = DomainIntelligence()
        
        self.rules = {
            "banking_trojan": {
                "perms": ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.RECEIVE_SMS"],
                "weight": 40, "trait": "Banking Trojan Indicators (Overlay & Accessibility Abuse)"
            },
            "spyware": {
                "perms": ["android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.READ_SMS", "android.permission.ACCESS_FINE_LOCATION"],
                "weight": 35, "trait": "Surveillance & Data Exfiltration Capable"
            },
            "persistence": {
                "perms": ["android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "android.permission.FOREGROUND_SERVICE"],
                "weight": 20, "trait": "Persistence Oriented (Runs in background secretly)"
            },
            "botnet_c2": {
                "keywords": ["bot", "telegram", "ngrok", "pastebin", "firebaseio", "discordapp"],
                "weight": 30, "trait": "Suspicious C2 / Botnet Infrastructure"
            }
        }
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.port_pattern = re.compile(r':(\d{4,5})(?:/|$)')
        
        # Initialize Machine Learning Model
        if ML_AVAILABLE:
            self.ai_model = RandomForestClassifier(n_estimators=50, random_state=42)
            self._train_ai_model()

    def _train_ai_model(self):
        """Train the AI with a dummy dataset of Android Behaviors"""
        # Features: [Total Perms, Risky Perms, Has Obfuscation, Has Hardcoded IPs, Has Secrets]
        X_train = np.array([
            [5,  0, 0, 0, 0], # Safe App
            [12, 1, 0, 0, 0], # Safe App
            [25, 4, 0, 0, 0], # Suspicious/Adware
            [15, 3, 1, 0, 0], # Suspicious (Obfuscated)
            [35, 8, 1, 1, 1], # Critical Malware
            [40, 10, 1, 1, 0], # Critical Malware
            [8,  2, 0, 1, 0]  # Suspicious
        ])
        y_train = np.array(["SAFE", "SAFE", "MEDIUM RISK", "MEDIUM RISK", "CRITICAL MALWARE", "CRITICAL MALWARE", "MEDIUM RISK"])
        self.ai_model.fit(X_train, y_train)

    def check_virustotal(self, file_path):
        try:
            # Agar api key missing hai .env mein, toh check run na kare
            if not self.vt_api_key:
                return None
                
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(url, headers={"x-apikey": self.vt_api_key})
            if response.status_code == 200:
                return response.json()['data']['attributes']['last_analysis_stats']
            return None
        except Exception:
            return None

    def _evaluate_obfuscation(self, package_name):
        if len(package_name.split('.')) > 1 and all(len(p) <= 2 for p in package_name.split('.')):
            return True
        standard_prefixes = ["com.", "org.", "net.", "gov.", "edu.", "android.", "mil."]
        if not any(package_name.startswith(prefix) for prefix in standard_prefixes):
            return True
        return False

    def _generate_attack_chain(self, traits):
        chain = []
        if "Unverified Publisher (Mod/Fake App)" in traits: chain.append("0. Bypassed official stores (Fake/Debug Key).")
        if "Persistence Oriented (Runs in background secretly)" in traits: chain.append("1. Starts automatically on boot.")
        if "Banking Trojan Indicators (Overlay & Accessibility Abuse)" in traits: chain.append("2. Draws overlays to steal credentials.")
        if "Surveillance & Data Exfiltration Capable" in traits: chain.append("3. Silently monitors user activities.")
        if "Suspicious C2 / Botnet Infrastructure" in traits: chain.append("4. Connects to C2 to exfiltrate data.")
        if "Insecure Data Storage (Hardcoded Secrets)" in traits: chain.append("X. Developer left hardcoded cloud/API keys in code, leading to data breach.")
        if "OWASP Mobile Security Risks" in traits: chain.append("X. Insecure AndroidManifest config allows data leakage.")
        
        if not chain: chain.append("No clear malicious attack chain detected.")
        return chain

    def analyze(self, apk_data):
        permissions = apk_data.get('permissions', [])
        urls = apk_data.get('urls', [])
        package_name = apk_data.get('package_name', 'Unknown')
        certs = apk_data.get('certificates', []) 
        yara_matches = apk_data.get('yara_matches', [])
        secrets = apk_data.get('secrets', {})
        owasp_vulns = apk_data.get('owasp_vulns', [])
        hidden_payloads = apk_data.get('hidden_payloads', [])
        file_path = apk_data.get('file_path')
        
        score = 0
        traits = []
        flags = []
        confidence = "LOW"
        
        risky_perms_count = 0
        has_hardcoded_ips = 0

        # 1. Behavior Patterns
        for category, rule in self.rules.items():
            if "perms" in rule:
                matches = [p for p in permissions if p in rule["perms"]]
                risky_perms_count += len(matches)
                if len(matches) >= max(1, len(rule["perms"]) // 2):
                    score += rule["weight"]
                    traits.append(rule["trait"])
                    for m in matches: flags.append(f"Suspicious Permission: {m.split('.')[-1]}")

        # 2. Network/Infrastructure (Original Logic)
        for url in urls:
            url_lower = url.lower()
            if any(k in url_lower for k in self.rules["botnet_c2"]["keywords"]):
                if "Suspicious C2" not in traits: traits.append(self.rules["botnet_c2"]["trait"])
                flags.append(f"Suspicious URL Keyword: {url}")
            if self.ip_pattern.search(url):
                has_hardcoded_ips = 1
                score += 15
                if "Suspicious C2" not in traits: traits.append("Suspicious C2 / Botnet Infrastructure")
                flags.append(f"Hardcoded IP: {url}")

        # 2.5 DEEP DOMAIN INTELLIGENCE SCAN
        domain_report = self.domain_scanner.analyze_domains(urls)
        score += domain_report['risk_increment']
        flags.extend(domain_report['domain_red_flags'])
        
        if domain_report.get('tunneling_detected') or domain_report.get('hardcoded_ips'):
            has_hardcoded_ips = 1

        # 3. Obfuscation & Certs
        is_obfuscated = 1 if self._evaluate_obfuscation(package_name) else 0
        if is_obfuscated:
            score += 15
            traits.append("Code Obfuscation Detected")
            flags.append(f"Suspicious Package Naming: '{package_name}'")

        for cert in certs:
            if "android debug" in cert.get('issuer', '').lower():
                score += 20
                if "Unverified Publisher" not in traits: traits.append("Unverified Publisher (Mod/Fake App)")
                flags.append("Suspicious Digital Signature")

        # 4. YARA Matches
        if yara_matches:
            score += 25
            traits.append("Malicious Code Patterns (YARA)")
            for match in yara_matches: flags.append(f"YARA Trigger: {match}")

        # 5. Insecure Data Storage
        has_secrets = 1 if secrets else 0
        if secrets:
            score += 25
            traits.append("Insecure Data Storage (Hardcoded Secrets)")
            for secret_type, values in secrets.items():
                flags.append(f"CRITICAL: Found exposed {secret_type}! ({len(values)} occurrences)")

        # 6. OWASP Misconfigurations & Hidden Payloads
        if owasp_vulns:
            score += 15
            traits.append("OWASP Mobile Security Risks")
            for vuln in owasp_vulns: flags.append(f"VULNERABILITY: {vuln}")

        if hidden_payloads:
            score += 30
            traits.append("Obfuscated C2 / Hidden Payloads")
            for payload in hidden_payloads: flags.append(f"DECODED PAYLOAD: {payload}")

        # 7. VirusTotal Cloud Check
        vt_stats = self.check_virustotal(file_path)
        if vt_stats and vt_stats.get('malicious', 0) > 0:
            score += (vt_stats['malicious'] * 5)
            traits.append("Flagged by Global Antivirus Engines")
            flags.append(f"VirusTotal Detections: {vt_stats['malicious']} engines flagged this.")

        score = min(score, 100)
        
        # 8. AI PREDICTION LOGIC
        ai_verdict = "AI Disabled (Install scikit-learn)"
        if ML_AVAILABLE:
            features = np.array([[len(permissions), risky_perms_count, is_obfuscated, has_hardcoded_ips, has_secrets]])
            ai_prediction = self.ai_model.predict(features)[0]
            ai_verdict = ai_prediction

        if len(traits) >= 3 or score >= 80: confidence = "HIGH"
        elif len(traits) == 2 or score >= 50: confidence = "MEDIUM"
        else: confidence = "LOW"

        if score >= 75: verdict = "CRITICAL RISK (Malware Behavior Detected)"
        elif score >= 40: verdict = "MEDIUM RISK (Suspicious Characteristics)"
        elif score > 15: verdict = "LOW RISK (Adware or Aggressive Tracking)"
        else: verdict = "SAFE (No significant threats detected)"

        if not traits and score <= 15: traits.append("Benign Application")

        return {
            "score": score, "verdict": verdict, "confidence": confidence,
            "threat_personality": list(set(traits)), "attack_chain": self._generate_attack_chain(traits), 
            "flags": list(set(flags)), "secrets": secrets,
            "owasp_vulns": owasp_vulns, "hidden_payloads": hidden_payloads,
            "ai_prediction": ai_verdict,
            "domain_intel": domain_report 
        }

import os
import re
import zipfile
import tempfile
import shutil
import subprocess
import requests
import string
import ipaddress  # 🔥 Yeh zaroori tha valid IPs check karne ke liye
import time       # 🔥 API Rate limit se bachne ke liye add kiya

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[!] 'yara-python' module missing. YARA scanning will be skipped.")

class APKAnalyzer:
    def __init__(self):
        # 1. Regular Expressions for finding data
        self.url_pattern = re.compile(r'https?://[a-zA-Z0-9./_?-]+')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.permission_pattern = re.compile(r'android\.permission\.[A-Z_]+')
        self.package_pattern = re.compile(r'package="([^"]+)"')
        
        # Secrets/API Keys Patterns
        self.secret_patterns = {
            "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "Google API Key": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
            "Firebase URL": re.compile(r'https://.*\.firebaseio\.com'),
            "Stripe Key": re.compile(r'(?:sk_live|pk_live)_[0-9a-zA-Z]{24}')
        }
        
        # OWASP Vulnerability Patterns (Checking insecure configurations)
        self.owasp_patterns = {
            "Cleartext Traffic Enabled": re.compile(r'usesCleartextTraffic=["\']true["\']'),
            "Debuggable App": re.compile(r'debuggable=["\']true["\']'),
            "Exported Component (Potential Intent Spoofing)": re.compile(r'exported=["\']true["\']')
        }

        # 2. Initialize and Update YARA Engine Live
        self.yara_rules = None
        if YARA_AVAILABLE:
            self._init_yara_rules()

    def _init_yara_rules(self):
        """🔥 OPTION A: Live YARA Signature Auto-Updater"""
        print("[*] Checking for latest YARA malware signatures...")
        # A robust base set of rules (Fallback)
        local_rules = """
        rule Android_Banker {
            meta:
                description = "Detects generic Android Banking Trojans"
            strings:
                $s1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
                $s2 = "SYSTEM_ALERT_WINDOW"
                $s3 = "RECEIVE_SMS"
            condition:
                2 of them
        }
        rule Obfuscated_Payload {
            meta:
                description = "Detects hidden Base64 or Dex payloads"
            strings:
                $b1 = "Base64.decode"
                $b2 = "DexClassLoader"
                $b3 = "loadClass"
            condition:
                all of them
        }
        """
        
        # Attempt to fetch live rules from internet (Threat Intel)
        try:
            # We use a known stable raw gist/repo for Android YARA rules
            url = "https://raw.githubusercontent.com/Koodous/androguard-yara/master/rules.yara"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print("[+] Successfully fetched LIVE YARA rules from Threat Intel Feed!")
                local_rules += "\n" + response.text
        except Exception:
            print("[-] Live YARA fetch failed or timed out. Using strong local rules.")

        try:
            self.yara_rules = yara.compile(source=local_rules)
        except Exception as e:
            print(f"[!] YARA compilation failed: {e}")

    def _extract_strings(self, data):
        """Extracts printable strings from binary data (like Dex)"""
        result = ""
        for char in data.decode('utf-8', errors='ignore'):
            if char in string.printable:
                result += char
        return result

    def _get_ip_intel(self, ip):
        """🔥 NEW FEATURE: IP Geolocation & ISP Lookup"""
        try:
            # Using ip-api.com for fast, free, no-key IP intelligence
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown")
                    }
        except Exception:
            pass # Silent fail if offline or timeout
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    def _deep_decompile(self, apk_path, extract_dir, deep_scan=False):
        """🔥 Handles Fast Zip Extraction OR Deep JADX Decompilation based on UI Selection"""
        if deep_scan:
            print(f"[*] Starting Deep JADX Decompilation for {os.path.basename(apk_path)}...")
            
            # Method 1: Try using JADX if it's installed on the system
            try:
                # Check if jadx is in system PATH
                subprocess.run(["jadx", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                print("[+] JADX detected! Performing full Java Source Code Decompilation...")
                subprocess.run(["jadx", "-d", os.path.join(extract_dir, "jadx_source"), "--no-res", apk_path], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True # Decompilation successful via JADX
            except (FileNotFoundError, subprocess.CalledProcessError):
                print("[-] JADX not found or failed. Falling back to internal Fast Bytecode Extraction...")
        else:
            print(f"[*] Fast Scan selected. Skipping JADX and using Bytecode Extraction for {os.path.basename(apk_path)}...")
            
        # Method 2: Internal Fallback (Extracting strings and raw data from classes.dex directly via Zip)
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                apk.extractall(extract_dir)
            return True
        except Exception as e:
            print(f"[!] Extraction failed: {e}")
            return False

    def analyze(self, file_path, deep_scan=False):
        """Main analysis function - Do NOT change output dict structure"""
        mode_str = "Deep Scan (JADX)" if deep_scan else "Fast Scan (Zip)"
        print(f"\n[>>>] Initializing {mode_str} for: {file_path}")
        
        apk_data = {
            'file_path': file_path,
            'package_name': 'Unknown',
            'permissions': [],
            'urls': [],
            'certificates': [],
            'yara_matches': [],
            'secrets': {},
            'owasp_vulns': [],
            'hidden_payloads': [],
            'ip_intel': {} # 🔥 Nayi dictionary IP Intel ke liye
        }

        # Create a temporary directory for safe decompilation
        temp_dir = tempfile.mkdtemp()
        
        try:
            # 1. Run Decompilation / Extraction based on selected mode
            self._deep_decompile(file_path, temp_dir, deep_scan=deep_scan)
            
            # 2. Walk through all extracted files to gather intelligence
            all_text_content = ""
            raw_manifest = ""
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path_ext = os.path.join(root, file)
                    
                    try:
                        with open(file_path_ext, 'rb') as f:
                            raw_data = f.read()
                            
                        # If it's the manifest, save it for specific checks
                        if file == 'AndroidManifest.xml':
                            raw_manifest = raw_data.decode('utf-8', errors='ignore')
                            
                        # Convert binary to readable strings
                        readable_text = self._extract_strings(raw_data)
                        all_text_content += readable_text + "\n"
                        
                        # 3. YARA File Scanning
                        if self.yara_rules:
                            matches = self.yara_rules.match(data=raw_data)
                            for match in matches:
                                if match.rule not in apk_data['yara_matches']:
                                    apk_data['yara_matches'].append(match.rule)
                                    
                    except Exception:
                        continue

            # ==========================================
            # 4. Extract Data using Regex from all gathered text
            apk_data['urls'] = list(set(self.url_pattern.findall(all_text_content)))
            
            # Extract Raw IPs
            raw_ips = list(set(self.ip_pattern.findall(all_text_content)))
            valid_clean_ips = []
            
            # 🔥 OIDs (Digital Certificates) aur common fake prefixes ko ignore karne ke liye list
            ignore_prefixes = (
                '2.5.29.',    # X.509 extensions
                '1.2.840.',   # RSA / Crypto OIDs
                '1.3.6.1.',   # Internet OIDs
                '0.',         # Invalid routing IPs
                '255.',       # Broadcast
                '127.',       # Loopback
            )
            
            # Strict Validation & Filtering with Rate Limiting
            print("[*] Fetching Geolocation for public IPs (Please wait, applying API rate limits)...")
            api_calls = 0
            
            for ip in raw_ips:
                if ip.startswith(ignore_prefixes) or ip.endswith('.0.0'):
                    continue
                    
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    valid_clean_ips.append(ip)
                    
                    # Geolocation sirf Public IPs ke liye nikalo
                    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast):
                        # Sirf pehle 40 IPs ko scan karo taake API block na kare
                        if api_calls < 40:
                            intel = self._get_ip_intel(ip)
                            if intel["country"] != "Unknown":
                                apk_data['ip_intel'][ip] = intel
                            api_calls += 1
                            time.sleep(1.2) # 🔥 API Rate Limit protection
                            
                except ValueError:
                    pass # Fake IP tha, silently ignore kar do

            # Sirf valid IPs ko URLs list mein dalo taake report saaf rahay
            apk_data['urls'].extend(valid_clean_ips)
            # ==========================================
            
            apk_data['permissions'] = list(set(self.permission_pattern.findall(all_text_content)))
            
            # Extract Package Name specifically from Manifest
            pkg_match = self.package_pattern.search(raw_manifest)
            if pkg_match:
                apk_data['package_name'] = pkg_match.group(1)

            # 5. Hunt for Hardcoded Secrets / API Keys
            for secret_name, pattern in self.secret_patterns.items():
                found_secrets = list(set(pattern.findall(all_text_content)))
                if found_secrets:
                    apk_data['secrets'][secret_name] = found_secrets

            # 6. Hunt for OWASP Misconfigurations in Manifest
            for vuln_name, pattern in self.owasp_patterns.items():
                if pattern.search(raw_manifest):
                    apk_data['owasp_vulns'].append(vuln_name)

            # 7. Hunt for Hidden/Obfuscated Payloads (Base64 encoded executables)
            base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
            long_b64_strings = base64_pattern.findall(all_text_content)
            for b64 in long_b64_strings:
                if len(b64) > 100:
                    apk_data['hidden_payloads'].append(f"Base64 Chunk ({len(b64)} chars)")

            apk_data['hidden_payloads'] = list(set(apk_data['hidden_payloads']))

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        return apk_data

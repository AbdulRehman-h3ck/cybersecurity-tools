import urllib.parse
import re
import requests
import os
from dotenv import load_dotenv

# Load Environment Variables taake keys safe rahein
load_dotenv()

class DomainIntelligence:
    def __init__(self):
        # Known threat actor infrastructures and evasion tools
        self.tunneling_services = ['ngrok.io', 'ngrok-free.app', 'serveo.net', 'localtunnel.me', 'pagekite.me', 'pinggy.link']
        self.ddns_services = ['duckdns.org', 'no-ip.com', 'ddns.net', 'dynu.net', 'freeddns.org', 'hopto.org']
        self.abuse_platforms = ['api.telegram.org', 'discord.com/api', 'discordapp.com/api', 'pastebin.com', 'raw.githubusercontent.com']
        self.suspicious_tlds = ['.xyz', '.top', '.pw', '.cc', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq']
        
        # Load OSINT API Keys
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")

    def check_abuseipdb(self, ip_address):
        """Live check if the IP is reported by the cybersecurity community"""
        if not self.abuseipdb_key or self.abuseipdb_key == "your_abuseipdb_api_key_here":
            return None
            
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
            headers = {'Accept': 'application/json', 'Key': self.abuseipdb_key}
            
            response = requests.get(url, headers=headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'abuseConfidenceScore': data['abuseConfidenceScore'],
                    'totalReports': data['totalReports'],
                    'countryCode': data['countryCode']
                }
        except Exception:
            pass
        return None

    def extract_domains(self, urls):
        """Extracts base domains and IPs from a list of raw URLs"""
        domains = set()
        for url in urls:
            try:
                # Add dummy scheme if missing so urlparse works correctly
                if not url.startswith(('http://', 'https://', 'ftp://', 'tcp://')):
                    url = 'http://' + url
                parsed = urllib.parse.urlparse(url)
                if parsed.netloc:
                    # Clean up ports if attached
                    netloc = parsed.netloc.split(':')[0].lower()
                    domains.add(netloc)
            except:
                pass
        return list(domains)

    def analyze_domains(self, urls):
        """Scans extracted domains for malicious infrastructure patterns"""
        domains = self.extract_domains(urls)
        
        intel_report = {
            'unique_domains': domains,
            'hardcoded_ips': [],
            'tunneling_detected': [],
            'ddns_detected': [],
            'abused_platforms': [],
            'suspicious_tlds': [],
            'domain_red_flags': [],
            'risk_increment': 0
        }

        # Regex for IPv4 addresses
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

        for domain in domains:
            # 1. Check Hardcoded IP & AbuseIPDB Live Intel
            if ip_pattern.match(domain):
                intel_report['hardcoded_ips'].append(domain)
                
                # 🔥 LIVE OSINT SCAN
                ip_intel = self.check_abuseipdb(domain)
                if ip_intel and ip_intel['abuseConfidenceScore'] > 20:
                    intel_report['domain_red_flags'].append(f"🚨 OSINT CRITICAL: IP {domain} is a known Malicious IP! ({ip_intel['totalReports']} reports, Score: {ip_intel['abuseConfidenceScore']}%, Country: {ip_intel['countryCode']})")
                    intel_report['risk_increment'] += 40
                else:
                    intel_report['domain_red_flags'].append(f"⚠️ Suspicious: Hardcoded IP Address found ({domain})")
                    intel_report['risk_increment'] += 15
                continue

            # 2. Check Tunneling Services
            if any(tunnel in domain for tunnel in self.tunneling_services):
                intel_report['tunneling_detected'].append(domain)
                intel_report['domain_red_flags'].append(f"🚨 CRITICAL: Hacker Tunneling Infrastructure Detected ({domain})")
                intel_report['risk_increment'] += 35

            # 3. Check Dynamic DNS
            if any(ddns in domain for ddns in self.ddns_services):
                intel_report['ddns_detected'].append(domain)
                intel_report['domain_red_flags'].append(f"🔴 HIGH: Dynamic DNS / Evasion Infra Detected ({domain})")
                intel_report['risk_increment'] += 25

            # 4. Check Abused Legit Platforms (Telegram/Discord C2)
            if any(plat in domain for plat in self.abuse_platforms):
                intel_report['abused_platforms'].append(domain)
                intel_report['domain_red_flags'].append(f"🟠 WARNING: Platform commonly abused for C2/Data Exfiltration ({domain})")
                intel_report['risk_increment'] += 20

            # 5. Check Suspicious TLDs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                intel_report['suspicious_tlds'].append(domain)
                intel_report['domain_red_flags'].append(f"🟡 NOTICE: Domain uses historically suspicious TLD ({domain})")
                intel_report['risk_increment'] += 5

        # Cap the max risk increment from domains to 40 so score doesn't exceed 100 artificially
        if intel_report['risk_increment'] > 40:
            intel_report['risk_increment'] = 40

        return intel_report

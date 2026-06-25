import os
import requests
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

class OSINTHunter:
    def __init__(self):
        # Ab keys directly hardcode nahi hain, .env se fetch hongi
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.otx_key = os.getenv("OTX_API_KEY")
        self.shodan_key = os.getenv("SHODAN_API_KEY")

        # Basic check taake agar .env miss ho toh debug karne mein asani ho
        if not self.abuseipdb_key or not self.otx_key or not self.shodan_key:
            print("[!] WARNING: Ek ya zyada API keys .env file se load nahi hui hain!")

    def check_abuseipdb(self, ip):
        if not self.abuseipdb_key: return None
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    "abuse_score": data.get('abuseConfidenceScore', 0),
                    "total_reports": data.get('totalReports', 0),
                    "is_malicious": data.get('abuseConfidenceScore', 0) > 0
                }
        except Exception as e:
            pass
        return None

    def check_otx(self, ip):
        if not self.otx_key: return None
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {'X-OTX-API-KEY': self.otx_key}
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('pulse_info', {}).get('count', 0)
                return {"otx_pulses": pulses, "is_malicious": pulses > 0}
        except Exception as e:
            pass
        return None

    def check_shodan(self, ip):
        if not self.shodan_key: return None
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    "ports": data.get('ports', []),
                    "os": data.get('os', 'Unknown'),
                    "vulns": data.get('vulns', []) # CVEs if any
                }
        except Exception as e:
            pass
        return None

    def full_ip_scan(self, ip):
        """Teeno APIs ko hit karke ek combined OSINT report banata hai"""
        # Private IPs ko scan karne ka faida nahi
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.") or ip.startswith("172."):
            return {"status": "private_ip"}

        osint_data = {
            "status": "scanned",
            "abuseipdb": self.check_abuseipdb(ip),
            "otx": self.check_otx(ip),
            "shodan": self.check_shodan(ip)
        }
        return osint_data

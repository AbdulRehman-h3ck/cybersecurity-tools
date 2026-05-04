import re
import logging
from androguard.core.apk import APK

# Sabse pehle logs ko bilkul silent kar dein
logging.getLogger("androguard").setLevel(logging.ERROR)

def analyze_apk(apk_path):
    try:
        app = APK(apk_path)
        
        # --- PACKAGE NAME FIX (The "Bulletproof" way) ---
        package_name = "Unknown"
        try:
            # Tareeqa 1: New version style
            package_name = app.package_name
        except AttributeError:
            try:
                # Tareeqa 2: Old version style
                package_name = app.get_package()
            except:
                package_name = "Could not detect package"

        # --- PERMISSIONS ---
        permissions = app.get_permissions()
        
        # --- URL & IP EXTRACTION ---
        urls = []
        url_pattern = r'https?://[^\s<>"]+|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        
        # Safe extraction for DEX strings
        for dex in app.get_all_dex():
            try:
                # Agar dex object hai toh uski strings nikalenge
                if hasattr(dex, 'get_strings'):
                    content = str(dex.get_strings())
                else:
                    # Agar dex sirf bytes hain (new version)
                    content = str(dex)
                
                found_urls = re.findall(url_pattern, content)
                for u in found_urls:
                    if isinstance(u, tuple): u = u[0]
                    if u and len(u) > 12:
                        clean_url = "".join(filter(lambda x: x.isprintable(), u))
                        urls.append(clean_url)
            except:
                continue

        return {
            "package": package_name,
            "permissions": permissions,
            "urls": list(set(urls))[:30],
            "is_signed": app.is_signed()
        }
    except Exception as e:
        return {"error": str(e)}

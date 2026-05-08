import os
import androguard
# Naya tareeqa taake PyInstaller ko dhokla na ho
from androguard.apk import APK 

def analyze_apk(apk_path):
    try:
        clean_path = os.path.normpath(apk_path)
        
        # Latest version 4.x check
        a = APK(clean_path)
        
        # Naye version ke attributes use karein
        package_name = getattr(a, 'package_name', "Unknown")
        version = getattr(a, 'version_name', "N/A")
        permissions = getattr(a, 'permissions', [])
        
        risk_score = 0
        flags = []
        
        dangerous_list = [
            "android.permission.SEND_SMS", 
            "android.permission.RECORD_AUDIO", 
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION"
        ]
        
        for p in permissions:
            if p in dangerous_list:
                risk_score += 25
                flags.append(f"Dangerous Permission: {p.split('.')[-1]}")

        if risk_score >= 75:
            verdict = "⚠️ CRITICAL - MALICIOUS ACTIVITY LIKELY"
        elif risk_score >= 25:
            verdict = "🟡 WARNING - SUSPICIOUS BEHAVIOR"
        else:
            verdict = "✅ SAFE - NO THREATS DETECTED"

        return {
            'package_name': package_name,
            'version': version,
            'risk_score': min(risk_score, 100),
            'verdict': verdict,
            'flags': flags
        }

    except Exception as e:
        return {
            'package_name': "ERROR",
            'version': "N/A",
            'risk_score': 0,
            'verdict': f"Analysis Failed: {str(e)}",
            'flags': ["Try a different APK or check library path."]
        }

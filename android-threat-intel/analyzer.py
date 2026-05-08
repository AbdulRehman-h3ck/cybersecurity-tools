import os
from androguard.core.bytecodes.apk import APK

def analyze_apk(apk_path):
    try:
        # Windows aur Linux dono ke paths ko sahi karta hai
        clean_path = os.path.normpath(apk_path)
        
        # Stable APK Loading
        a = APK(clean_path)
        
        # Data extraction (Stable methods)
        package_name = a.get_package() if a.get_package() else "Unknown"
        version = a.get_androidversion_name() if a.get_androidversion_name() else "N/A"
        permissions = a.get_permissions()
        
        risk_score = 0
        flags = []
        
        # Security Logic
        dangerous_permissions = [
            "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        ]
        
        for p in permissions:
            if p in dangerous_permissions:
                risk_score += 25
                flags.append(f"Suspicious: {p.split('.')[-1]}")

        # Verdict
        if risk_score >= 75:
            verdict = "⚠️ CRITICAL - MALICIOUS INDICATORS"
        elif risk_score >= 25:
            verdict = "🟡 WARNING - SUSPICIOUS"
        else:
            verdict = "✅ SAFE - NO THREATS"

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
            'verdict': f"Engine Error: {str(e)}",
            'flags': ["Invalid APK file selected."]
        }

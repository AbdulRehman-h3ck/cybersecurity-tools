import os
from androguard.apk import APK  # Naya Modern Import

def analyze_apk(apk_path):
    try:
        # Path normalize karna
        clean_path = os.path.normpath(apk_path)
        
        # Naye version mein APK load karne ka tareeqa
        a = APK(clean_path)
        
        package_name = a.package_name if a.package_name else "Unknown"
        version = a.version_name if a.version_name else "N/A"
        permissions = a.permissions
        
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
            'flags': ["Invalid APK or Library mismatch."]
        }

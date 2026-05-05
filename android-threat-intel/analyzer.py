from androguard.core.bytecodes.apk import APK
import os

def analyze_apk(apk_path):
    try:
        # Path ko normalize karna (Windows/Linux compatibility)
        clean_path = os.path.normpath(apk_path)
        
        # APK load karna
        a = APK(clean_path)
        
        # Data extract karna (Safe method)
        package_name = a.get_package() if a.get_package() else "Unknown"
        version = a.get_androidversion_name() if a.get_androidversion_name() else "N/A"
        permissions = a.get_permissions()
        
        # Risk Analysis Logic
        risk_score = 0
        flags = []
        
        # Dangerous Permissions Check
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

        # Final Verdict
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
        # Agar analysis fail ho jaye toh ye return karega
        return {
            'package_name': "ERROR",
            'version': "N/A",
            'risk_score': 0,
            'verdict': f"Analysis Failed: {str(e)}",
            'flags': ["Make sure it is a valid APK file."]
        }

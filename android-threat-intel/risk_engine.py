def analyze_risk(permissions, urls):
    score = 0
    flags = []

    # 1. Dangerous Permissions Check
    dangerous_perms = {
        "android.permission.SEND_SMS": 20,
        "android.permission.READ_SMS": 15,
        "android.permission.RECORD_AUDIO": 15,
        "android.permission.ACCESS_FINE_LOCATION": 10,
        "android.permission.RECEIVE_BOOT_COMPLETED": 10 # Startup malware
    }

    for perm in permissions:
        if perm in dangerous_perms:
            score += dangerous_perms[perm]
            flags.append(f"Permission Risk: {perm.split('.')[-1]}")

    # 2. Suspicious URL/C2 Check
    malicious_keywords = ["bot", "telegram", "ngrok", "pastebin", "firebaseio"]
    for url in urls:
        if any(key in url.lower() for key in malicious_keywords):
            score += 25
            flags.append(f"Suspicious Connection: {url}")

    # 3. Verdict Logic
    verdict = "SAFE"
    if score > 60: verdict = "HIGH RISK (Malicious)"
    elif score > 30: verdict = "MEDIUM RISK (Suspicious)"

    return {
        "score": min(score, 100),
        "verdict": verdict,
        "flags": flags
    }

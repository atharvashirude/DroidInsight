import re

SUSPICIOUS_KEYWORDS = [
    "password", "passwd", "secret", "apikey", "api_key", "token", "auth", "credential",
    "key", "username", "user", "login", "http://", "https://", "jwt", "bearer", "aws",
    "access", "private", "certificate"
]

RISKY_PERMISSIONS = {
    "android.permission.CAMERA": "Allows access to camera hardware",
    "android.permission.RECORD_AUDIO": "Allows recording audio",
    "android.permission.READ_SMS": "Allows reading SMS messages",
    "android.permission.SEND_SMS": "Allows sending SMS messages",
    "android.permission.SYSTEM_ALERT_WINDOW": "Allows overlaying on top of other apps",
    "android.permission.READ_CONTACTS": "Access to user contacts",
    "android.permission.WRITE_CONTACTS": "Modify user contacts",
    "android.permission.READ_CALL_LOG": "Access call logs",
    "android.permission.PROCESS_OUTGOING_CALLS": "Monitor outgoing calls",
    "android.permission.READ_PHONE_STATE": "Access phone state",
    # Add more as needed
}

def find_hardcoded_strings(dex_strings):
    findings = []
    for s in dex_strings:
        s_lower = s.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in s_lower:
                findings.append({"string": s, "reason": f"Contains keyword '{kw}'"})
                break
    return findings

def analyze_permissions(permissions):
    findings = []
    for perm in permissions:
        if perm in RISKY_PERMISSIONS:
            findings.append({"permission": perm, "risk": RISKY_PERMISSIONS[perm]})
    return findings

def analyze_manifest_exported_components(manifest_xml):
    results = {"exported_components": [], "debuggable": False}
    exported = re.findall(r'android:exported\s*=\s*"true"', manifest_xml, re.IGNORECASE)
    results["exported_components"] = exported
    results["debuggable"] = bool(re.search(r'android:debuggable\s*=\s*"true"', manifest_xml, re.IGNORECASE))
    return results

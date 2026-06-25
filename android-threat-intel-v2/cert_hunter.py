import hashlib
import zipfile
import os

class CertificateHunter:
    def __init__(self, apk_path):
        self.apk_path = str(apk_path)

    def get_certificate_hash(self):
        """Extracts the META-INF signing certificate from the APK and generates a SHA-256 hash."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                for filename in apk.namelist():
                    # Look for Android signing certificates
                    if filename.startswith('META-INF/') and (filename.endswith('.RSA') or filename.endswith('.DSA') or filename.endswith('.EC')):
                        cert_data = apk.read(filename)
                        # Generate SHA-256 fingerprint
                        sha256_hash = hashlib.sha256(cert_data).hexdigest()
                        return sha256_hash.upper()
            return "UNSIGNED_OR_NOT_FOUND"
        except Exception as e:
            return f"ERROR_EXTRACTING_CERT"

# For testing independently
if __name__ == "__main__":
    test_apk = "test.apk" # Replace with an actual APK name if you want to test
    if os.path.exists(test_apk):
        hunter = CertificateHunter(test_apk)
        print(f"[*] Certificate SHA-256: {hunter.get_certificate_hash()}")

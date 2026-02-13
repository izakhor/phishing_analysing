import hashlib
import vt_scanner


def extract_attachments(msg):
    elements = []
    for part in msg.walk():
        file = part.get_filename()
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        size = len(payload) if payload else 0
        hash_256 = file_hash(payload)
        scanner = vt_scanner.vt_lookup_hash(hash_256) if hash_256 else None
        is_suspicious = is_suspicious_ext(file) if file else False
        if scanner:
            if file:
                elements.append({
                    'Filename': file,
                    'Content-Type': content_type,
                    'Size': size,
                    'SHA256': hash_256,
                    'Is-Suspicious-Extension': is_suspicious,
                    'VirusTotal-Detections': scanner
                })
    return elements


def file_hash(payload):
    if payload:
        return hashlib.sha256(payload).hexdigest()
    return None


def is_suspicious_ext(filename):
    suspicious_extensions = {
        '.exe', '.scr', '.pif', '.bat', '.cmd', '.js', '.vbs', '.wsf', '.jar',
        '.com', '.dll', '.zip', '.rar', '.html', '.iso', '.lnk', '.docm'
    }
    for ext in suspicious_extensions:
        if filename.lower().endswith(ext):
            return True
    return False

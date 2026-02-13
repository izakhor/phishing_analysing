import os


def _extract_bool(value, default=True):
    if isinstance(value, tuple) and value:
        return bool(value[0])
    if isinstance(value, bool):
        return value
    return default


def calculate_header_score(headers):
    score = 0

    if not _extract_bool(headers.get("DKIM-Check", (True,))):
        score += 10

    if not _extract_bool(headers.get("SPF-Check", (True,))):
        score += 10

    if not _extract_bool(headers.get("DMARC-Check", (True,))):
        score += 10

    if not _extract_bool(headers.get("From-Return-Path-Match", (True,))):
        score += 5

    return min(score, 30)


def calculate_content_score(content_results):
    score = 0

    url_entries = content_results.get("url_check")
    if not isinstance(url_entries, list):
        url_entries = content_results.get("urls_check")
    if not isinstance(url_entries, list):
        url_entries = content_results.get("urls", [])
    if not isinstance(url_entries, list):
        url_entries = []

    for url in url_entries:
        if not isinstance(url, dict):
            continue

        if url.get("is_shortener"):
            score += 10
        if url.get("ip_address"):
            score += 10
        if isinstance(url.get("typosquatting"), dict) and url["typosquatting"].get("is_typosquatting"):
            score += 10
        elif url.get("is_typosquatting"):
            score += 10

    html_mismatches = content_results.get("html_mismatch")
    if not isinstance(html_mismatches, list):
        html_mismatches = content_results.get("html_mismatches", [])
    if not isinstance(html_mismatches, list):
        html_mismatches = []
    score += len(html_mismatches) * 6

    keywords = content_results.get("suspicious keyword")
    if not isinstance(keywords, list):
        keywords = content_results.get("keywords", [])
    if not isinstance(keywords, list):
        keywords = []
    score += len(keywords) * 3

    return min(score, 30)


def calculate_attachment_score(attachment):
    score = 0

    if len(attachment) != 0:
        score += 5

    for file in attachment:
        if file.get("Is-Suspicious-Extension"):
            score += 10

        vt_detections = file.get("VirusTotal-Detections", "0/0")
        vt_positive = 0
        if isinstance(vt_detections, str) and "/" in vt_detections:
            try:
                vt_positive = int(vt_detections.split("/")[0])
            except ValueError:
                vt_positive = 0
        if vt_positive > 0:
            score += 20

        extension = os.path.splitext(file.get("Filename") or "")[1].lower()
        if extension in [".exe", ".js", ".vbs", ".scr"]:
            score += 20
        if extension in [".zip", ".rar", ".7z"]:
            score += 10

    return min(score, 40)


def calcule_attachment_score(attachment):
    return calculate_attachment_score(attachment)


def total_score(scores):
    header = scores.get("headers", 0)
    content = scores.get("content", 0)
    attachment = scores.get("attachment", 0)
    total = sum([header, content, attachment])

    if total <= 20:
        level = "Low"
    elif total <= 50:
        level = "Medium"
    elif total <= 75:
        level = "High"
    else:
        level = "Critical"

    return {
        "total_score": total,
        "risk_level": level,
        "details": scores
    }

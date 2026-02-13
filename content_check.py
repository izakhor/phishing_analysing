import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from extra import KNOWN_DOMAINS
from extra import PHISHING_KEYWORDS

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "lnkd.in", "shorturl.at"
}

def extract_url(body):
    pattern = r"(http[s]?:\/\/[A-Za-z0-9.:\-#\/?=&%]+)"
    urls = re.findall(pattern, body)
    
    return urls

def get_domain(url):
    return urlparse(url).netloc or ""

def levenshtein(a, b):
    if len(a) < len(b):
        return levenshtein(b, a)

    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def is_typosquatting(domain):
    for legit in KNOWN_DOMAINS:
        if domain == legit:
            continue
        d = levenshtein(domain, legit)
        if 0 < d <= 2:
            return True, legit, d
    return False

def is_shortened(domain):
    return domain in KNOWN_SHORTENERS

def is_address(url):
    return re.search(r"(((?!25?[6-9])[12]\d|[1-9])?\d\.?\b){4}", url) is not None

def detect_suspicious_url(urls):
    results = []
    for url in urls: 
        domain = get_domain(url)
        entry = {
            "url": url,
            "domain": domain,
            "ip_address": False,
            "is_shortener": False,
            "is_typosquatting": False
        }
        if is_shortened(domain):
            entry["shortener"] = True

        if is_address(url): 
            entry["ip_address"] = True

        typo = is_typosquatting(domain)
        if typo:
            entry["typosquatting"] = {
                "is_typosquatting": typo[0],
                "target": typo[1],
                "distance": typo[2]
            }
        results.append(entry)
    return results

def looks_like_domain(text):
    pattern = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    return re.search(pattern, text) is not None

def normalize_domain(domain):
    return domain.lower().replace("www.", "")

def check_html_mismatch(body_html):
    mismatches = []

    if not body_html:
        return mismatches

    soup = BeautifulSoup(body_html, "html.parser")

    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        visible_text = link.get_text().strip()

        if not href.startswith("http"):
            continue

        if visible_text.startswith("http"):
            visible_domain = urlparse(visible_text).netloc

        elif looks_like_domain(visible_text):
            visible_domain = visible_text

        else:
            continue

        href_domain = urlparse(href).netloc

        if normalize_domain(href_domain) != normalize_domain(visible_domain):
            mismatches.append({
                "visible_text": visible_text,
                "actual_url": href,
                "is_mismatch": True
            })

    return mismatches

def keyword_detection(body:str):
    found =  []
    
    if not body:
        return found
    
    body_lower = body.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in body_lower:
            found.append(keyword)
    return found

def content_gathered(body_text, body_html):
    content = {
        "urls": [],
        "html_mismatch": [],
        "suspicious keyword": []
    }

    urls = extract_url(body_text)
    content["urls"] = detect_suspicious_url(urls)
    
    content["html_mismatch"] = check_html_mismatch(body_html)

    content["suspicious keyword"] = keyword_detection(body_text)

    return content

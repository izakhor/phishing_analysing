import requests

def vt_lookup_hash(HASH):
    url = f"https://www.virustotal.com/api/v3/files/{HASH}"
    API_KEY = ""
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = f"{stats['malicious']}/{stats['malicious'] + stats['undetected']}"
        return malicious_count



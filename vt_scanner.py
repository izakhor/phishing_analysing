import requests

def vt_lookup_hash(HASH):
    url = f"https://www.virustotal.com/api/v3/files/{HASH}"
    API_KEY = "d00637d49b097714f973bdc6e0820c2f798707d5bd707e47bfe968ed5ed3556e"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = f"{stats['malicious']}/{stats['malicious'] + stats['undetected']}"
        return malicious_count


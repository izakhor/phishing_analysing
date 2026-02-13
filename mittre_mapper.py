def map_headers_to_mitre(results):
    mitre = []
    headers = results.get("headers", {})

    for check in ["DKIM-Check", "SPF-Check", "DMARC-Check"]:
        value = headers.get(check)

        if not value:
            continue

        passed, message = value

        if passed is False:
            mitre.append({
                "evidence": f"{check}: {message}",
                "tactic": "Initial Access",
                "technique_id": "T1566",
                "technique": "Phishing",
                "subtechnique_id": None,
                "subtechnique": None,
                "source": "headers",
                
            })

    return mitre

def deduplicate_mitre(mitre_list):
    seen = set()
    unique = []

    for entry in mitre_list:
        key = (entry["technique_id"], entry["subtechnique_id"])
        if key not in seen:
            seen.add(key)
            unique.append(entry)

    return unique


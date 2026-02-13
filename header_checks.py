def spf_checker(msg):
    spf_results = msg.get_all('Received-SPF')
    if "pass" in str(spf_results).lower():
        return True ,"SPF Passed"
    return False, "SPF Failed"

def dkim_checker(msg):
    auth_results = msg.get_all('Authentication-Results')
    if auth_results:
        for result in auth_results:
            if "dkim=pass" in result.lower():
                return True, "DKIM Passed"
    return False, "DKIM Failed"

def dmarc_checker(msg):
    auth_results = msg.get_all('Authentication-Results')
    if auth_results:
        for result in auth_results:
            if "dmarc=pass" in result.lower():
                return True, "DMARC Passed"
    return False, "DMARC Failed"

def compare_from_return_path(msg):
    from_header = msg.get("From")
    return_path = msg.get("Return-Path")
    if from_header and return_path:
        from_domain = from_header.split('@')[-1] if '@' in from_header else None
        return_path_domain = return_path.split('@')[-1] if '@' in return_path else None
        if from_domain and return_path_domain and from_domain == return_path_domain:
            return True, "From and Return-Path domains match"
    return False, "From and Return-Path domains do not match"
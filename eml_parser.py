from email import message_from_file
import header_checks
import content_check
import attachment


def load_email(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        return message_from_file(f)


def extract_headers(msg):
    headers = {
        'From': msg.get('From'),
        'To': msg.get('To'),
        'Subject': msg.get('Subject'),
        'Return-Path': msg.get('Return-Path'),
        'Received-SPF': msg.get_all('Received-SPF'),
        'Authentication-Results': msg.get_all('Authentication-Results'),
    }

    headers.update({
        'DKIM-Check': header_checks.dkim_checker(msg),
        'SPF-Check': header_checks.spf_checker(msg),
        'DMARC-Check': header_checks.dmarc_checker(msg),
        'From-Return-Path-Match': header_checks.compare_from_return_path(msg)
    })

    return {k: v for k, v in headers.items() if v}


def extract_body(msg):
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            charset = part.get_content_charset() or "utf-8"
            payload = part.get_payload(decode=True)

            if not payload:
                continue

            if content_type == "text/plain" and not body_text:
                body_text = payload.decode(charset, errors="replace")
            elif content_type == "text/html" and not body_html:
                body_html = payload.decode(charset, errors="replace")

    else:
        payload = msg.get_payload(decode=True)
        charset = msg.get_content_charset() or "utf-8"
        content_type = msg.get_content_type()

        if payload:
            if content_type == "text/plain":
                body_text = payload.decode(charset, errors="replace")
            elif content_type == "text/html":
                body_html = payload.decode(charset, errors="replace")

    return {
        "body_text": body_text,
        "body_html": body_html
    }


def parse_email(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        msg = message_from_file(f)

    headers = extract_headers(msg)
    body = extract_body(msg)
    content = content_check.content_gathered(body["body_text"], body["body_html"])
    attachments = attachment.extract_attachments(msg)

    return {
        "headers": headers,
        "content": content,
        "attachments": attachments
    }

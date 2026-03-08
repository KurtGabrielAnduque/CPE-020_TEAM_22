from urllib.parse import urlparse
import re
import math
import ipaddress
from collections import Counter
import tldextract

def decode_punycode(hostname):
    try:
        parts = hostname.split('.')
        decoded_parts = []
        for part in parts:
            if part.startswith('xn--'):
                decoded_parts.append(part.encode('ascii').decode('idna'))
            else:
                decoded_parts.append(part)
        return '.'.join(decoded_parts)
    except Exception:
        return hostname


SUSPICIOUS_TLDS = {
    'xyz','top','tk','ml','cf','gq','zip','work','click','link'
}

LOGIN_KEYWORDS = {
    'login','signin','verify','wallet','secure','account',
    'update','confirm','password','auth'
}

BRAND_KEYWORDS = {
    'paypal','google','apple','facebook',
    'microsoft','amazon','bank'
}

def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (freq/length) * math.log2(freq/length)
        for freq in counts.values()
    )

def small_edit_distance(a, b, max_dist=1):
    if abs(len(a) - len(b)) > max_dist:
        return False
    mismatches = sum(c1 != c2 for c1, c2 in zip(a, b))
    mismatches += abs(len(a) - len(b))
    return mismatches <= max_dist

def extract_features(url):
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        scheme = (parsed.scheme or "").lower()

        has_punycode = int('xn--' in hostname)
        hostname_display = decode_punycode(hostname) if has_punycode else hostname

        ext = tldextract.extract(hostname_display)
        subdomain = ext.subdomain
        domain = ext.domain
        tld = ext.suffix

        full_registered = f"{domain}.{tld}" if domain and tld else ""

        try:
            ipaddress.ip_address(hostname)
            has_ip = 1
        except ValueError:
            has_ip = 0

        domain_tokens = re.split(r'[.-]', hostname_display)
        path_tokens = re.split(r'[/._-]', path)

        brand_exact_token = int(any(
            token in BRAND_KEYWORDS for token in domain_tokens
        ))
        brand_adjacent_separator = int(bool(re.search(
            r'(paypal|google|apple|facebook|microsoft|amazon)[-.]',
            hostname_display
        )))
        brand_edit_distance_flag = int(any(
            small_edit_distance(domain, brand, 1)
            for brand in BRAND_KEYWORDS
        ))

        special_char_count = len(re.findall(r'[^a-zA-Z0-9.-]', hostname_display))
        digit_count_hostname = sum(c.isdigit() for c in hostname_display)
        hostname_length = len(hostname_display)

        subdomain_count = len(subdomain.split('.')) if subdomain else 0
        excessive_subdomains = int(subdomain_count >= 2)

        digit_ratio_hostname = (
            digit_count_hostname / hostname_length
            if hostname_length else 0
        )
        special_ratio_hostname = (
            special_char_count / hostname_length
            if hostname_length else 0
        )

        path_length = len(path)
        digit_count_path = sum(c.isdigit() for c in path)
        digit_ratio_path = (
            digit_count_path / path_length
            if path_length else 0
        )

        url_length = len(url)
        suspicious_tld = int(tld in SUSPICIOUS_TLDS)
        long_url_flag = int(url_length > 75)
        deep_path_flag = int(path.count('/') >= 5)
        param_count = query.count('=')
        long_query_flag = int(len(query) > 50)

        has_login_keyword = int(any(
            k in path_tokens or k in domain_tokens
            for k in LOGIN_KEYWORDS
        ))

        return {
            'url_length': url_length,
            'hostname_length': hostname_length,
            'path_length': path_length,
            'query_length': len(query),
            'dot_count': hostname_display.count('.'),
            'hyphen_count': hostname_display.count('-'),
            'subdomain_count': subdomain_count,
            'excessive_subdomains': excessive_subdomains,
            'path_depth': path.count('/'),
            'has_port': int(parsed.port is not None),
            'has_at_symbol': int('@' in url),
            'double_slash_path': int('//' in path[1:]),
            'is_https': int(scheme == 'https'),   # ← was missing in Django!
            'has_ip': has_ip,
            'has_punycode': has_punycode,
            'suspicious_tld': suspicious_tld,
            'long_url_flag': long_url_flag,
            'deep_path_flag': deep_path_flag,
            'brand_exact_token': brand_exact_token,
            'brand_adjacent_separator': brand_adjacent_separator,
            'brand_edit_distance_flag': brand_edit_distance_flag,
            'has_login_keyword': has_login_keyword,
            'param_count': param_count,
            'long_query_flag': long_query_flag,
            'digit_ratio_hostname': digit_ratio_hostname,
            'digit_ratio_path': digit_ratio_path,
            'special_ratio_hostname': special_ratio_hostname,
            'hostname_entropy': shannon_entropy(hostname_display),
            'path_entropy': shannon_entropy(path),
        }

    except Exception:
        return None
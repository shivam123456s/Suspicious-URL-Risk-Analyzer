import re
import validators
import tldextract
from urllib.parse import urlparse
import whois
import socket


class URLAnalyzer:

    def __init__(self, url):
        self.url = url
        self.score = 0
        self.reasons = []
        self.domain = urlparse(url).netloc
        self.whois_data = None  # cache WHOIS

    # -----------------------------
    # BASIC VALIDATION
    # -----------------------------
    def check_valid_url(self):
        if not validators.url(self.url):
            self.reasons.append("Invalid URL format")
            return False
        return True

    # -----------------------------
    # RULES
    # -----------------------------
    def check_https(self):
        if not self.url.startswith("https"):
            self.score += 20
            self.reasons.append("URL does not use HTTPS")

    def check_url_length(self):
        length = len(self.url)
        if length >= 75:
            self.score += 15
            self.reasons.append("URL is very long")
        elif length >= 54:
            self.score += 8
            self.reasons.append("URL length is suspicious")

    def check_ip_address(self):
        try:
            socket.inet_aton(self.domain)
            self.score += 25
            self.reasons.append("Domain uses IP address")
        except:
            pass

    def check_url_shortener(self):
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
        if any(s in self.url for s in shorteners):
            self.score += 20
            self.reasons.append("URL uses shortening service")

    def check_at_symbol(self):
        if "@" in self.url:
            self.score += 25
            self.reasons.append("URL contains @ symbol")

    def check_double_slash(self):
        if self.url.rfind("//") > 7:
            self.score += 10
            self.reasons.append("Suspicious redirect using //")

    def check_hyphen(self):
        if "-" in self.domain:
            self.score += 8
            self.reasons.append("Hyphen detected in domain")

    def check_subdomain(self):
        extracted = tldextract.extract(self.url)
        if extracted.subdomain.count(".") >= 2:
            self.score += 15
            self.reasons.append("Multiple subdomains detected")

    def check_numbers_in_domain(self):
        if any(char.isdigit() for char in self.domain):
            self.score += 8
            self.reasons.append("Numbers detected in domain")

    def check_https_token(self):
        if "https" in self.domain:
            self.score += 10
            self.reasons.append("HTTPS token inside domain")

    def check_keywords(self):
        keywords = ["login", "verify", "secure", "account", "update", "bank"]
        count = sum(1 for word in keywords if word in self.url.lower())

        if count >= 2:
            self.score += 15
            self.reasons.append("Multiple suspicious keywords detected")
        elif count == 1:
            self.score += 8
            self.reasons.append("Suspicious keyword detected")

    def check_tld(self):
        suspicious = ["xyz", "tk", "ml", "gq", "top"]
        ext = tldextract.extract(self.url)
        if ext.suffix in suspicious:
            self.score += 10
            self.reasons.append(f"Suspicious TLD: {ext.suffix}")

    # -----------------------------
    # WHOIS (CACHED)
    # -----------------------------
    def load_whois(self):
        if self.whois_data is None:
            try:
                self.whois_data = whois.whois(self.domain)
            except Exception as e:
                print("WHOIS ERROR:", e)
                self.whois_data = {}

    def check_domain_age(self):
        self.load_whois()
        if not self.whois_data or not self.whois_data.get("creation_date"):
            self.score += 10
            self.reasons.append("Domain age not verified")

    def check_domain_expiry(self):
        self.load_whois()
        if not self.whois_data or not self.whois_data.get("expiration_date"):
            self.score += 8
            self.reasons.append("Domain expiry unknown")

    # -----------------------------
    # NETWORK
    # -----------------------------
    def check_dns_record(self):
        try:
            socket.gethostbyname(self.domain)
        except:
            self.score += 20
            self.reasons.append("DNS record not found")

    def check_port(self):
        parsed = urlparse(self.url)
        if parsed.port not in [None, 80, 443]:
            self.score += 10
            self.reasons.append("Non-standard port detected")

    # -----------------------------
    # MAIN ANALYSIS
    # -----------------------------
    def analyze(self):

        if not self.check_valid_url():
            return {"score": 0, "reasons": ["Invalid URL"]}

        self.check_https()
        self.check_url_length()
        self.check_ip_address()
        self.check_url_shortener()
        self.check_at_symbol()
        self.check_double_slash()
        self.check_hyphen()
        self.check_subdomain()
        self.check_numbers_in_domain()
        self.check_https_token()
        self.check_keywords()
        self.check_tld()
        self.check_domain_age()
        self.check_domain_expiry()
        self.check_dns_record()
        self.check_port()

        # LIMIT SCORE
        self.score = min(self.score, 100)

        return {
            "score": self.score,
            "reasons": self.reasons
        }